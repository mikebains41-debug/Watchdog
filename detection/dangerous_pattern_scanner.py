#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
dangerous_pattern_scanner.py -- AST-Based Dangerous-Code-Pattern Scanner
Part of Watchdog AI-Attack Detection Suite.

Extends the torch_load_auditor approach (AST, no execution) beyond
deserialization to the broader set of dangerous patterns that show up in
ML serving code and AI-generated code. This is a SAST-style scanner using
Python's own ast module -- no LLM, no third-party engine, deterministic.

Patterns detected (all real, all high-signal in ML/serving contexts):
- SUBPROCESS_SHELL_TRUE    -- subprocess with shell=True (command injection)
- OS_SYSTEM                -- os.system / os.popen (command execution)
- EVAL_EXEC                -- eval() / exec() / compile() on dynamic input
- EVAL_INPUT               -- eval(input()) / exec(input()) (classic RCE)
- YAML_UNSAFE_LOAD         -- yaml.load without SafeLoader
- HARDCODED_SECRET         -- assignment of a secret-looking literal
- REQUESTS_VERIFY_FALSE    -- requests(..., verify=False) (TLS bypass)
- FLASK_DEBUG_TRUE         -- app.run(debug=True) (Werkzeug RCE console)
- PICKLE_LOAD              -- pickle.load/loads (delegated note; see auditor)

Reports file:line + the exact fix. Reporting only -- fixing is a
developer action, never auto-applied.

Complements, does not replace, torch_load_auditor (which owns the
torch.load / weights_only specifics).
"""

import ast
import re
from pathlib import Path

# secret-looking assignment target names + value patterns
SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|secret|token|passwd|password|private[_-]?key|aws[_-]?access)",
    re.IGNORECASE)
SECRET_VALUE_RE = re.compile(r"^(sk-|ghp_|AKIA|xox[baprs]-|-----BEGIN)")


def _call_name(call: ast.Call) -> str:
    f = call.func
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def _kw(call: ast.Call, name: str):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _arg_is_input_call(call: ast.Call) -> bool:
    return any(isinstance(a, ast.Call) and _call_name(a) in ("input", "raw_input")
               for a in call.args)


def audit_source(source: str, filename: str = "<string>") -> list:
    findings = []
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as e:
        return [{"rule": "PARSE_ERROR", "line": e.lineno or 0,
                 "detail": f"could not parse: {e.msg}", "fix": ""}]

    for node in ast.walk(tree):
        # hardcoded secrets: assignment with secret-looking name or value
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                tname = getattr(tgt, "id", "") if isinstance(tgt, ast.Name) else ""
                val = node.value
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    if SECRET_NAME_RE.search(tname) and len(val.value) >= 8 \
                            and val.value not in ("", "changeme", "your_key_here"):
                        findings.append({
                            "rule": "HARDCODED_SECRET", "line": node.lineno,
                            "detail": f"secret-looking literal assigned to '{tname}'",
                            "fix": "load from env/secret manager, never hardcode",
                        })
                    elif SECRET_VALUE_RE.search(val.value):
                        findings.append({
                            "rule": "HARDCODED_SECRET", "line": node.lineno,
                            "detail": "value matches a known credential prefix",
                            "fix": "load from env/secret manager, never hardcode",
                        })
            continue

        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        line = getattr(node, "lineno", 0)

        if name in ("os.system", "os.popen"):
            findings.append({"rule": "OS_SYSTEM", "line": line,
                             "detail": f"{name} executes a shell command",
                             "fix": "use subprocess with a list arg and shell=False"})
        elif name.startswith("subprocess.") or name == "subprocess":
            sh = _kw(node, "shell")
            if sh is not None and _is_true(sh):
                findings.append({"rule": "SUBPROCESS_SHELL_TRUE", "line": line,
                                 "detail": "subprocess with shell=True (command injection risk)",
                                 "fix": "pass args as a list and shell=False"})
        elif name in ("eval", "exec", "compile"):
            if _arg_is_input_call(node):
                findings.append({"rule": "EVAL_INPUT", "line": line,
                                 "detail": f"{name}() on input() -- direct RCE",
                                 "fix": "parse/validate input; never eval user data"})
            else:
                findings.append({"rule": "EVAL_EXEC", "line": line,
                                 "detail": f"{name}() can execute arbitrary code",
                                 "fix": "avoid dynamic eval/exec; use safe parsing"})
        elif name == "yaml.load":
            if _kw(node, "Loader") is None:
                findings.append({"rule": "YAML_UNSAFE_LOAD", "line": line,
                                 "detail": "yaml.load without SafeLoader",
                                 "fix": "use yaml.safe_load"})
        elif name in ("requests.get", "requests.post", "requests.put",
                      "requests.delete", "requests.request", "requests.patch"):
            v = _kw(node, "verify")
            if v is not None and _is_false(v):
                findings.append({"rule": "REQUESTS_VERIFY_FALSE", "line": line,
                                 "detail": "TLS verification disabled (verify=False)",
                                 "fix": "remove verify=False; fix the cert chain instead"})
        elif name.endswith(".run") and name.split(".")[0] in ("app", "application"):
            d = _kw(node, "debug")
            if d is not None and _is_true(d):
                findings.append({"rule": "FLASK_DEBUG_TRUE", "line": line,
                                 "detail": "Flask debug=True exposes the Werkzeug console (RCE)",
                                 "fix": "never run debug=True in production"})
        elif name in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"):
            findings.append({"rule": "PICKLE_LOAD", "line": line,
                             "detail": "pickle load executes code on untrusted data",
                             "fix": "use safetensors; see torch_load_auditor"})

    return findings


def audit_path(path: Path, max_files: int = 5000) -> dict:
    path = Path(path)
    if not path.exists():
        return {"status": "SKIPPED", "message": f"{path} not found"}
    py_files = [path] if path.is_file() else sorted(path.rglob("*.py"))[:max_files]
    all_findings = []
    for f in py_files:
        try:
            src = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for finding in audit_source(src, filename=str(f)):
            finding["file"] = str(f)
            all_findings.append(finding)
    status = "DANGEROUS_PATTERNS_FOUND" if all_findings else "SCAN_CLEAN"
    return {"status": status, "files_scanned": len(py_files),
            "finding_count": len(all_findings), "findings": all_findings}


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    r = audit_path(Path(target))
    print(f"[DANGER-SCAN] {r['status']} "
          f"({r.get('finding_count', 0)} findings in {r.get('files_scanned', 0)} files)")
    for f in r.get("findings", [])[:25]:
        print(f"  {f['file']}:{f['line']}  {f['rule']} -- {f['detail']}")
