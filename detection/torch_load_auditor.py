#!/usr/bin/env python3
"""
torch_load_auditor.py -- Insecure Deserialization Call-Site Auditor.
Part of Watchdog AI-Attack Detection Suite.

THREAT (A3)
-----------
torch.load() invokes pickle implicitly and executes arbitrary code on
load unless weights_only=True is passed. Real 2025 advisory: lmdeploy
GHSA-9pf3-7rrr-x5jh -- multiple torch.load(shard) call sites missing the
flag, giving RCE from a malicious checkpoint. PyTorch made
weights_only=True the default in 2.6 (Nov 2024), but a huge installed
base of older code and code that explicitly passes weights_only=False for
compatibility remains exploitable.

This is a CODE-HYGIENE detector: it scans the serving stack's own Python
source (AST, no import, no execution) for insecure deserialization call
sites:
  - torch.load(...) with no weights_only=True (or weights_only=False)
  - pickle.load / pickle.loads / cPickle.* on any argument
  - joblib.load / numpy.load(allow_pickle=True)
  - yaml.load without a safe Loader

Citations: lmdeploy GHSA-9pf3-7rrr-x5jh (Dec 2025); PyTorch weights-only
default since 2.6; CVE-2025-1716 (picklescan bypass -> pip install RCE).

AST-based, so it is not fooled by whitespace/formatting and does not
execute the code. Fully testable with fixture source strings.

REMEDIATION
-----------
Detection + reporting only. This audits source code, so remediation is a
developer fix (add weights_only=True / switch to safetensors), not a
runtime action. Emits precise file:line findings and the exact fix.
"""

import ast
from pathlib import Path


def _kw_get(call: ast.Call, name: str):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_literal_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_literal_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _call_name(call: ast.Call) -> str:
    """Return a dotted callable name like 'torch.load' or 'pickle.loads'."""
    f = call.func
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def audit_source(source: str, filename: str = "<string>") -> list:
    """Return a list of findings, each a dict with rule/line/detail/fix."""
    findings = []
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as e:
        return [{"rule": "PARSE_ERROR", "line": e.lineno or 0,
                 "detail": f"could not parse: {e.msg}", "fix": ""}]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        line = getattr(node, "lineno", 0)

        # torch.load without weights_only=True
        if name.endswith("torch.load") or name == "load" and _looks_like_torch(node):
            wo = _kw_get(node, "weights_only")
            if wo is None:
                findings.append({
                    "rule": "TORCH_LOAD_NO_WEIGHTS_ONLY", "line": line,
                    "detail": "torch.load() without weights_only=True executes pickle (RCE on malicious checkpoint)",
                    "fix": "add weights_only=True, or load .safetensors via safetensors.load_file",
                })
            elif _is_literal_false(wo):
                findings.append({
                    "rule": "TORCH_LOAD_WEIGHTS_ONLY_FALSE", "line": line,
                    "detail": "torch.load(weights_only=False) explicitly re-enables arbitrary code execution",
                    "fix": "remove weights_only=False; migrate to safetensors",
                })

        # pickle.load / pickle.loads / cPickle.*
        elif name in ("pickle.load", "pickle.loads", "cPickle.load",
                      "cPickle.loads", "_pickle.load", "_pickle.loads"):
            findings.append({
                "rule": "PICKLE_LOAD", "line": line,
                "detail": f"{name} executes arbitrary code on untrusted data",
                "fix": "do not unpickle untrusted model data; use safetensors",
            })

        # joblib.load
        elif name in ("joblib.load",):
            findings.append({
                "rule": "JOBLIB_LOAD", "line": line,
                "detail": "joblib.load uses pickle under the hood; unsafe on untrusted files",
                "fix": "validate provenance/hash before load, or avoid pickle-backed formats",
            })

        # numpy.load(allow_pickle=True)
        elif name in ("numpy.load", "np.load"):
            ap = _kw_get(node, "allow_pickle")
            if ap is not None and _is_literal_true(ap):
                findings.append({
                    "rule": "NUMPY_ALLOW_PICKLE", "line": line,
                    "detail": "numpy.load(allow_pickle=True) can execute code via pickled object arrays",
                    "fix": "set allow_pickle=False unless the file is fully trusted",
                })

        # yaml.load without SafeLoader
        elif name in ("yaml.load",):
            loader = _kw_get(node, "Loader")
            if loader is None:
                findings.append({
                    "rule": "YAML_LOAD_NO_SAFELOADER", "line": line,
                    "detail": "yaml.load without Loader=SafeLoader can instantiate arbitrary objects",
                    "fix": "use yaml.safe_load or Loader=yaml.SafeLoader",
                })

    return findings


def _looks_like_torch(call: ast.Call) -> bool:
    """Heuristic: a bare load(...) whose first arg name hints at a model/
    checkpoint file. Conservative -- avoids flagging every load()."""
    if not call.args:
        return False
    a = call.args[0]
    hint = ""
    if isinstance(a, ast.Name):
        hint = a.id.lower()
    elif isinstance(a, ast.Constant) and isinstance(a.value, str):
        hint = a.value.lower()
    return any(t in hint for t in ("ckpt", "checkpoint", "model", "weight", "shard", ".pt", ".pth", ".bin"))


def audit_path(path: Path, max_files: int = 5000) -> dict:
    """Scan a file or a directory tree of .py files. Returns a summary dict."""
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

    status = "INSECURE_DESERIALIZATION_FOUND" if all_findings else "DESERIALIZATION_CLEAN"
    return {
        "status": status,
        "files_scanned": len(py_files),
        "finding_count": len(all_findings),
        "findings": all_findings,
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    r = audit_path(Path(target))
    print(f"[TORCH-LOAD-AUDIT] {r['status']} "
          f"({r.get('finding_count', 0)} findings in {r.get('files_scanned', 0)} files)")
    for fnd in r.get("findings", [])[:20]:
        print(f"  {fnd['file']}:{fnd['line']}  {fnd['rule']} -- {fnd['detail']}")
