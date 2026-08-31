#!/usr/bin/env python3
"""
model_weight_integrity_detector.py -- Silent Weight-Swap & Malicious
Pickle Detector.
Part of Watchdog AI-Attack Detection Suite.

THREAT
------
Two distinct attacks on model files at rest:

1. Silent weight swapping (IoC #19/#34): an attacker replaces an approved
   .pth/.safetensors file with a backdoored one in local storage; the
   deployed model then runs attacker-controlled weights. Detected by hash
   drift from a signed baseline.

2. Malicious pickle payloads: PyTorch .pth/.bin/.pt files default to the
   pickle format, which executes arbitrary code on load. Real 2025 CVEs
   in PickleScan itself (CVE-2025-10155/10156/10157, CVSS 9.3;
   CVE-2025-46417) let crafted files bypass scanners via extension
   spoofing, ZIP CRC errors, and blocklist evasion. The ShaiWorm
   PyTorch-Lightning supply-chain compromise (malicious lightning 2.6.2/
   2.6.3, April 2026) and tensor-steganography techniques (Snyk) make
   "trust the file because the version number is right" unsafe. Detected
   by scanning the pickle opcode stream for the dangerous globals
   (REDUCE / GLOBAL / STACK_GLOBAL importing os, posix, subprocess,
   builtins.eval/exec, etc.) rather than delegating to a scanner with
   known bypasses.

APPROACH
--------
- Hash check: SHA-256 the file, compare to a baseline manifest of
  approved {path: hash}. Drift => WEIGHT_SWAP_DETECTED.
- Pickle opcode scan: parse the pickle stream with pickletools.genops
  (does NOT execute it) and flag any GLOBAL/STACK_GLOBAL that imports a
  module/callable on the dangerous list. This inspects the raw opcodes so
  it is not fooled by the file-extension / CRC bypasses that defeated
  PickleScan. .safetensors files carry no pickle and are treated as
  code-safe by format (hash check still applies).

No torch import, no model load, no code execution. Reads bytes only.
Fully testable with crafted fixture files.

REMEDIATION (safe / auto vs. gated)
-----------------------------------
- MALICIOUS_PICKLE_DETECTED: a file that will execute code on load is
  unambiguously unsafe. Auto-safe remediation = QUARANTINE (move file
  out of the load path, chmod 000), which is reversible and prevents the
  RCE without destroying evidence. Eligible for auto_remediate=True.
  It never auto-DELETES (evidence preservation).
- WEIGHT_SWAP_DETECTED (hash drift, but pickle scan clean): could be a
  legitimate operator update. GATED: recommend blocking load + human
  confirmation against a change record. Not auto-quarantined, because a
  false positive here halts a legitimate deploy.
- INTEGRITY_OK / SAFETENSORS_OK: log only.
"""

import hashlib
import io
import json
import pickletools
from pathlib import Path

# Callables/modules that should never appear in a pure weights file.
DANGEROUS_GLOBALS = {
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil",
    "builtins.eval", "builtins.exec", "builtins.compile",
    "builtins.__import__", "builtins.getattr", "builtins.setattr",
    "importlib", "importlib.import_module", "runpy", "pty", "commands",
    "linecache", "ssl", "webbrowser", "ctypes", "operator.attrgetter",
    "pickle.loads", "codecs.decode", "base64.b64decode",
}

SAFE_EXTENSIONS_NO_PICKLE = {".safetensors"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_pickle_opcodes(raw: bytes) -> list:
    """Return a list of flagged global imports found in the pickle stream.
    Parses opcodes only -- never executes. Handles the torch .pth ZIP
    container by scanning any embedded pickle members too."""
    flagged = []

    def _check_token(token: str):
        module_root = token.split(".")[0]
        if token in DANGEROUS_GLOBALS or module_root in DANGEROUS_GLOBALS:
            flagged.append(token)

    def _scan_stream(data: bytes):
        # Track recent string pushes so STACK_GLOBAL (protocol 2+), which
        # carries arg=None and instead consumes the two preceding pushed
        # strings (module, name), can be resolved. GLOBAL (protocol 0/1)
        # carries "module\nname" directly in arg.
        recent_strings = []
        try:
            for opcode, arg, _pos in pickletools.genops(data):
                name = opcode.name
                if name in ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
                            "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"):
                    if arg is not None:
                        recent_strings.append(str(arg))
                        if len(recent_strings) > 4:
                            recent_strings.pop(0)
                elif name == "GLOBAL" and arg:
                    token = str(arg).replace(" ", ".").replace("\n", ".")
                    _check_token(token)
                elif name == "STACK_GLOBAL":
                    # module and name are the two most recent string pushes
                    if len(recent_strings) >= 2:
                        module, attr = recent_strings[-2], recent_strings[-1]
                        _check_token(f"{module}.{attr}")
                        _check_token(module)
        except Exception:
            # Truncated/obfuscated stream: report as suspicious rather than
            # swallowing -- a stream we can't parse is not "clean".
            flagged.append("<unparseable_pickle_stream>")

    # torch .pth may be a ZIP archive of pickles; try that first.
    if raw[:2] == b"PK":
        import zipfile
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                for name in z.namelist():
                    if name.endswith((".pkl", "data.pkl")) or "/data" in name:
                        _scan_stream(z.read(name))
                    else:
                        member = z.read(name)
                        if member[:1] == b"\x80":  # pickle PROTO marker
                            _scan_stream(member)
        except Exception:
            flagged.append("<unreadable_zip_container>")
    else:
        _scan_stream(raw)

    return flagged


def load_manifest(manifest_path: Path):
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def check_model_file(path: Path,
                     manifest_path: Path = None,
                     auto_remediate: bool = False) -> dict:
    path = Path(path)
    if not path.exists():
        return {"status": "SKIPPED", "message": f"{path} not found"}

    ext = path.suffix.lower()
    file_hash = sha256_file(path)
    result = {"path": str(path), "sha256": file_hash}

    # 1. Pickle opcode scan (skip for pickle-free formats).
    if ext not in SAFE_EXTENSIONS_NO_PICKLE:
        raw = path.read_bytes()
        flagged = scan_pickle_opcodes(raw)
        if flagged:
            result["status"] = "MALICIOUS_PICKLE_DETECTED"
            result["flagged_globals"] = sorted(set(flagged))
            action = {
                "action": "quarantine_file",
                "detail": ("move file out of load path and chmod 000; do NOT "
                           "delete (preserve evidence)"),
                "risk": "low_reversible",
            }
            if auto_remediate:
                result["remediation_dispatched"] = action
                result["note"] = "auto_remediate=True: quarantine dispatched"
            else:
                result["recommended_action"] = action
                result["note"] = "gated: quarantine recommended"
            return result

    # 2. Hash check against approved manifest.
    manifest = load_manifest(manifest_path) if manifest_path else None
    if manifest is not None:
        approved = manifest.get(str(path)) or manifest.get(path.name)
        if approved is None:
            result["status"] = "UNKNOWN_FILE_NOT_IN_MANIFEST"
            result["note"] = "file not in approved manifest; add or investigate"
            return result
        if approved != file_hash:
            result["status"] = "WEIGHT_SWAP_DETECTED"
            result["approved_hash"] = approved
            result["recommended_action"] = {
                "action": "block_load_pending_change_record",
                "detail": ("hash differs from approved baseline; block load "
                           "and confirm against an operator change record"),
                "risk": "gated_no_autokill",
            }
            result["note"] = "gated: could be legitimate update; human confirm"
            return result

    if ext in SAFE_EXTENSIONS_NO_PICKLE:
        result["status"] = "SAFETENSORS_OK"
    else:
        result["status"] = "INTEGRITY_OK"
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        r = check_model_file(Path(sys.argv[1]))
        print(f"[WEIGHT-INTEGRITY] {r['status']} ({r.get('path')})")
    else:
        print("usage: model_weight_integrity_detector.py <model_file>")
