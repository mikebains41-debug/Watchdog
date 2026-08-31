#!/usr/bin/env python3
"""
test_ai_attack_detectors_batch2.py -- tests for the second batch of
AI-attack detectors (Tier A + Tier B from the researched candidate list):
  - model_format_security_detector (GGUF/Jinja, config template, safe-format parse)
  - torch_load_auditor (insecure deserialization call-site audit)
  - gpu_memory_integrity_detector (LeftoverLocals, weight canary, GPUThor ECC-break)

Run standalone: python3 tests/test_ai_attack_detectors_batch2.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
Imports use detection.* package paths because run_all.py runs with cwd=REPO_ROOT.
Follows the tests/README.md pattern.
"""

import os
import sys
import json
import struct
import shutil
import tempfile
from pathlib import Path

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.model_format_security_detector import (
    check_model_format, scan_template_string, _validate_safetensors_header,
)
from detection.torch_load_auditor import audit_source, audit_path
from detection.gpu_memory_integrity_detector import (
    detect_leftover_locals, seal_weight_canary, check_weight_canary,
    seal_output_canary, check_output_canary, detect_ecc_break,
)

PASSED = 0
FAILED = 0


def check(name, condition, detail=""):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"[PASS] {name}")
    else:
        FAILED += 1
        print(f"[FAIL] {name} {detail}")


# --------------------------------------------------------------------------
# model_format_security_detector
# --------------------------------------------------------------------------
def _make_safetensors(path: Path, valid=True):
    if valid:
        meta = {"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}
        header = json.dumps(meta).encode()
        buffer = b"\x00" * 8
        path.write_bytes(struct.pack("<Q", len(header)) + header + buffer)
    else:
        # offsets point past the buffer -> malformed
        meta = {"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 9999]}}
        header = json.dumps(meta).encode()
        buffer = b"\x00" * 8
        path.write_bytes(struct.pack("<Q", len(header)) + header + buffer)


def _make_gguf(path: Path, template=None, malformed=False):
    if malformed:
        # magic ok but counts absurd
        path.write_bytes(GGUF := b"GGUF" + struct.pack("<I", 3)
                         + struct.pack("<Q", 10**18) + struct.pack("<Q", 10**18))
        return
    body = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 1)
    if template:
        body += b"chat_template" + template.encode()
    path.write_bytes(body)


def test_model_format():
    tmp = Path(tempfile.mkdtemp(prefix="fmt_"))
    try:
        # Config file with dangerous Jinja template
        cfg = tmp / "tokenizer_config.json"
        cfg.write_text(json.dumps({
            "chat_template": "{{ self.__class__.__mro__[1].__subclasses__() }}"
        }))
        r = check_model_format(cfg)
        check("fmt: dangerous chat_template in config -> DANGEROUS_TEMPLATE_DETECTED",
              r["status"] == "DANGEROUS_TEMPLATE_DETECTED", f"got {r['status']}")

        # Config with benign template
        cfg2 = tmp / "tokenizer_config2.json"
        cfg2.write_text(json.dumps({"chat_template": "{{ messages[0]['content'] }}"}))
        r2 = check_model_format(cfg2)
        check("fmt: benign template -> TEMPLATE_OK",
              r2["status"] == "TEMPLATE_OK", f"got {r2['status']}")

        # Valid safetensors header
        st = tmp / "model.safetensors"
        _make_safetensors(st, valid=True)
        r3 = check_model_format(st)
        check("fmt: valid safetensors -> HEADER_OK",
              r3["status"] == "HEADER_OK", f"got {r3['status']}")

        # Malformed safetensors (offsets out of bounds)
        stbad = tmp / "bad.safetensors"
        _make_safetensors(stbad, valid=False)
        r4 = check_model_format(stbad)
        check("fmt: out-of-bounds safetensors offsets -> MALFORMED_HEADER",
              r4["status"] == "MALFORMED_HEADER", f"got {r4['status']}")

        # GGUF with dangerous embedded template
        gg = tmp / "model.gguf"
        _make_gguf(gg, template="{{ cycler.__init__.__globals__.os.popen('id') }}")
        r5 = check_model_format(gg)
        check("fmt: dangerous GGUF template -> DANGEROUS_TEMPLATE_DETECTED",
              r5["status"] == "DANGEROUS_TEMPLATE_DETECTED", f"got {r5['status']}")

        # Malformed GGUF header
        ggbad = tmp / "bad.gguf"
        _make_gguf(ggbad, malformed=True)
        r6 = check_model_format(ggbad)
        check("fmt: malformed GGUF counts -> MALFORMED_HEADER",
              r6["status"] == "MALFORMED_HEADER", f"got {r6['status']}")

        # auto_remediate dispatches quarantine on dangerous template
        r7 = check_model_format(cfg, auto_remediate=True)
        check("fmt: auto_remediate dispatches quarantine",
              r7.get("remediation_dispatched", {}).get("action") == "quarantine_file",
              f"got {r7.get('remediation_dispatched')}")

        # template scanner unit: sandbox-escape gadget flagged
        check("fmt: scan_template_string flags __globals__",
              "__globals__" in " ".join(scan_template_string("{{ x.__globals__ }}")),
              "did not flag")
        check("fmt: scan_template_string clean on plain template",
              scan_template_string("Hello {{ name }}") == [],
              "false positive on benign")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# torch_load_auditor
# --------------------------------------------------------------------------
def test_torch_load_auditor():
    # torch.load without weights_only
    src1 = "import torch\nm = torch.load('model.pth')\n"
    f1 = audit_source(src1)
    check("audit: torch.load no weights_only -> flagged",
          any(x["rule"] == "TORCH_LOAD_NO_WEIGHTS_ONLY" for x in f1), f"got {f1}")

    # torch.load(weights_only=True) is clean
    src2 = "import torch\nm = torch.load('model.pth', weights_only=True)\n"
    f2 = audit_source(src2)
    check("audit: torch.load weights_only=True -> clean",
          not any("TORCH_LOAD" in x["rule"] for x in f2), f"got {f2}")

    # weights_only=False explicitly flagged
    src3 = "import torch\nm = torch.load(f, weights_only=False)\n"
    f3 = audit_source(src3)
    check("audit: weights_only=False -> flagged explicitly",
          any(x["rule"] == "TORCH_LOAD_WEIGHTS_ONLY_FALSE" for x in f3), f"got {f3}")

    # pickle.loads flagged
    src4 = "import pickle\nx = pickle.loads(data)\n"
    f4 = audit_source(src4)
    check("audit: pickle.loads -> flagged",
          any(x["rule"] == "PICKLE_LOAD" for x in f4), f"got {f4}")

    # numpy allow_pickle=True flagged
    src5 = "import numpy as np\na = np.load('x.npy', allow_pickle=True)\n"
    f5 = audit_source(src5)
    check("audit: numpy allow_pickle=True -> flagged",
          any(x["rule"] == "NUMPY_ALLOW_PICKLE" for x in f5), f"got {f5}")

    # yaml.load without SafeLoader flagged
    src6 = "import yaml\nc = yaml.load(stream)\n"
    f6 = audit_source(src6)
    check("audit: yaml.load no SafeLoader -> flagged",
          any(x["rule"] == "YAML_LOAD_NO_SAFELOADER" for x in f6), f"got {f6}")

    # clean file produces no findings
    src7 = "import torch\nx = torch.tensor([1,2,3])\nprint(x.sum())\n"
    f7 = audit_source(src7)
    check("audit: clean source -> no findings",
          len(f7) == 0, f"got {f7}")

    # audit_path over a temp dir
    tmp = Path(tempfile.mkdtemp(prefix="audit_"))
    try:
        (tmp / "a.py").write_text("import torch\ntorch.load('ckpt.pth')\n")
        (tmp / "b.py").write_text("x = 1 + 1\n")
        r = audit_path(tmp)
        check("audit: audit_path finds the one insecure call",
              r["status"] == "INSECURE_DESERIALIZATION_FOUND" and r["finding_count"] == 1,
              f"got {r}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# gpu_memory_integrity_detector
# --------------------------------------------------------------------------
def test_gpu_memory_integrity():
    # A4 LeftoverLocals
    r = detect_leftover_locals(528_000_000, after_process_exit=True,
                                vendor="NVIDIA", driver="550")
    check("mem: residual after exit -> LEFTOVER_LOCALS_RESIDUAL",
          r["status"] == "LEFTOVER_LOCALS_RESIDUAL", f"got {r['status']}")
    check("mem: LeftoverLocals cites CVE-2023-4969",
          r.get("cve") == "CVE-2023-4969", f"got {r.get('cve')}")

    r_clean = detect_leftover_locals(0, after_process_exit=True)
    check("mem: zero residual -> NO_RESIDUAL",
          r_clean["status"] == "NO_RESIDUAL", f"got {r_clean['status']}")

    r_skip = detect_leftover_locals(100, after_process_exit=False)
    check("mem: residual pre-exit -> SKIPPED",
          r_skip["status"] == "SKIPPED", f"got {r_skip['status']}")

    # A5 weight canary
    sealed = seal_weight_canary(b"reference-weights-v1")
    ok = check_weight_canary(b"reference-weights-v1", sealed)
    check("mem: matching weights -> WEIGHT_CANARY_OK",
          ok["status"] == "WEIGHT_CANARY_OK", f"got {ok['status']}")
    drift = check_weight_canary(b"tampered-weights", sealed)
    check("mem: drifted weights -> WEIGHT_DRIFT_DETECTED",
          drift["status"] == "WEIGHT_DRIFT_DETECTED", f"got {drift['status']}")
    check("mem: weight drift never auto-kills",
          drift.get("recommended_action", {}).get("risk") == "gated_no_autokill",
          f"got {drift.get('recommended_action')}")

    # output canary
    osealed = seal_output_canary([0.1, 0.9])
    check("mem: matching output -> OUTPUT_CANARY_OK",
          check_output_canary([0.1, 0.9], osealed)["status"] == "OUTPUT_CANARY_OK")
    check("mem: drifted output -> OUTPUT_DRIFT_DETECTED",
          check_output_canary([0.9, 0.1], osealed)["status"] == "OUTPUT_DRIFT_DETECTED")

    # B1 ECC-break
    # uncorrectable present -> CRITICAL
    r_unc = detect_ecc_break([0, 5, 12], [0, 0, 2])
    check("mem: uncorrectable ECC -> ECC_BREAK_SUSPECTED CRITICAL",
          r_unc["status"] == "ECC_BREAK_SUSPECTED" and r_unc["severity"] == "CRITICAL",
          f"got {r_unc}")

    # rising corrected rate only -> WARNING
    r_rate = detect_ecc_break([0, 10, 22, 40], [0, 0, 0, 0])
    check("mem: rising corrected rate -> ECC_BREAK_SUSPECTED WARNING",
          r_rate["status"] == "ECC_BREAK_SUSPECTED" and r_rate["severity"] == "WARNING",
          f"got {r_rate}")

    # nominal steady ECC -> ECC_NOMINAL
    r_nom = detect_ecc_break([5, 5, 5, 5], [0, 0, 0, 0])
    check("mem: steady ECC -> ECC_NOMINAL",
          r_nom["status"] == "ECC_NOMINAL", f"got {r_nom}")

    check("mem: ECC-break never auto-resets (forensics preserved)",
          r_unc.get("recommended_action", {}).get("risk") == "gated_urgent_no_autoreset",
          f"got {r_unc.get('recommended_action')}")


def main():
    test_model_format()
    test_torch_load_auditor()
    test_gpu_memory_integrity()
    print(f"\nPASSED: {PASSED}   FAILED: {FAILED}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
