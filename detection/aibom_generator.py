#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
aibom_generator.py -- AI Bill of Materials (AIBOM) Generator & Provenance Auditor
Part of Watchdog AI-Attack Detection Suite.

WHAT / WHY
----------
model_weight_integrity_detector + torch_load_auditor answer "is this file
safe to load." An AIBOM answers a different, complementary question:
"WHAT AI components does this system depend on, WHERE did each come from,
is it PINNED, and is the source TRUSTED." That is supply-chain provenance,
not file safety.

This is now a regulatory artifact, not just good practice:
- EU AI Act Article 11 (technical documentation) is enforceable for
  high-risk systems; Article 53(1d) imposes a training-data summary on
  GPAI providers (effective 2 Aug 2025).
- The settled format is CycloneDX ML-BOM v1.7 (ECMA-424, 2nd ed,
  Oct 2025); SPDX 3.0 AI Profile is the compatible alternative.
- CISA "SBOM for AI: Minimum Elements", NIST AI RMF, OWASP AIBOM Project
  all converged on this in 2025-2026.

It maps directly onto Watchdog's existing EU AI Act compliance agent and
the pharma/insurance verticals (auditors will ask for exactly this).

WHAT THIS DOES
--------------
- Inventories AI components: models (.safetensors/.gguf/.pth/.bin), datasets,
  and (optionally) pinned Python deps, from a directory tree + optional
  manifest.
- Records SHA-256 for each artifact (the provenance anchor).
- Flags provenance risks:
    UNPINNED_SOURCE      -- component has no recorded version/hash
    UNTRUSTED_SOURCE     -- source host not on the trusted allowlist
    MISSING_LICENSE      -- no license recorded (Article 11 gap)
    MISSING_TRAINING_DATA-- model with no training-data reference (Art. 53 gap)
- Emits a CycloneDX-1.7-shaped ML-BOM JSON (a valid subset -- the fields
  auditors and SBOM tooling actually consume).

Pure stdlib, no network, no model load. Fully testable with fixtures.

REMEDIATION
-----------
Detection/inventory + reporting only. Remediation for provenance gaps is a
process fix (pin the version, record the license, document training data),
not a runtime action. The generator produces the artifact + a gap list.
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

MODEL_EXTS = {".safetensors", ".gguf", ".pth", ".pt", ".bin", ".onnx", ".ckpt"}
DATASET_EXTS = {".csv", ".parquet", ".jsonl", ".arrow", ".tfrecord"}

# Hosts considered trusted provenance sources. Extend per deployment.
DEFAULT_TRUSTED_SOURCES = {
    "huggingface.co", "hf.co", "github.com", "pytorch.org",
    "download.pytorch.org", "storage.googleapis.com",  # e.g. TF Hub mirrors
    "internal",  # sentinel for first-party artifacts
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _host_of(source: str) -> str:
    if not source:
        return ""
    m = re.match(r"[a-z]+://([^/]+)/?", source)
    if m:
        return m.group(1).lower()
    # bare host or "internal"
    return source.split("/")[0].lower()


def classify(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in MODEL_EXTS:
        return "machine-learning-model"
    if ext in DATASET_EXTS:
        return "data"
    return "file"


def build_aibom(root: Path,
                manifest_path: Path = None,
                trusted_sources: set = None,
                max_files: int = 10000) -> dict:
    """
    root: directory tree to inventory.
    manifest_path: optional JSON mapping artifact name/path -> metadata
        {"name": {"source": "...", "version": "...", "license": "...",
                  "training_data": "..."}}
    Returns a CycloneDX-1.7-shaped ML-BOM plus a provenance gap list.
    """
    root = Path(root)
    if not root.exists():
        return {"status": "SKIPPED", "message": f"{root} not found"}

    trusted = trusted_sources or DEFAULT_TRUSTED_SOURCES
    manifest = {}
    if manifest_path and Path(manifest_path).exists():
        try:
            manifest = json.loads(Path(manifest_path).read_text())
        except (json.JSONDecodeError, OSError):
            manifest = {}

    components = []
    gaps = []

    files = [p for p in sorted(root.rglob("*"))
             if p.is_file() and p.suffix.lower() in (MODEL_EXTS | DATASET_EXTS)]
    files = files[:max_files]

    for f in files:
        ctype = classify(f)
        meta = manifest.get(str(f)) or manifest.get(f.name) or {}
        digest = sha256_file(f)
        source = meta.get("source", "")
        version = meta.get("version")
        license_ = meta.get("license")
        training_data = meta.get("training_data")

        comp = {
            "type": ctype,
            "name": f.name,
            "version": version or "UNPINNED",
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "properties": [
                {"name": "watchdog:path", "value": str(f)},
                {"name": "watchdog:source", "value": source or "UNKNOWN"},
            ],
        }
        if license_:
            comp["licenses"] = [{"license": {"id": license_}}]
        components.append(comp)

        # Provenance gap checks
        host = _host_of(source)
        if not version and not source:
            gaps.append({"component": f.name, "gap": "UNPINNED_SOURCE",
                         "detail": "no version or source recorded"})
        if source and host not in trusted:
            gaps.append({"component": f.name, "gap": "UNTRUSTED_SOURCE",
                         "detail": f"source host '{host}' not in trusted allowlist"})
        if not license_:
            gaps.append({"component": f.name, "gap": "MISSING_LICENSE",
                         "detail": "no license recorded (EU AI Act Art. 11 gap)"})
        if ctype == "machine-learning-model" and not training_data:
            gaps.append({"component": f.name, "gap": "MISSING_TRAINING_DATA",
                         "detail": "model has no training-data reference "
                                   "(EU AI Act Art. 53 gap)"})

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "GPU Optimizer Inc.",
                       "name": "Watchdog AIBOM Generator", "version": "1.0"}],
            "properties": [{"name": "watchdog:note",
                            "value": "Subset of CycloneDX 1.7 ML-BOM fields; "
                                     "simulation-based, requires real hardware validation"}],
        },
        "components": components,
    }

    status = "PROVENANCE_GAPS_FOUND" if gaps else "AIBOM_CLEAN"
    return {
        "status": status,
        "component_count": len(components),
        "gap_count": len(gaps),
        "gaps": gaps,
        "aibom": bom,
    }


def write_aibom(result: dict, out_path: Path) -> None:
    Path(out_path).write_text(json.dumps(result["aibom"], indent=2))


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    r = build_aibom(Path(target))
    print(f"[AIBOM] {r['status']} "
          f"({r.get('component_count', 0)} components, {r.get('gap_count', 0)} gaps)")
    for g in r.get("gaps", [])[:20]:
        print(f"  {g['component']}: {g['gap']} -- {g['detail']}")
