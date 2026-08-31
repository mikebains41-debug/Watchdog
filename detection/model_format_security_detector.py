#!/usr/bin/env python3
"""
model_format_security_detector.py -- GGUF/Jinja Template, Config-File
Injection, and Safe-Format Parse Validator.
Part of Watchdog AI-Attack Detection Suite.

Closes gaps left by model_weight_integrity_detector.py, which only handled
pickle payloads and treated .safetensors / non-pickle formats as
automatically safe. Real 2024-2026 research shows "not pickle" is NOT
"safe":

A1. GGUF / Jinja2 chat-template execution
    GGUF files (llama.cpp) and tokenizer_config.json embed Jinja2 chat
    templates that execute at inference-initialization time in frameworks
    that don't sandbox the template engine. Same class as CVE-2024-2952
    (BerriAI/litellm SSTI via chat_template). Detected by extracting the
    template string and scanning for dangerous Jinja constructs
    (attribute access reaching os/subprocess/eval, {% ... %} calling out,
    __class__/__mro__/__globals__ sandbox-escape gadgets).

A2. Safe-format parser memory-corruption preconditions
    Even safetensors/GGUF have parser CVEs (CVE-2024-41130 null-ptr deref
    in gguf_init_from_file; a family of model-parse memory-corruption
    CVEs). A malformed-but-plausible header crashes or potentially
    executes in the loader. Detected by validating structural invariants
    of the header BEFORE the real loader touches it: offsets within file
    bounds, non-negative sizes, well-formed metadata/name table.

Citations (for docstring / deck): CVE-2024-2952 (litellm Jinja SSTI);
CVE-2024-41130 (ggml gguf parse null-ptr deref); arXiv:2502.12497
(LLM supply-chain, 6 model-parse memory-corruption CVEs); CSA "Model
Poisoning: Credential Exfiltration in Self-Hosted LLM Deployments"
(May 2026); Trail of Bits safetensors audit (2023).

No template is ever rendered. No model is ever loaded. Bytes/JSON only.
Fully testable with crafted fixtures, no GPU / no torch / no jinja2.

REMEDIATION
-----------
- DANGEROUS_TEMPLATE_DETECTED: template will execute attacker code at
  init. Auto-safe = quarantine (chmod 000, move out of load path, never
  delete). Eligible for auto_remediate=True.
- MALFORMED_HEADER: parser-crash / memory-corruption precondition.
  GATED: block load, recommend re-fetch from trusted source + human
  review (a genuinely corrupt-but-benign file shouldn't be destroyed).
- TEMPLATE_OK / HEADER_OK / NO_TEMPLATE: log only.
"""

import json
import re
import struct
from pathlib import Path

# Jinja / template constructs that indicate code execution or sandbox
# escape rather than plain string formatting.
DANGEROUS_TEMPLATE_PATTERNS = [
    r"__class__", r"__mro__", r"__globals__", r"__subclasses__",
    r"__builtins__", r"__import__", r"__base__", r"__init__\.__globals__",
    r"\bos\b", r"\bsubprocess\b", r"\bsys\b", r"\beval\b", r"\bexec\b",
    r"\bpopen\b", r"\bsystem\b", r"\bgetattr\b", r"\brequest\b",
    r"\bsocket\b", r"\bopen\s*\(", r"cycler\.__init__", r"lipsum\.__globals__",
    r"config\.__class__", r"\bself\b\.__", r"namespace\.__",
]
_DANGEROUS_RE = re.compile("|".join(DANGEROUS_TEMPLATE_PATTERNS), re.IGNORECASE)

# GGUF magic + basic type table (subset needed for structural validation).
GGUF_MAGIC = b"GGUF"


def scan_template_string(template: str) -> list:
    """Return list of dangerous constructs found in a Jinja/chat template.
    Pure regex over the raw string -- never renders it."""
    if not template:
        return []
    hits = _DANGEROUS_RE.findall(template)
    # Normalize to unique, readable tokens.
    return sorted({h.strip() for h in hits if h and h.strip()})


def _extract_config_templates(path: Path) -> dict:
    """Pull chat_template / any *_template field from a JSON config file."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    templates = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and "template" in k.lower():
                templates[k] = v
    return templates


def _read_gguf_metadata_template(raw: bytes) -> tuple:
    """Very small GGUF header walk: confirm magic, then look for a
    chat_template metadata value. Returns (template_or_None, malformed_reason_or_None).
    Deliberately conservative -- validates structure, does not fully parse.
    """
    if raw[:4] != GGUF_MAGIC:
        return None, None  # not a GGUF file, not our concern here
    if len(raw) < 24:
        return None, "gguf_header_too_short"
    try:
        # GGUF v2/v3 header: magic(4) version(u32) tensor_count(u64) kv_count(u64)
        version = struct.unpack_from("<I", raw, 4)[0]
        if version not in (1, 2, 3):
            return None, f"gguf_unknown_version_{version}"
        tensor_count = struct.unpack_from("<Q", raw, 8)[0]
        kv_count = struct.unpack_from("<Q", raw, 16)[0]
        # Sanity: counts absurdly large relative to file size => malformed
        if tensor_count > len(raw) or kv_count > len(raw):
            return None, "gguf_counts_exceed_file_size"
        # Look for the literal chat_template key in the metadata region and
        # grab a bounded slice after it. This is a heuristic string pull,
        # not a full KV parse -- enough to feed scan_template_string.
        idx = raw.find(b"chat_template")
        if idx != -1:
            # take a bounded window; templates are text
            window = raw[idx: idx + 8192]
            try:
                text = window.decode("utf-8", errors="ignore")
                return text, None
            except Exception:
                return None, None
        return None, None
    except struct.error:
        return None, "gguf_header_unpackable"


def _validate_safetensors_header(raw: bytes) -> str:
    """Validate the safetensors header structurally. Returns a
    malformed-reason string, or '' if the header is structurally sound.

    safetensors format: first 8 bytes = little-endian u64 header length N,
    then N bytes of JSON metadata, then the tensor byte-buffer.
    """
    if len(raw) < 8:
        return "safetensors_too_short_for_length_prefix"
    header_len = struct.unpack_from("<Q", raw, 0)[0]
    # Header length must fit inside the file and be sane.
    if header_len == 0:
        return "safetensors_zero_header_length"
    if 8 + header_len > len(raw):
        return "safetensors_header_len_exceeds_file"
    if header_len > 100_000_000:  # 100MB of JSON header is not legitimate
        return "safetensors_header_len_absurd"
    header_json = raw[8: 8 + header_len]
    try:
        meta = json.loads(header_json)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "safetensors_header_not_valid_json"
    if not isinstance(meta, dict):
        return "safetensors_header_not_object"
    # Each tensor entry's data_offsets must lie within the buffer.
    buffer_len = len(raw) - 8 - header_len
    for name, spec in meta.items():
        if name == "__metadata__":
            continue
        if not isinstance(spec, dict) or "data_offsets" not in spec:
            return f"safetensors_bad_entry_{name}"
        offs = spec["data_offsets"]
        if (not isinstance(offs, list) or len(offs) != 2
                or not all(isinstance(o, int) and o >= 0 for o in offs)):
            return f"safetensors_bad_offsets_{name}"
        begin, end = offs
        if begin > end or end > buffer_len:
            return f"safetensors_offsets_out_of_bounds_{name}"
    return ""


def check_model_format(path: Path, auto_remediate: bool = False) -> dict:
    path = Path(path)
    if not path.exists():
        return {"status": "SKIPPED", "message": f"{path} not found"}

    ext = path.suffix.lower()
    name = path.name.lower()
    result = {"path": str(path)}

    # ---- Config-file template injection (tokenizer_config.json etc.) ----
    if ext == ".json" or "config" in name:
        templates = _extract_config_templates(path)
        flagged = {}
        for field, tmpl in templates.items():
            hits = scan_template_string(tmpl)
            if hits:
                flagged[field] = hits
        if flagged:
            result["status"] = "DANGEROUS_TEMPLATE_DETECTED"
            result["flagged_template_fields"] = flagged
            _attach_quarantine(result, auto_remediate,
                               "config template contains code-exec/sandbox-escape constructs")
            return result
        if templates:
            result["status"] = "TEMPLATE_OK"
            result["scanned_template_fields"] = list(templates.keys())
            return result
        result["status"] = "NO_TEMPLATE"
        return result

    raw = path.read_bytes()

    # ---- GGUF: structural validation + embedded template scan ----
    if ext == ".gguf" or raw[:4] == GGUF_MAGIC:
        template, malformed = _read_gguf_metadata_template(raw)
        if malformed:
            result["status"] = "MALFORMED_HEADER"
            result["reason"] = malformed
            result["recommended_action"] = {
                "action": "block_load_refetch_from_trusted_source",
                "detail": "GGUF header fails structural validation (parser-crash precondition)",
                "risk": "gated_no_delete",
            }
            return result
        if template:
            hits = scan_template_string(template)
            if hits:
                result["status"] = "DANGEROUS_TEMPLATE_DETECTED"
                result["flagged_constructs"] = hits
                _attach_quarantine(result, auto_remediate,
                                   "GGUF embedded chat_template contains dangerous constructs")
                return result
            result["status"] = "TEMPLATE_OK"
            return result
        result["status"] = "HEADER_OK"
        return result

    # ---- safetensors: structural header validation ----
    if ext == ".safetensors" or name.endswith(".safetensors"):
        reason = _validate_safetensors_header(raw)
        if reason:
            result["status"] = "MALFORMED_HEADER"
            result["reason"] = reason
            result["recommended_action"] = {
                "action": "block_load_refetch_from_trusted_source",
                "detail": "safetensors header fails structural validation",
                "risk": "gated_no_delete",
            }
            return result
        result["status"] = "HEADER_OK"
        return result

    result["status"] = "SKIPPED"
    result["message"] = f"format {ext or '(none)'} not handled by this detector"
    return result


def _attach_quarantine(result: dict, auto_remediate: bool, detail: str):
    action = {
        "action": "quarantine_file",
        "detail": detail + "; move out of load path + chmod 000, never delete",
        "risk": "low_reversible",
    }
    if auto_remediate:
        result["remediation_dispatched"] = action
        result["note"] = "auto_remediate=True: quarantine dispatched"
    else:
        result["recommended_action"] = action
        result["note"] = "gated: quarantine recommended"


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        r = check_model_format(Path(sys.argv[1]))
        print(f"[MODEL-FORMAT] {r['status']} ({r.get('path')})")
    else:
        print("usage: model_format_security_detector.py <model_or_config_file>")
