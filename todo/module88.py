#!/usr/bin/env python3
"""
Watchdog — Module 88: Indirect Prompt Injection Detector
Status: FUNCTIONAL — no special hardware required

THE ATTACK: an agent reads external content — a web page, a document,
a tool's output, an email — and that content contains instructions
which the agent follows as if the operator had typed them.

Confirmed, published research: Greshake, Abdelnabi, Mishra, Endres,
Holz & Fritz, "Not what you've signed up for: Compromising Real-World
LLM-Integrated Applications with Indirect Prompt Injection." Presented
at ACM CCS AISec Workshop 2023. Demonstrated against real deployed LLM
applications: an attacker who never interacts with the target user or
model directly places injected instructions in content the target
retrieves — a web page it browses, a document it summarizes, an email
it reads — and the model treats those instructions as legitimate.

This is the natural companion to modules 76-85. Those modules watch
what an agent DOES after compromise — its egress, its credential
access, its Kubernetes footprint. This module watches the boundary
where compromise BEGINS: the moment untrusted content crosses into the
agent's instruction-following context.

WHY THIS IS HARD TO STOP AT THE MODEL LAYER: the model cannot reliably
distinguish "instructions from my operator" from "text that looks like
instructions, encountered while doing my job." An agent summarizing a
document is supposed to process instruction-shaped sentences as
content, not commands — but there is no hard boundary in a token
stream. Detection has to happen at the infrastructure layer, watching
what content flows into an agent's context and flagging what looks
like an injection attempt BEFORE the model acts on it.

WHAT THIS MODULE DETECTS — all functional now:
  1. Instruction-override markers in fetched/tool-output content:
     phrases structurally designed to reassign the model's role or
     discard its prior instructions, at the PATTERN level (not a
     reproducible payload library).
  2. Zero-width and invisible Unicode characters used to hide injected
     text from human review while it remains machine-readable —
     U+200B, U+200C, U+200D, U+FEFF, and the Unicode Tags block
     (U+E0000-E007F), the latter demonstrated in real jailbreak research
     as an invisible-payload channel.
  3. Role-marker injection: content containing fake system/assistant
     turn markers (e.g. structured tokens resembling a chat template's
     role delimiters) that do not belong in the content type being
     processed.
  4. Encoded payload smuggling: base64 or hex blocks embedded in content
     that is not expected to carry binary data, sized consistently with
     a text instruction rather than genuine binary content.
  5. Abnormal instruction density: a statistical outlier in imperative
     sentence structure for the content type (a CSV row, a code
     comment, an image alt-text field are not supposed to contain
     paragraph-length directives).
  6. Content-type mismatch: file extension or declared MIME type not
     matching the actual content structure — a strong signal the file
     was crafted to be misclassified by a naive content-type check.
  7. Tool-output injection: MCP/function-call results and API responses
     scanned before being appended to agent context, since these are a
     confirmed and growing injection vector distinct from documents.

WHAT THIS MODULE DOES NOT DO: it does not reproduce or catalogue
verbatim jailbreak strings. Detection stays at the structural/pattern
level — the presence of role-override syntax, invisible characters,
or anomalous instruction density — which is what a defender needs and
does not itself function as an attack toolkit.
"""
import os, json, time, datetime, glob, re, hashlib, unicodedata

POLL_INTERVAL       = 60
MAX_FILE_SCAN_BYTES = 2 * 1024 * 1024
STATE_FILE          = "/tmp/watchdog_prompt_injection.json"

# Content locations an agent might read from — tool outputs, fetched
# pages, uploaded documents, downloaded files
SCAN_DIRS = [
    "/tmp/agent_downloads", "/tmp/agent_fetched", "/tmp/tool_output",
    "/var/lib/agent/inbox", os.path.expanduser("~/agent_workspace"),
    "/tmp", os.path.expanduser("~/Downloads"),
]
SCAN_EXTENSIONS = [".txt", ".md", ".html", ".htm", ".json", ".csv",
                   ".xml", ".yaml", ".yml", ".py", ".js"]

# Invisible/zero-width Unicode characters — a documented payload-hiding
# channel. Presence of ANY of these in ordinary text content is itself
# the finding; we do not need to decode what they spell to flag it.
INVISIBLE_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u2060": "WORD JOINER",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
}
# Unicode Tags block — demonstrated as an invisible ASCII-smuggling
# channel in published prompt injection research (2024)
TAGS_BLOCK_RANGE = (0xE0000, 0xE007F)

# Structural markers indicating an attempt to reassign model role or
# override prior instructions. Pattern-level only — generic structural
# phrases, not a reproducible payload library.
ROLE_OVERRIDE_PATTERNS = [
    r'\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b',
    r'\bdisregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|rules?)\b',
    r'\byou\s+are\s+now\s+(in\s+)?(?:a\s+)?(?:new|different)\s+(mode|role|persona)\b',
    r'\bnew\s+system\s+prompt\b',
    r'\[?\s*system\s*\]?\s*:\s*.{0,10}override',
    r'\bact\s+as\s+if\s+you\s+(have\s+)?no\s+(restrictions?|guidelines?|filters?)\b',
    r'\breveal\s+your\s+(system\s+)?(prompt|instructions)\b',
    r'<\|?\s*(system|assistant|user)\s*\|?>',   # fake chat template markers
    r'###\s*(instruction|system|override)\s*:',
]

# Encoded payload smuggling — a base64/hex block of meaningful size in
# a context that should not contain binary data
BASE64_BLOCK = re.compile(r'[A-Za-z0-9+/]{200,}={0,2}')
HEX_BLOCK    = re.compile(r'(?:[0-9a-fA-F]{2}\s?){100,}')

# Content types where a long imperative instruction has no legitimate
# reason to appear
NON_INSTRUCTION_CONTEXTS = [".csv", ".json"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"scanned_hashes": {}, "established": now_iso()}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def find_scannable_files():
    found = []
    seen = set()
    for base in SCAN_DIRS:
        if not os.path.isdir(base):
            continue
        for ext in SCAN_EXTENSIONS:
            for path in glob.glob(os.path.join(base, f"*{ext}"))[:100]:
                if path not in seen and os.path.isfile(path):
                    seen.add(path)
                    found.append(path)
    return found[:300]

def read_content(path):
    try:
        size = os.path.getsize(path)
        with open(path, "r", errors="replace") as f:
            return f.read(min(size, MAX_FILE_SCAN_BYTES))
    except Exception:
        return None

def scan_invisible_chars(content):
    findings = []
    counts = {}
    for ch in content:
        if ch in INVISIBLE_CHARS:
            counts[ch] = counts.get(ch, 0) + 1
        else:
            cp = ord(ch)
            if TAGS_BLOCK_RANGE[0] <= cp <= TAGS_BLOCK_RANGE[1]:
                counts["TAGS_BLOCK"] = counts.get("TAGS_BLOCK", 0) + 1
    for ch, count in counts.items():
        name = INVISIBLE_CHARS.get(ch, "UNICODE TAGS BLOCK CHARACTER")
        findings.append({"character": name, "count": count})
    return findings

def scan_role_override(content):
    findings = []
    for pattern in ROLE_OVERRIDE_PATTERNS:
        matches = list(re.finditer(pattern, content, re.IGNORECASE))
        if matches:
            m = matches[0]
            start = max(0, m.start() - 30)
            end = min(len(content), m.end() + 30)
            findings.append({
                "pattern_matched": True,
                "occurrences": len(matches),
                "context": content[start:end].replace("\n", " ")[:100],
            })
    return findings

def scan_encoded_payloads(content, extension):
    findings = []
    if extension in (".py", ".js"):
        return findings  # code files legitimately contain long tokens
    b64_matches = BASE64_BLOCK.findall(content)
    for match in b64_matches[:5]:
        findings.append({"type": "base64_block", "length": len(match)})
    hex_matches = HEX_BLOCK.findall(content)
    for match in hex_matches[:5]:
        findings.append({"type": "hex_block", "length": len(match)})
    return findings

def scan_instruction_density(content, extension):
    """
    A statistical check: content types that should not carry paragraph
    directives (CSV cells, JSON string values) but do.
    """
    if extension not in NON_INSTRUCTION_CONTEXTS:
        return None
    imperative_markers = len(re.findall(
        r'\b(must|should|please|now|immediately|always|never)\b',
        content, re.IGNORECASE))
    sentence_count = len(re.findall(r'[.!?]\s', content)) + 1
    density = imperative_markers / max(sentence_count, 1)
    if density > 0.4 and len(content) > 200:
        return {"density": round(density, 3), "imperative_markers": imperative_markers}
    return None

def scan_content_type_mismatch(path, content):
    """A .json file that does not parse as JSON, a .csv with no delimiters, etc."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        try:
            json.loads(content)
            return None
        except Exception:
            return {"declared": "json", "issue": "does not parse as valid JSON"}
    if ext == ".csv":
        lines = content.splitlines()[:5]
        if lines and not any("," in l or ";" in l or "\t" in l for l in lines):
            return {"declared": "csv", "issue": "no delimiters found in first lines"}
    return None

def analyse_file(path, content, state):
    alerts = []
    ext = os.path.splitext(path)[1].lower()

    invisible = scan_invisible_chars(content)
    if invisible:
        total = sum(f["count"] for f in invisible)
        alerts.append({
            "event":    "INVISIBLE_UNICODE_PAYLOAD",
            "severity": "CRITICAL",
            "path":     path,
            "characters_found": invisible,
            "total_hidden_chars": total,
            "confidence": 0.85,
            "citation": "Unicode Tags block invisible-payload technique, 2024 prompt injection research",
            "note": ("This file contains invisible or zero-width Unicode "
                     "characters. This is a documented technique for hiding "
                     "instructions from human review while keeping them "
                     "machine-readable to an LLM processing the raw text"),
        })

    role_override = scan_role_override(content)
    if role_override:
        alerts.append({
            "event":    "ROLE_OVERRIDE_PATTERN",
            "severity": "CRITICAL",
            "path":     path,
            "matches":  role_override,
            "confidence": 0.75,
            "citation": "Greshake et al., ACM CCS AISec Workshop 2023 (indirect prompt injection)",
            "note": ("Content contains structural language attempting to "
                     "override prior instructions or reassign the model's "
                     "role. If this content is fed to an agent's context, "
                     "the model may follow these as legitimate instructions"),
        })

    encoded = scan_encoded_payloads(content, ext)
    if encoded:
        alerts.append({
            "event":    "ENCODED_PAYLOAD_IN_CONTENT",
            "severity": "WARN",
            "path":     path,
            "blocks":   encoded,
            "confidence": 0.55,
            "note": ("A large base64 or hex-encoded block was found in "
                     "content that is not expected to carry binary payloads. "
                     "This is a known technique for smuggling instructions "
                     "past naive content filters"),
        })

    density = scan_instruction_density(content, ext)
    if density:
        alerts.append({
            "event":    "ABNORMAL_INSTRUCTION_DENSITY",
            "severity": "WARN",
            "path":     path,
            "extension": ext,
            "metrics":  density,
            "confidence": 0.50,
            "note": (f"A .{ext.lstrip('.')} file has an unusually high "
                     "density of imperative language for its content type"),
        })

    mismatch = scan_content_type_mismatch(path, content)
    if mismatch:
        alerts.append({
            "event":    "CONTENT_TYPE_MISMATCH",
            "severity": "WARN",
            "path":     path,
            "detail":   mismatch,
            "confidence": 0.55,
            "note": ("File extension does not match actual content "
                     "structure — consistent with a file crafted to be "
                     "misclassified by a naive extension-based filter"),
        })

    return alerts

def find_mcp_tool_output_files():
    """MCP/function-call result caches, if the agent framework writes them to disk."""
    patterns = ["/tmp/mcp_*.json", "/tmp/tool_result_*.json",
               "/tmp/function_output_*.json"]
    found = []
    for pattern in patterns:
        found.extend(glob.glob(pattern)[:50])
    return found

def analyse(files, state):
    alerts = []
    known_hashes = state.setdefault("scanned_hashes", {})

    for path in files:
        content = read_content(path)
        if content is None:
            continue

        h = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        if known_hashes.get(path) == h:
            continue  # unchanged since last scan
        known_hashes[path] = h

        alerts.extend(analyse_file(path, content, state))

    return alerts, state

def main():
    log = open(f"module88_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "88_indirect_prompt_injection",
        "status": "FUNCTIONAL — no special hardware required",
        "attack_class": ("An agent reads external content — a web page, a "
                          "document, tool output — and that content contains "
                          "instructions the agent follows as if the operator "
                          "had typed them"),
        "reference": ("Greshake, Abdelnabi, Mishra, Endres, Holz & Fritz — "
                       "Not what you've signed up for: Compromising "
                       "Real-World LLM-Integrated Applications with Indirect "
                       "Prompt Injection. ACM CCS AISec Workshop 2023. "
                       "Demonstrated against real deployed LLM applications"),
        "companion_to": ("modules 76-85 watch what an agent does after "
                          "compromise. This module watches the boundary "
                          "where compromise begins — untrusted content "
                          "entering the agent's instruction-following context"),
        "detects": [
            "Role-override / instruction-reassignment structural patterns",
            "Invisible Unicode payload channels (zero-width, Tags block)",
            "Fake chat-template role markers in content",
            "Base64/hex payload smuggling in non-binary content",
            "Abnormal imperative-language density for content type",
            "File extension vs actual content-structure mismatch",
            "MCP / tool-call output injection",
        ],
        "restraint": ("Detection stays at the structural/pattern level. This "
                       "module does not reproduce or catalogue verbatim "
                       "jailbreak strings — a comprehensive payload library "
                       "would function as an attack toolkit, not a defence"),
        "scan_directories": SCAN_DIRS,
    })

    state = load_state()

    while True:
        files = find_scannable_files()
        mcp_files = find_mcp_tool_output_files()
        all_files = list(set(files + mcp_files))

        emit({"event": "INJECTION_SCAN",
              "files_scanned": len(all_files),
              "mcp_tool_outputs": len(mcp_files)})

        if not all_files:
            emit({"event": "NO_SCANNABLE_CONTENT",
                  "note": ("No content found in monitored directories. This "
                           "module activates where an agent fetches, "
                           "downloads, or processes external content.")})
            time.sleep(POLL_INTERVAL)
            continue

        alerts, state = analyse(all_files, state)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "CONTENT_CLEAN", "files_scanned": len(all_files)})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
