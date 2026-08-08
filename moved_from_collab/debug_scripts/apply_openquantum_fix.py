"""
Applies the four real method fixes to quantum_providers/openquantum_provider.py
Replaces stub bodies in place. Run from the repo root.
"""
import re
import sys

TARGET = "quantum_providers/openquantum_provider.py"
FIX_FILE = "openquantum_provider_fix.py"

with open(TARGET) as f:
    src = f.read()

with open(FIX_FILE) as f:
    fix_src = f.read()

# Extract each function body from the fix file
def extract_func(name, text):
    pattern = rf"(def {name}\(self.*?\n(?:(?:    .*\n)|\n)*)"
    m = re.search(pattern, text)
    return m.group(1).rstrip() + "\n" if m else None

replacements = {}
for fname in ("get_calibration_data", "get_queue_depth",
              "get_job_history", "get_job_timing"):
    body = extract_func(fname, fix_src)
    if body is None:
        print(f"WARNING: could not extract {fname} from fix file")
        continue
    replacements[fname] = body

changed = 0
for fname, new_body in replacements.items():
    # Match the existing stub: def fname(...): ... up to next top-level def
    old_pattern = re.compile(
        rf"    def {fname}\(self.*?\n(?:(?:        .*\n)|(?:    .*\n)|\n)*?(?=    def |\Z)",
        re.MULTILINE
    )
    m = old_pattern.search(src)
    if not m:
        print(f"WARNING: could not find existing {fname} in {TARGET} — skipped")
        continue

    indented_new = "\n".join(
        ("    " + line if line.strip() else line)
        for line in new_body.split("\n")
    ) + "\n\n"

    src = src[:m.start()] + indented_new + src[m.end():]
    changed += 1
    print(f"  Replaced: {fname}")

if changed == 0:
    print("Nothing changed — aborting write")
    sys.exit(1)

with open(TARGET, "w") as f:
    f.write(src)

print(f"\n{changed}/4 methods replaced in {TARGET}")
