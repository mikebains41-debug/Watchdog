"""
patch_second_sleep.py — fixes the second exit-path bug found in
module57 (and checks 58/60 for the same pattern): a
time.sleep(POLL_INTERVAL) immediately followed by continue, which
jumps back to the top of the loop and skips the break patch entirely
on certain code paths (e.g. first-run baseline with no findings).

Replaces that specific sleep+continue pair with a break, so ANY exit
path from the loop now actually exits instead of just some of them.
"""
import re
import shutil
import os

TARGET_MODULES = [57, 58, 60]
MODULES_DIR = "modules"
BACKUP_DIR = "modules/stub_backups"

def patch_module(module_id):
    path = os.path.join(MODULES_DIR, f"module{module_id}.py")
    if not os.path.isfile(path):
        return "SKIPPED (file not found)"

    with open(path) as f:
        content = f.read()

    # Match: time.sleep(POLL_INTERVAL) then continue, on the next
    # line, any indentation, preserving the indent of the sleep line
    pattern = re.compile(
        r'(?P<indent>[ \t]*)time\.sleep\(POLL_INTERVAL\)\s*\n\s*continue'
    )
    matches = list(pattern.finditer(content))
    if not matches:
        return "SKIPPED (no sleep+continue pattern found — may already be fine, or different structure)"

    # Backup before modifying
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(BACKUP_DIR, f"module{module_id}_pre_second_patch.py")
    shutil.copy(path, backup_path)

    def replacement(m):
        indent = m.group("indent")
        return f"{indent}break  # patched: exit immediately instead of looping back (was sleep+continue)"

    new_content = pattern.sub(replacement, content)

    with open(path, "w") as f:
        f.write(new_content)

    return f"PATCHED ({len(matches)} occurrence(s) fixed, backup at {backup_path})"


if __name__ == "__main__":
    print(f"Checking/patching {len(TARGET_MODULES)} modules for the second exit-path bug...\n")
    for i in TARGET_MODULES:
        result = patch_module(i)
        print(f"  module{i}: {result}")
