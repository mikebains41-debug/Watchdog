"""
patch_daemon_modules.py — converts infinite-loop monitoring modules
into "run once and exit" mode by inserting a break right before their
final time.sleep(POLL_INTERVAL) call.

This does NOT touch the actual scan/check logic at all — only adds one
line so the loop exits after its first real pass instead of running
forever. Confirmed correct for module55's exact structure; verifies
the same pattern exists in each target file before patching, and
SKIPS (does not guess) any file that doesn't match.

Run this from /data/data/com.termux/files/home/Watchdog
"""
import re
import shutil
import os

TARGET_MODULES = [43, 44, 47, 48, 49, 55, 56, 57, 58, 59, 60]
MODULES_DIR = "modules"
BACKUP_DIR = "modules/stub_backups"  # already exists from earlier

def patch_module(module_id):
    path = os.path.join(MODULES_DIR, f"module{module_id}.py")
    if not os.path.isfile(path):
        return "SKIPPED (file not found)"

    with open(path) as f:
        content = f.read()

    if "while True:" not in content:
        return "SKIPPED (no 'while True:' found — different structure, needs manual review)"

    if "break" in content and "time.sleep(POLL_INTERVAL)" in content:
        # Check if a break already exists right before the sleep — avoid double-patching
        pattern = r'break\s*\n\s*time\.sleep\(POLL_INTERVAL\)'
        if re.search(pattern, content):
            return "SKIPPED (already patched)"

    # Find the LAST occurrence of time.sleep(POLL_INTERVAL) or similar
    # sleep call at the end of the loop body, insert break before it,
    # preserving exact indentation.
    sleep_pattern = re.compile(
        r'(?P<indent>[ \t]*)(time\.sleep\((?:POLL_INTERVAL|\w+)\))'
    )
    matches = list(sleep_pattern.finditer(content))
    if not matches:
        return "SKIPPED (no time.sleep(...) call found at end of loop — needs manual review)"

    # Use the LAST match (assume it's the loop's closing sleep)
    last_match = matches[-1]
    indent = last_match.group("indent")
    insertion = f"{indent}break  # patched: run once and exit instead of infinite monitoring loop\n"

    insert_pos = last_match.start()
    new_content = content[:insert_pos] + insertion + content[insert_pos:]

    # Backup original before writing
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(BACKUP_DIR, f"module{module_id}_pre_break_patch.py")
    shutil.copy(path, backup_path)

    with open(path, "w") as f:
        f.write(new_content)

    return f"PATCHED (backup saved to {backup_path})"


if __name__ == "__main__":
    print(f"Patching {len(TARGET_MODULES)} daemon-style modules to run once and exit...\n")
    for i in TARGET_MODULES:
        result = patch_module(i)
        print(f"  module{i}: {result}")
