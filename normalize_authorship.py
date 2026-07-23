#!/usr/bin/env python3
"""
normalize_authorship.py

Adds or standardizes an author attribution line across every .py and .sh
file in the repo, so authorship is unambiguous everywhere -- not just in
the files that already had some form of it.

Standard line, identical for both file types:
  # Author: Manmohan (Mike) Bains -- Watchdog AIDR

Behavior per file:
  - If a line already matches an existing author pattern ("Mike Bains",
    "Manmohan", or "Author:"), that SPECIFIC line is replaced with the
    standard form -- not duplicated alongside it.
  - If no such line exists, a new standard line is inserted near the top:
    right after the shebang line if present, otherwise as the very first
    line.
  - An empty file (e.g. a bare __init__.py marker) gets the standard
    line as its sole content -- not skipped.
  - A file is only WRITTEN if the resulting content still parses
    correctly -- ast.parse() for .py files, `bash -n` for .sh files. A
    file that would break is left completely untouched and reported, not
    silently corrupted.
  - Idempotent: running this twice on an already-normalized file changes
    nothing on the second run.

Run from the repo root:
  python3 normalize_authorship.py --dry-run   (preview only, writes nothing)
  python3 normalize_authorship.py             (writes for real)
"""
import ast
import re
import subprocess
import sys
import os

STANDARD_LINE = "# Author: Manmohan (Mike) Bains -- Watchdog AIDR\n"

AUTHOR_PATTERN = re.compile(r"(Mike Bains|Manmohan|Author\s*:)", re.IGNORECASE)

SKIP_DIRS = {"__pycache__", ".git", "node_modules", "venv", ".venv"}


def find_target_files(root="."):
    targets = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py") or fn.endswith(".sh"):
                targets.append(os.path.join(dirpath, fn))
    return sorted(targets)


def normalize_file(path, dry_run=False):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        original = f.read()

    lines = original.splitlines(keepends=True)

    if not lines:
        new_content = STANDARD_LINE
        if path.endswith(".py"):
            try:
                ast.parse(new_content)
            except SyntaxError as e:
                return f"skipped_syntax_error: {e}"
        elif path.endswith(".sh"):
            result = subprocess.run(["bash", "-n"], input=new_content,
                                     capture_output=True, text=True)
            if result.returncode != 0:
                return f"skipped_syntax_error: {result.stderr.strip()[:200]}"
        if not dry_run:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new_content)
        return "inserted"

    author_line_idx = None
    for i, line in enumerate(lines):
        if AUTHOR_PATTERN.search(line):
            author_line_idx = i
            break

    if author_line_idx is not None:
        if lines[author_line_idx].strip() == STANDARD_LINE.strip():
            return "unchanged"
        new_lines = list(lines)
        new_lines[author_line_idx] = STANDARD_LINE
        action = "replaced"
    else:
        insert_at = 1 if lines[0].startswith("#!") else 0
        new_lines = lines[:insert_at] + [STANDARD_LINE] + lines[insert_at:]
        action = "inserted"

    new_content = "".join(new_lines)

    if path.endswith(".py"):
        try:
            ast.parse(new_content)
        except SyntaxError as e:
            return f"skipped_syntax_error: {e}"
    elif path.endswith(".sh"):
        result = subprocess.run(["bash", "-n"], input=new_content,
                                 capture_output=True, text=True)
        if result.returncode != 0:
            return f"skipped_syntax_error: {result.stderr.strip()[:200]}"

    if not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)

    return action


def main():
    dry_run = "--dry-run" in sys.argv
    files = find_target_files(".")
    results = {"replaced": [], "inserted": [], "unchanged": [], "skipped": []}

    for path in files:
        outcome = normalize_file(path, dry_run=dry_run)
        if outcome == "replaced":
            results["replaced"].append(path)
        elif outcome == "inserted":
            results["inserted"].append(path)
        elif outcome == "unchanged":
            results["unchanged"].append(path)
        else:
            results["skipped"].append((path, outcome))

    print("=" * 70)
    print(f"{'DRY RUN -- nothing written -- ' if dry_run else ''}AUTHORSHIP NORMALIZATION")
    print("=" * 70)
    print(f"Total files scanned: {len(files)}")
    print(f"  Replaced existing author line: {len(results['replaced'])}")
    print(f"  Inserted new author line:      {len(results['inserted'])}")
    print(f"  Already standard, unchanged:   {len(results['unchanged'])}")
    print(f"  Skipped (syntax risk):         {len(results['skipped'])}")

    if results["skipped"]:
        print("\nSkipped -- NOT modified, would have broken syntax:")
        for path, reason in results["skipped"]:
            print(f"  {path}: {reason}")

    if results["replaced"]:
        print(f"\nReplaced existing line ({len(results['replaced'])} files):")
        for p in results["replaced"]:
            print(f"  {p}")

    if results["inserted"]:
        print(f"\nInserted new line ({len(results['inserted'])} files):")
        for p in results["inserted"]:
            print(f"  {p}")


if __name__ == "__main__":
    main()
