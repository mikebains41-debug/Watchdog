#!/usr/bin/env bash
# Master script — runs all cleanup and update steps in order
set -e
cd ~/Watchdog

SRC=~/storage/downloads

echo "╔══════════════════════════════════════╗"
echo "║  Watchdog — Full Update              ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── Step 1: Repo cleanup ──────────────────────────────────────────────
echo "── Step 1: Repo cleanup ──"
bash "$SRC/step1_cleanup.sh"

# ── Step 2: Add tests for modules 22-50 ──────────────────────────────
echo ""
echo "── Step 2: Add tests for modules 22-50 ──"
python3 "$SRC/step2_add_tests.py"

# Verify syntax after patching
python3 -c "import ast; ast.parse(open('todo/test_b200_watchdog.py').read()); print('  Syntax OK')"

# Run tests
echo ""
echo "── Step 3: Run full test suite ──"
cd ~/Watchdog/todo
python3 test_b200_watchdog.py
TEST_RESULT=$?
cd ~/Watchdog

if [ $TEST_RESULT -ne 0 ]; then
    echo "TESTS FAILED — fix before continuing"
    exit 1
fi

# ── Step 4: Update README ─────────────────────────────────────────────
echo ""
echo "── Step 4: Update README.md ──"
cp "$SRC/README.md" ~/Watchdog/README.md
echo "  OK  README.md updated (50 modules)"

# ── Step 5: Commit everything ─────────────────────────────────────────
echo ""
echo "── Step 5: Final commit ──"
git add \
    todo/test_b200_watchdog.py \
    README.md

git diff --cached --quiet && echo "  Nothing new to commit" || \
    git commit -m "Add tests for modules 22-50, update README to 50 modules"

git push

echo ""
echo "╔══════════════════════════════════════╗"
echo "║  All done.                           ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "Total modules:    50"
echo "Physics models:   19"
echo "README:           updated"
