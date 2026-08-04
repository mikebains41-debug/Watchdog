#!/usr/bin/env bash
# Step 1: Fix repo hygiene — verify module21, commit untracked, update .gitignore
set -e
cd ~/Watchdog

echo "=== Checking module21 quantum wiring ==="
if grep -q "M_quantum_efficiency_score" todo/module21.py; then
    echo "  OK  module21.py has quantum wiring"
else
    echo "  MISSING  quantum wiring in module21.py — needs re-push"
fi

echo ""
echo "=== Updating .gitignore ==="
cat >> .gitignore << 'EOF'

# Watchdog runtime outputs
*.jsonl
compliance_*.json
module*_????????_??????.jsonl
watchdog_supervisor_*.jsonl
/tmp/watchdog_*

# Collected results (raw data — tracked selectively)
cpu_results/CPU_SUMMARY_*.txt
cpu_results/*.tar.gz
b200_watchdog/B200_SUMMARY_*.txt
collect_*.sh
main
EOF
echo "  OK  .gitignore updated"

echo ""
echo "=== Committing untracked files selectively ==="
# Commit the untracked items that SHOULD be tracked
git add b200_watchdog/B200_SUMMARY_20260731_193939.txt \
        b200_watchdog/B200_SUMMARY_20260731_194147.txt \
        cpu_results/CPU_SUMMARY_20260731_193859.txt \
        cpu_results/CPU_SUMMARY_20260731_194132.txt \
        collect_b200_results.sh \
        collect_cpu_results.sh \
        .gitignore 2>/dev/null || true

# The mystery 'main' file — check what it is first
if [ -f main ]; then
    echo "  INFO  'main' file contents:"
    head -3 main
    # Only add if it looks like a script, not a binary
    if file main | grep -q "text"; then
        git add main 2>/dev/null || true
    else
        echo "main" >> .gitignore
    fi
fi

git diff --cached --quiet && echo "  Nothing new to commit" || \
    git commit -m "Fix repo hygiene: gitignore runtime outputs + commit B200/CPU result summaries"

echo ""
echo "=== Final git status ==="
git status --short

git push 2>/dev/null && echo "Pushed." || echo "Nothing to push."
echo ""
echo "=== Step 1 done ==="
