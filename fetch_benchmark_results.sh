#!/bin/bash
# Pull the benchmark result JSONs off the pod branch into a local folder so
# fp_audit.py and scoreboard.py can read them on the phone. Read-only: copies
# files out of the branch, does not merge or change main.
set -e
cd ~/Watchdog
mkdir -p vastai_results
git fetch origin vastai-51172-benchmark 2>/dev/null || true
for f in $(git ls-tree -r --name-only origin/vastai-51172-benchmark 2>/dev/null | grep -E 'benchmark.*\.json|handover.*\.json|scoreboard\.md'); do
  git show "origin/vastai-51172-benchmark:$f" > "vastai_results/$(basename "$f")" 2>/dev/null && echo "got $(basename "$f")"
done
echo "--- files now local ---"
ls -1 vastai_results/
