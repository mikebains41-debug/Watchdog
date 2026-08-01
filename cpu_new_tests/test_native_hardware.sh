#!/bin/bash
echo "=== Native CPU Hardware Tests ==="
echo "--- Cache ---"
lscpu | grep -E "L1|L2|L3|cache" 2>/dev/null || echo "No cache info"
echo "--- Memory ---"
free -h
echo "--- CPU ---"
lscpu | grep -E "Model name|CPU\(s\)|MHz"
