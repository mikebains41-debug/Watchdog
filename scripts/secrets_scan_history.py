#!/usr/bin/env python3
"""
Watchdog -- secrets scan of the FULL git history (masked output).

The Watchdog repo is public. Anything ever committed -- even if deleted in a
later commit -- is still readable in history. This scans every line ever ADDED
in any commit on any branch, and prints only a MASKED form of each match, so
running it never puts a full secret on screen.

If a real credential is found: ROTATE IT at the provider first. Rewriting git
history afterwards does not help once a repo has been public -- copies and
forks may already exist.

LIMITS: pattern-based. It finds common key formats and obvious assignments; it
cannot recognise every credential format, and some matches will be
placeholders (flagged 'likely placeholder', not dropped). A clean result means
none of these patterns matched, not that no secret exists.

Usage (from the repo root):  python3 scripts/secrets_scan_history.py
"""
import re
import subprocess
import sys

PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}")),
    ("Anthropic key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI-style key", re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("Hugging Face token", re.compile(r"hf_[A-Za-z0-9]{30,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Stripe live key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("Credentials in URL", re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@'\"]+:[^/\s:@'\"]{4,}@")),
    ("Assigned secret", re.compile(
        r"(?i)(?:api[_\-]?key|secret|token|passw(?:or)?d|client[_\-]?secret|auth)\w*\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]")),
]
PLACEHOLDER = re.compile(r"(?i)your|example|xxxx|<|\$\{|replace|changeme|dummy|placeholder|test|fake|mock|sample|\*\*\*")


def mask(s):
    s = s.strip()
    return "%s...%s (%d chars)" % (s[:4], s[-2:], len(s)) if len(s) > 8 else "*** (%d chars)" % len(s)


def main():
    try:
        p = subprocess.Popen(["git", "log", "-p", "--all", "--no-color", "--format=@@COMMIT %h %ad", "--date=short"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    except FileNotFoundError:
        print("git not found"); return 2
    commit, fname, seen, findings, lines = "?", "?", set(), [], 0
    for line in p.stdout:
        if line.startswith("@@COMMIT "):
            commit = line[9:].strip(); continue
        if line.startswith("+++ "):
            fname = line[6:].strip() if line.startswith("+++ b/") else line[4:].strip(); continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        lines += 1
        body = line[1:]
        for name, rx in PATTERNS:
            for m in rx.finditer(body):
                val = m.group(1) if m.groups() else m.group(0)
                key = val
                if key in seen:
                    continue
                seen.add(key)
                findings.append((commit, fname, name, mask(val), bool(PLACEHOLDER.search(val))))
    p.wait()
    real = [f for f in findings if not f[4]]
    print("SECRETS SCAN -- full git history, %d added lines scanned, output masked" % lines)
    for c, f, n, m, ph in findings:
        print("  %-22s %-18s %-40s %s%s" % (c, n, f[-40:], m, "  [likely placeholder]" if ph else ""))
    print("\n%d match(es): %d likely placeholder, %d to check by hand" % (len(findings), len(findings) - len(real), len(real)))
    if real:
        print("For each one to check: if it is a real credential, ROTATE it at the provider now.")
        print("Removing it from history does not help once the repo has been public.")
    else:
        print("No pattern matched a non-placeholder value. Not proof that no secret exists.")
    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main())
