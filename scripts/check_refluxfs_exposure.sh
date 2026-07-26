#!/bin/bash
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
#
# check_refluxfs_exposure.sh
#
# Checks the three published exposure conditions for CVE-2026-64600
# ("RefluXFS"), a Linux kernel XFS copy-on-write race condition
# disclosed by Qualys 2026-07-22, fixed upstream 2026-07-16:
#   1. Kernel version >= 4.11 and unpatched
#   2. An XFS filesystem is in use
#   3. reflink is enabled on that XFS filesystem
#
# This script assesses CONFIGURATION ONLY. It does not attempt to
# trigger, exploit, or verify the race condition itself.
#
# KNOWN LIMITATION, same caveat as the CVE-2026-31431 kernel-version
# check elsewhere in this project: comparing `uname -r` against a raw
# version number is fragile. Distributions routinely backport security
# fixes without changing the reported kernel version string.
#
# ON ALERTING: if exposure conditions are found, this script prints a
# DRAFT notification message and does NOT send anything automatically.
# Same discipline as remediation/response.py elsewhere in this project:
# real external actions require a human decision, not an automatic
# trigger off a single script's output.
#
# Run: bash check_refluxfs_exposure.sh

echo "=== CVE-2026-64600 (RefluXFS) Exposure Check ==="
echo

# --- Check 1: Kernel version ---
echo "--- Kernel version ---"
KVER=$(uname -r)
echo "Running kernel: $KVER"
echo "NOTE: version-string matching is fragile -- see script header."
echo "Vulnerable range per Qualys: kernel >= 4.11, unpatched (fix merged 2026-07-16)."
echo "Verify actual patch status against your distribution's own advisory,"
echo "not this version string alone."
echo

# --- Environment relevance check ---
# Added after running this on Termux/Android and getting a trivially
# true "not exposed" result that didn't actually test anything -- a
# phone was never a candidate target for a server-side XFS bug. This
# check exists so that fact is visible IN THE OUTPUT every time this
# runs, not just buried in a comment someone has to remember to reread.
NOT_REAL_TARGET=""
if echo "$KVER" | grep -qi "android"; then
    NOT_REAL_TARGET="yes"
    echo "############################################################"
    echo "# NOTE: this looks like Android/Termux, not a rented Linux  #"
    echo "# GPU server. A 'not exposed' result here doesn't prove     #"
    echo "# anything -- this was never a candidate target for a       #"
    echo "# server-side XFS bug. This check only means something when #"
    echo "# run on the actual rented instance (RunPod/Vast.ai/etc).   #"
    echo "############################################################"
    echo
fi

# --- Check 2: XFS filesystems in use ---
echo "--- XFS filesystems in use ---"
XFS_MOUNTS=$(findmnt -t xfs -n -o TARGET,SOURCE 2>/dev/null)
if [ -z "$XFS_MOUNTS" ]; then
    echo "No XFS filesystems found via findmnt. Precondition 2 (XFS in use) NOT met."
    echo "(If findmnt is unavailable, this check could not run -- verify manually"
    echo "with 'mount | grep xfs' before trusting a negative result.)"
else
    echo "XFS filesystem(s) found:"
    echo "$XFS_MOUNTS"
fi
echo

# --- Check 3: reflink status on each XFS mount ---
REFLINK_FOUND=""
EXPOSED_MOUNTS=""
if [ -n "$XFS_MOUNTS" ]; then
    echo "--- reflink status per XFS filesystem ---"
    while read -r target source; do
        if command -v xfs_info >/dev/null 2>&1; then
            REFLINK_LINE=$(xfs_info "$target" 2>/dev/null | grep -o 'reflink=[01]')
            if [ -z "$REFLINK_LINE" ]; then
                echo "$target ($source): could not determine reflink status (xfs_info failed or produced no reflink line)"
            elif [ "$REFLINK_LINE" = "reflink=1" ]; then
                echo "$target ($source): reflink=1 -- precondition 3 MET"
                REFLINK_FOUND="yes"
                EXPOSED_MOUNTS="${EXPOSED_MOUNTS}${target} (${source})\n"
            else
                echo "$target ($source): reflink=0 -- precondition 3 NOT met"
            fi
        else
            echo "$target ($source): xfs_info not available -- cannot determine reflink status. Install xfsprogs to check."
        fi
    done < <(echo "$XFS_MOUNTS")
else
    echo "--- reflink status ---"
    echo "Skipped -- no XFS filesystems found in the previous check."
fi
echo

echo "=== Verdict ==="
if [ -n "$XFS_MOUNTS" ] && [ "$REFLINK_FOUND" = "yes" ]; then
    echo "############################################################"
    echo "# EXPOSURE CONDITIONS MET -- XFS + reflink=1 FOUND          #"
    echo "# Confirm kernel patch status with your provider before    #"
    echo "# treating this host as safe or unsafe.                    #"
    echo "############################################################"
    echo
    echo "--- DRAFT notification (NOT sent -- copy, review, send yourself) ---"
    echo "To: <provider security contact, e.g. security@<provider>.com>"
    echo "Subject: CVE-2026-64600 (RefluXFS) exposure check on rented instance"
    echo
    echo -e "Hi,"
    echo
    echo -e "Running a configuration check for CVE-2026-64600 (RefluXFS,"
    echo -e "disclosed by Qualys 2026-07-22) on an instance rented from you,"
    echo -e "I found the following exposure preconditions present:"
    echo
    echo -e "  Kernel version: ${KVER}"
    echo -e "  XFS filesystem(s) with reflink enabled:"
    echo -e "  ${EXPOSED_MOUNTS}"
    echo -e "This does not confirm the host is unpatched -- only that the"
    echo -e "published preconditions (XFS + reflink=1, kernel >=4.11) are"
    echo -e "present. Could you confirm whether this host's kernel has the"
    echo -e "2026-07-16 fix applied?"
    echo
    echo -e "Thanks,"
    echo -e "$(whoami 2>/dev/null || echo '<your name>')"
    echo "--- END DRAFT ---"
else
    if [ "$NOT_REAL_TARGET" = "yes" ]; then
        echo "Exposure conditions NOT met -- but see the environment note"
        echo "above. This result doesn't validate anything about a real"
        echo "rented Linux server; re-run this on the actual target."
    else
        echo "Exposure conditions NOT met on this host (XFS not in use, or"
        echo "reflink not enabled). No notification needed."
    fi
fi
