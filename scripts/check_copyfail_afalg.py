#!/usr/bin/env python3
"""
check_copyfail_afalg.py

Checks whether AF_ALG socket creation is possible on this host --
Microsoft's own official mitigation guidance for CVE-2026-31431
("Copy Fail") states two independent mitigation paths: patch the
kernel, OR block AF_ALG socket creation. Watchdog's existing check for
this CVE (documented in README's Field observations) only does kernel
version string matching, already disclosed as fragile to backports.
This is a DIFFERENT, independent signal -- it doesn't care what the
kernel version string says, it directly tests whether the specific
attack surface (AF_ALG socket creation) is actually reachable right
now.

Neither check alone is complete. Kernel version matching can be fooled
by backports in either direction. This AF_ALG check can only confirm
whether socket creation is CURRENTLY blocked -- it says nothing about
whether the underlying kernel bug is patched, only whether this one
attack path is closed. Both signals together are stronger than either
alone; this does not replace the existing kernel-version check.

STILL UNRESOLVED, stated rather than hidden: this only tests whether
AF_ALG socket creation succeeds for the CURRENT user. A more
privileged process, or a container with different capabilities, could
see a different result. This is a single-context snapshot, not a
system-wide guarantee.

Run: python3 check_copyfail_afalg.py
"""
import socket
import sys


def check_afalg_blocked():
    af_alg = getattr(socket, "AF_ALG", None)
    if af_alg is None:
        return None, "socket.AF_ALG not available in this Python/OS -- not Linux, or a very old Python. Cannot run this check here."

    try:
        s = socket.socket(af_alg, socket.SOCK_SEQPACKET, 0)
        s.close()
        return False, "AF_ALG socket creation SUCCEEDED -- this specific mitigation path is NOT in place. Does not mean the kernel is unpatched, only that this particular attack surface is reachable."
    except PermissionError as e:
        return True, f"AF_ALG socket creation blocked by permissions (PermissionError: {e}) -- this mitigation path IS in place for the current user."
    except OSError as e:
        return True, f"AF_ALG socket creation failed (OSError: {e}) -- this attack path is not currently reachable, though the specific reason (module not loaded vs. explicitly restricted) is not distinguished here."
    except Exception as e:
        return None, f"Unexpected error testing AF_ALG socket creation: {e!r}. Result inconclusive, do not treat as either blocked or open."


def main():
    print("=== CVE-2026-31431 (Copy Fail) -- AF_ALG Mitigation Check ===")
    print()
    print("This checks ONE of Microsoft's two official mitigation paths")
    print("(block AF_ALG socket creation) -- independent of and")
    print("complementary to Watchdog's existing kernel-version check for")
    print("this same CVE, which is separately disclosed as fragile to")
    print("backports.")
    print()

    blocked, detail = check_afalg_blocked()

    if blocked is None:
        print(f"[INCONCLUSIVE] {detail}")
        sys.exit(2)
    elif blocked:
        print(f"[MITIGATED] {detail}")
        sys.exit(0)
    else:
        print(f"[NOT MITIGATED VIA THIS PATH] {detail}")
        print()
        print("This does not confirm the host is vulnerable -- only that")
        print("this specific mitigation is absent. Cross-reference against")
        print("the kernel-version check and your distribution's own")
        print("advisory before drawing a conclusion either way.")
        sys.exit(1)


if __name__ == "__main__":
    main()
