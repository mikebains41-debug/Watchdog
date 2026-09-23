"""
Watchdog provider benchmark -- shared test registry.

Every probe imports TESTS from here so an ID/title is defined in ONE place and
matches across probe output, result JSON, and the scoreboard. Adding a provider
later is a new column; adding a test is a new row here.

VERDICTS (from the provider's point of view -- PASS means the provider did the
right thing, so a clean machine is all PASS):
  PASS    -- provider did the right thing (clean, patched, isolated, honest)
  FAIL    -- provider did not (leftover data, unpatched, exposed, mis-billed)
  BLOCKED -- the platform prevented the check (still informative; recorded)
  ERROR   -- the probe itself failed (tool missing, no GPU, crash)
  NA      -- not applicable on this machine (e.g. single-GPU box, NVLink test)

Everything here measures YOUR OWN rented instance and what the provider handed
you. No probe reaches into another live tenant. That boundary is what keeps the
benchmark publishable.
"""

VERDICTS = ("PASS", "FAIL", "BLOCKED", "ERROR", "NA")

# id -> (title, group, one-line what-it-checks)
TESTS = {
    # HH -- Handover Hygiene: was the machine clean when handed over?
    "HH-01": ("Leftover Tenant Files", "Handover Hygiene",
              "files owned by a previous tenant in shared paths (metadata only)"),
    "HH-02": ("VRAM Zeroed at Handover", "Handover Hygiene",
              "a fresh GPU allocation read back -- all zero, or previous contents"),
    "HH-03": ("GPU Counter Reset", "Handover Hygiene",
              "NVLink / PCIe / ECC counters at zero, or carrying prior activity"),
    "HH-04": ("Live Context at Handover", "Handover Hygiene",
              "memory in use, power above idle, or boosted clocks before any work"),
    "HH-05": ("GPU Reset Available", "Handover Hygiene",
              "whether nvidia-smi --gpu-reset runs and clears the accounting gap"),
    # HS -- Host Security: what did they ship you?
    "HS-01": ("Kernel vs KEV", "Host Security",
              "running kernel against known-exploited-vulnerability list"),
    "HS-02": ("Container Escape Surface", "Host Security",
              "docker socket, dangerous capabilities, host paths mounted in"),
    "HS-03": ("Namespace Isolation", "Host Security",
              "visibility of host processes / other tenants / host network"),
    "HS-04": ("Baked-in Credentials", "Host Security",
              "keys or tokens left in the base image handed to you"),
    "HS-05": ("Cloud Metadata Reachable", "Host Security",
              "cloud metadata endpoint reachable from inside the instance"),
    # BH -- Billing Honesty: charged for what you got?
    "BH-01": ("VRAM Accounting Gap", "Billing Honesty",
              "memory reported allocated after teardown vs actually in use"),
    "BH-02": ("Ghost Power at Idle", "Billing Honesty",
              "watts drawn above true idle with a model resident but 0% util"),
    "BH-03": ("GPU Generation as Advertised", "Billing Honesty",
              "the GPU present matches the generation the listing sold"),
    "BH-04": ("Noisy-Neighbour Throughput Loss", "Billing Honesty",
              "throughput lost to co-tenant contention on a shared host"),
}

GROUP_ORDER = ["Handover Hygiene", "Host Security", "Billing Honesty"]


def title(tid):
    return TESTS[tid][0] if tid in TESTS else tid


def make_result(tid, verdict, detail, **evidence):
    """Uniform result record every probe writes, so the scoreboard can read them all."""
    assert verdict in VERDICTS, "bad verdict %r for %s" % (verdict, tid)
    assert tid in TESTS, "unknown test id %r" % tid
    t = TESTS[tid]
    return {"test_id": tid, "title": t[0], "group": t[1], "checks": t[2],
            "verdict": verdict, "detail": detail, "evidence": evidence}
