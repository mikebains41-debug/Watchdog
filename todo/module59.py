#!/usr/bin/env python3
"""
Watchdog — Module 59: Entropy & QRNG Statistical Health Monitor
Status: FUNCTIONAL — no special hardware required

Attack vector: every cryptographic operation on the control host depends on
the kernel entropy pool. So does randomized benchmarking, which is how a
quantum system measures its own gate fidelity. If the entropy source is
degraded, biased, or has been quietly replaced with something predictable:

  - TLS session keys, SSH host keys, and API tokens become guessable
  - Randomized benchmarking returns fabricated fidelity numbers because the
    "random" Clifford sequences are not random
  - Any nonce-based defence (module40's replay prevention) is defeated
  - A hardware RNG that has failed silently reports success while emitting
    a repeating or constant stream

Entropy starvation is also a real availability problem: a control host that
blocks on /dev/random during key generation stalls the whole job pipeline.

Implements a genuine subset of NIST SP 800-22 Rev 1a:
  - 2.1  Frequency (Monobit) Test
  - 2.2  Frequency Test within a Block
  - 2.3  Runs Test
  - 2.6  Discrete Fourier Transform (Spectral) Test — simplified
  - Byte-level chi-squared uniformity
  - Shannon entropy per byte
  - Repeated-block detection (catches a stuck or replaying source)

These use the real formulas with erfc / igamc, not the placeholder
approximations that appear in most quick implementations.

Sources checked, in order of preference:
  /dev/hwrng      hardware RNG (TPM, CPU RNG, or a QRNG appliance)
  /dev/random     blocking kernel pool
  /dev/urandom    non-blocking kernel pool
Also reads /proc/sys/kernel/random/entropy_avail for pool depth.
"""
import os, json, math, time, datetime, hashlib
from collections import Counter

SAMPLE_BYTES         = 4096     # bytes per test run — 32768 bits
P_VALUE_THRESHOLD    = 0.01     # NIST standard: p < 0.01 = fail
BLOCK_SIZE_BITS      = 128      # for the block frequency test
ENTROPY_AVAIL_FLOOR  = 256      # kernel pool bits below this = starvation
SHANNON_FLOOR        = 7.90     # bits/byte; ideal is 8.0
REPEAT_BLOCK_SIZE    = 64       # bytes; identical blocks = stuck source
POLL_INTERVAL        = 600      # seconds between checks
STATE_FILE           = "/tmp/watchdog_entropy_state.json"

ENTROPY_SOURCES = ["/dev/hwrng", "/dev/random", "/dev/urandom"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ── Special functions ──────────────────────────────────────────────────
def erfc(x: float) -> float:
    """Complementary error function — math.erfc, present since Python 3.2."""
    return math.erfc(x)

def igamc(a: float, x: float) -> float:
    """
    Regularised upper incomplete gamma function Q(a, x).
    Needed for the block frequency and DFT tests' p-values.
    Continued-fraction expansion for x > a+1, series otherwise.
    """
    if x <= 0 or a <= 0:
        return 1.0
    if x < a + 1.0:
        # Series expansion for P(a,x), then Q = 1 - P
        ap = a
        total = 1.0 / a
        delta = total
        for _ in range(1000):
            ap += 1.0
            delta *= x / ap
            total += delta
            if abs(delta) < abs(total) * 1e-15:
                break
        try:
            return 1.0 - total * math.exp(-x + a * math.log(x) - math.lgamma(a))
        except (ValueError, OverflowError):
            return 1.0
    # Continued fraction for Q(a,x)
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    try:
        return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h
    except (ValueError, OverflowError):
        return 0.0

# ── Bit helpers ────────────────────────────────────────────────────────
def bytes_to_bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)

# ── NIST SP 800-22 tests ───────────────────────────────────────────────
def monobit_test(bits: str) -> dict:
    """
    NIST SP 800-22 section 2.1 — Frequency (Monobit) Test.
    Counts ones vs zeros. p = erfc(|S_n| / sqrt(2n)) where S_n is the
    signed sum of the bit sequence mapped to +/-1.
    """
    n = len(bits)
    if n == 0:
        return {"test": "monobit", "p_value": 0.0, "passed": False,
                 "error": "empty sequence"}
    s = sum(1 if b == "1" else -1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)
    p = erfc(s_obs / math.sqrt(2.0))
    return {"test": "monobit", "n_bits": n, "ones": bits.count("1"),
             "zeros": bits.count("0"), "s_obs": round(s_obs, 6),
             "p_value": round(p, 6), "passed": p >= P_VALUE_THRESHOLD}

def block_frequency_test(bits: str, block_size: int = BLOCK_SIZE_BITS) -> dict:
    """
    NIST SP 800-22 section 2.2 — Frequency Test within a Block.
    Splits into M-bit blocks, measures how far each block's proportion of
    ones deviates from 0.5, and evaluates chi-squared against the
    incomplete gamma function.
    """
    n = len(bits)
    if n < block_size:
        return {"test": "block_frequency", "p_value": 0.0, "passed": False,
                 "error": f"need >= {block_size} bits"}
    num_blocks = n // block_size
    chi_sq = 0.0
    for i in range(num_blocks):
        block = bits[i * block_size:(i + 1) * block_size]
        pi = block.count("1") / block_size
        chi_sq += (pi - 0.5) ** 2
    chi_sq *= 4.0 * block_size
    p = igamc(num_blocks / 2.0, chi_sq / 2.0)
    return {"test": "block_frequency", "block_size": block_size,
             "num_blocks": num_blocks, "chi_squared": round(chi_sq, 4),
             "p_value": round(p, 6), "passed": p >= P_VALUE_THRESHOLD}

def runs_test(bits: str) -> dict:
    """
    NIST SP 800-22 section 2.3 — Runs Test.
    Counts uninterrupted runs of identical bits. A biased or correlated
    source produces too few or too many runs. Prerequisite: the monobit
    proportion must be within 2/sqrt(n) of 0.5, else the test is invalid.
    """
    n = len(bits)
    if n == 0:
        return {"test": "runs", "p_value": 0.0, "passed": False,
                 "error": "empty sequence"}
    pi = bits.count("1") / n
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return {"test": "runs", "p_value": 0.0, "passed": False,
                 "prerequisite_failed": True, "pi": round(pi, 6),
                 "note": "monobit proportion out of range — runs test invalid"}
    v_obs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            v_obs += 1
    numerator = abs(v_obs - 2.0 * n * pi * (1.0 - pi))
    denominator = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    if denominator == 0:
        return {"test": "runs", "p_value": 0.0, "passed": False,
                 "error": "degenerate denominator"}
    p = erfc(numerator / denominator)
    return {"test": "runs", "n_bits": n, "runs_observed": v_obs,
             "pi": round(pi, 6), "p_value": round(p, 6),
             "passed": p >= P_VALUE_THRESHOLD}

def spectral_test(bits: str) -> dict:
    """
    NIST SP 800-22 section 2.6 — Discrete Fourier Transform (Spectral) Test.
    Detects periodic patterns. Implemented with a direct DFT over a
    truncated sequence — the full FFT is unnecessary at this sample size
    and this avoids a numpy dependency.
    """
    n = len(bits)
    # Direct DFT is O(n^2); cap the working length to keep this cheap.
    work = min(n, 4096)
    if work < 1000:
        return {"test": "spectral", "p_value": 1.0, "passed": True,
                 "skipped": True, "note": "sequence too short for DFT test"}
    x = [1.0 if bits[i] == "1" else -1.0 for i in range(work)]
    half = work // 2
    magnitudes = []
    for k in range(half):
        re = im = 0.0
        ang = 2.0 * math.pi * k / work
        for i in range(work):
            a = ang * i
            re += x[i] * math.cos(a)
            im -= x[i] * math.sin(a)
        magnitudes.append(math.sqrt(re * re + im * im))

    threshold = math.sqrt(math.log(1.0 / 0.05) * work)
    n0 = 0.95 * half                      # expected peaks below threshold
    n1 = sum(1 for m in magnitudes if m < threshold)
    denom = math.sqrt(work * 0.95 * 0.05 / 4.0)
    if denom == 0:
        return {"test": "spectral", "p_value": 0.0, "passed": False}
    d = (n1 - n0) / denom
    p = erfc(abs(d) / math.sqrt(2.0))
    return {"test": "spectral", "n_bits_used": work,
             "peaks_below_threshold": n1, "expected": round(n0, 1),
             "d": round(d, 4), "p_value": round(p, 6),
             "passed": p >= P_VALUE_THRESHOLD}

def byte_chi_squared(data: bytes) -> dict:
    """
    Chi-squared uniformity over the 256 possible byte values.
    A healthy source is uniform; a stuck or biased source is not.
    """
    n = len(data)
    if n < 256:
        return {"test": "byte_chi_squared", "p_value": 1.0, "passed": True,
                 "skipped": True, "note": "need >= 256 bytes"}
    counts = Counter(data)
    expected = n / 256.0
    chi_sq = sum(((counts.get(b, 0) - expected) ** 2) / expected
                 for b in range(256))
    # 255 degrees of freedom
    p = igamc(255.0 / 2.0, chi_sq / 2.0)
    return {"test": "byte_chi_squared", "n_bytes": n,
             "chi_squared": round(chi_sq, 2), "dof": 255,
             "distinct_values": len(counts),
             "p_value": round(p, 6), "passed": p >= P_VALUE_THRESHOLD}

def shannon_entropy(data: bytes) -> dict:
    """Shannon entropy in bits per byte. Ideal is 8.0."""
    n = len(data)
    if n == 0:
        return {"test": "shannon", "bits_per_byte": 0.0, "passed": False}
    counts = Counter(data)
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return {"test": "shannon", "bits_per_byte": round(h, 4),
             "floor": SHANNON_FLOOR, "n_bytes": n,
             "passed": h >= SHANNON_FLOOR}

def repeated_block_check(data: bytes,
                          block: int = REPEAT_BLOCK_SIZE) -> dict:
    """
    A stuck or replaying entropy source emits identical blocks.
    Any repeat at this block size in a healthy stream is astronomically
    unlikely, so a single repeat is a definitive failure.
    """
    if len(data) < block * 2:
        return {"test": "repeated_block", "passed": True, "skipped": True}
    seen = set()
    repeats = 0
    for i in range(0, len(data) - block + 1, block):
        chunk = data[i:i + block]
        h = hashlib.sha256(chunk).hexdigest()
        if h in seen:
            repeats += 1
        seen.add(h)
    return {"test": "repeated_block", "block_bytes": block,
             "blocks_checked": len(seen) + repeats,
             "repeats": repeats, "passed": repeats == 0}

# ── Source handling ────────────────────────────────────────────────────
def read_entropy(n: int = SAMPLE_BYTES) -> dict:
    """Read from the best available entropy source."""
    for src in ENTROPY_SOURCES:
        if not os.path.exists(src):
            continue
        try:
            # Never block: /dev/random can stall on a starved pool.
            fd = os.open(src, os.O_RDONLY | os.O_NONBLOCK)
            try:
                data = os.read(fd, n)
            finally:
                os.close(fd)
            if data and len(data) >= n // 2:
                return {"source": src, "data": data, "bytes_read": len(data)}
        except (OSError, BlockingIOError):
            continue
    # Last resort — os.urandom always works
    try:
        return {"source": "os.urandom", "data": os.urandom(n),
                "bytes_read": n}
    except Exception as e:
        return {"error": str(e)}

def read_entropy_avail() -> int | None:
    """Kernel entropy pool depth in bits."""
    try:
        with open("/proc/sys/kernel/random/entropy_avail") as f:
            return int(f.read().strip())
    except Exception:
        return None

def hwrng_current() -> str | None:
    """Which hardware RNG the kernel has selected, if any."""
    try:
        with open("/sys/class/misc/hw_random/rng_current") as f:
            return f.read().strip()
    except Exception:
        return None

def hwrng_available() -> str | None:
    try:
        with open("/sys/class/misc/hw_random/rng_available") as f:
            return f.read().strip()
    except Exception:
        return None

# ── Analysis ───────────────────────────────────────────────────────────
def run_all_tests(data: bytes) -> list:
    bits = bytes_to_bits(data)
    return [
        monobit_test(bits),
        block_frequency_test(bits),
        runs_test(bits),
        spectral_test(bits),
        byte_chi_squared(data),
        shannon_entropy(data),
        repeated_block_check(data),
    ]

def analyse(results: list, source: str,
            entropy_avail: int | None) -> list:
    alerts = []
    failed = [r for r in results
              if not r.get("passed") and not r.get("skipped")]

    for r in failed:
        name = r.get("test")
        # Repeated blocks and Shannon collapse are unambiguous.
        if name == "repeated_block":
            alerts.append({
                "event":    "ENTROPY_SOURCE_STUCK",
                "severity": "CRITICAL",
                "source":   source,
                "repeats":  r.get("repeats"),
                "confidence": 0.98,
                "note": ("Identical blocks found in the entropy stream. The "
                         "source is stuck, replaying, or has failed while "
                         "still reporting success. Every key generated from "
                         "this pool must be treated as compromised"),
            })
        elif name == "shannon":
            alerts.append({
                "event":    "ENTROPY_SHANNON_COLLAPSE",
                "severity": "CRITICAL",
                "source":   source,
                "bits_per_byte": r.get("bits_per_byte"),
                "floor":    SHANNON_FLOOR,
                "confidence": 0.90,
                "note": ("Shannon entropy far below the 8.0 bits/byte ideal. "
                         "The stream carries substantially less randomness "
                         "than its length implies"),
            })
        else:
            alerts.append({
                "event":    "ENTROPY_BIAS_DETECTED",
                "severity": "CRITICAL",
                "source":   source,
                "failed_test": name,
                "p_value":  r.get("p_value"),
                "threshold": P_VALUE_THRESHOLD,
                "detail":   r,
                "confidence": 0.85,
                "note": (f"NIST SP 800-22 {name} test failed (p={r.get('p_value')} "
                         f"< {P_VALUE_THRESHOLD}). Statistical bias in the "
                         "entropy source undermines every key, nonce, and "
                         "randomized benchmarking sequence derived from it"),
            })

    # Multiple simultaneous failures is a stronger signal than any one
    if len(failed) >= 3:
        alerts.append({
            "event":    "ENTROPY_MULTI_TEST_FAILURE",
            "severity": "CRITICAL",
            "source":   source,
            "failed_count": len(failed),
            "failed_tests": [r.get("test") for r in failed],
            "confidence": 0.95,
            "note": ("Three or more independent statistical tests failed on "
                     "the same sample. This is not sampling noise — the "
                     "entropy source is compromised or has failed"),
        })

    # Pool starvation
    if entropy_avail is not None and entropy_avail < ENTROPY_AVAIL_FLOOR:
        alerts.append({
            "event":    "ENTROPY_POOL_STARVED",
            "severity": "WARN",
            "entropy_avail_bits": entropy_avail,
            "floor":    ENTROPY_AVAIL_FLOOR,
            "confidence": 0.75,
            "note": ("Kernel entropy pool depth is low. Key generation may "
                     "block, stalling the job pipeline, or fall back to a "
                     "weaker source"),
        })

    return alerts

def main():
    log = open(f"module59_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "59_entropy_qrng_health",
        "status": "FUNCTIONAL — no special hardware required",
        "standard": "NIST SP 800-22 Rev 1a (subset)",
        "tests": [
            "2.1 Frequency (Monobit)",
            "2.2 Frequency within a Block",
            "2.3 Runs",
            "2.6 Discrete Fourier Transform (Spectral)",
            "Byte-level chi-squared uniformity (255 dof)",
            "Shannon entropy per byte",
            "Repeated-block / stuck-source detection",
        ],
        "p_value_threshold": P_VALUE_THRESHOLD,
        "sample_bytes":      SAMPLE_BYTES,
        "sources_tried":     ENTROPY_SOURCES,
        "hwrng_current":     hwrng_current(),
        "hwrng_available":   hwrng_available(),
    })

    while True:
        sample = read_entropy(SAMPLE_BYTES)

        if "error" in sample:
            emit({"event": "ENTROPY_READ_ERROR", "detail": sample["error"]})
            time.sleep(POLL_INTERVAL)
            continue

        entropy_avail = read_entropy_avail()
        results = run_all_tests(sample["data"])
        passed  = sum(1 for r in results if r.get("passed"))

        emit({"event":  "ENTROPY_TEST_RUN",
              "source": sample["source"],
              "bytes":  sample["bytes_read"],
              "entropy_avail_bits": entropy_avail,
              "tests_passed": passed,
              "tests_total":  len(results),
              "results": results})

        alerts = analyse(results, sample["source"], entropy_avail)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event":  "ENTROPY_POOL_HEALTH_OK",
                  "source": sample["source"],
                  "tests_passed": f"{passed}/{len(results)}",
                  "entropy_avail_bits": entropy_avail})

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
