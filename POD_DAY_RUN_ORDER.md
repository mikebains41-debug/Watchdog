# Vast.ai pod day — run order

2× H100 (check the listing says NVLink/NVSwitch, not plain PCIe). ~$1.73/hr.
Total paid time across everything: 3–4 hours. Copy every output file off the
pod before releasing it.

---

## Rule 0 — the first command of every rental

```bash
python3 handover_capture.py
```

Before anything else, every time, on every machine — including cheap single-GPU
rentals. It takes 30 seconds and it is the only moment the previous tenant's
state is visible. Afterwards you are measuring your own.

**Boundary, deliberate:** leftovers are recorded as path, size, owner and time.
Contents are never opened, copied or hashed. The metadata proves the leak;
reading the data would be the thing being reported.

**Sample size is the whole point.** One dirty machine proves nothing. Rent, capture,
release, repeat — 20 short rentals is worth far more than one long one, and costs
a couple of dollars at per-second billing.

---

## Order on the 2× H100 pod

| # | Test | Script | Time |
|---|---|---|---|
| 1 | Handover capture (tests 1–7) | `handover_capture.py` | 30 s |
| 2 | NVLink units + cross-GPU residual (8, 9) | `nvlink_units_test.py` | ~1 h |
| 3 | H100 loaded-idle ghost — confirm or refute | below | ~30 min |
| 4 | Today's ghost + chip-health checks on real GPUs (11) | below | ~1 h |
| 5 | Neighbour visibility (10) — shared machine only | below | ~1 h |

---

## Test 3 — H100 loaded idle (settles a contradiction)

The whitepaper calls H100 a clean negative control for ghost power. The
2026-09-21 `gpu-core-private` run on H100 measured a loaded model sitting idle at
117.13 W against a 70.64 W cold floor — 46.49 W recoverable, 39.7%, at 0%
utilisation across all 325 samples. Both cannot be true.

Method: cold floor with no context → load a model, leave it idle → release the
context → re-read. Compare with the published H100 numbers.

**Done when:** the whitepaper's H100 claim is either confirmed or corrected in
writing. H100 is the most widely deployed datacenter GPU — this one matters.

---

## Test 4 — confirm what was only simulated

Everything from 2026-09-21 was tested on synthetic data. On a real 2-GPU pod:

- **Loaded-idle ghost (`GHOST_POWER_RESIDENT`)** — run normal bursty inference
  for 20 min with both GPUs holding a model: must stay silent. Then pin one GPU's
  clocks high with no work: must fire.
- **Fleet health** — is one GPU's temperature-vs-power curve stable enough on real
  hardware for the 8 °C degradation threshold to mean anything? Record both cards'
  curves for 20 min under varied load. This decides whether the threshold holds
  or needs changing.
- **Thermal cycling** — count real heat/cool cycles during ordinary bursty
  serving. Compare with the synthetic estimate of ~86 cycles/hour.
- **Power periodicity** — bursty serving must not read as a rhythm on real
  telemetry, as it no longer does on synthetic.

**Done when:** each synthetic result is confirmed or corrected against real numbers.

---

## Test 5 — neighbour visibility (shared machine only)

Vast.ai often rents a slice of a machine, so other tenants are genuinely present —
something a dedicated pod cannot offer. Record your own telemetry for 30 min while
running nothing: power floor, temperature, clocks, achieved sample rate. Look for
variation that cannot come from your own idle instance.

Establishes whether a neighbour's activity is visible in your own readings. State
plainly what it cannot show: which neighbour, or what they were running.

---

## Not on this pod

- Memory-clock lever (`-lgc/-lmc/-pl`) — refused on rented containers, needs bare metal
- MIG behaviour — needs bare metal
- Remediation end-to-end — needs a real cluster or scheduler, not a pod
