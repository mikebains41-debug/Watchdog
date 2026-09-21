"""
Watchdog -- node-level GPU health: dead, overheating, or wearing out.
Author: Manmohan (Mike) Bains / GPU Optimizer Inc.

Deliberately sees ALL GPUs on a node (NOT wrapped in PerGPU): for health,
the neighbours are the reference. Three checks:

1. GPU_MISSING / GPU_UNRESPONSIVE -- a GPU stops reporting while its
   neighbours keep going, or reports blank readings for several samples.
2. GPU_THERMAL_EXTREME -- sustained temperature at warning / critical
   level. Defaults 85 C / 92 C are NOT any GPU's official limits: set them
   from the model's documented slowdown temperature.
3. GPU_COOLING_DEGRADED -- a GPU now runs hotter AT THE SAME POWER than it
   used to. Two traps are handled:
     * slot position: GPUs near a chassis's hot end always run warmer, so
       each GPU is compared with ITS OWN learned temperature-vs-power curve,
       not with its neighbours' absolute temperatures;
     * room temperature: if the room warms, every GPU runs hotter, so the
       median drift across the node is subtracted -- only a GPU drifting on
       its own counts. Needs >= 3 GPUs reporting; with fewer, alerts say the
       room-wide change could not be separated.

Counts SAMPLES, not wall-clock time.

LIMITS, stated: a GPU degraded from its first samples learns that state as
normal. If every GPU vanishes at once (driver crash), no rows arrive and
this detector cannot fire -- the sampler must catch that. Thresholds are
defaults, not validated against real failure data.
"""


def _num(row, key):
    v = row.get(key) if isinstance(row, dict) else None
    try:
        return None if v is None or v == "" else float(v)
    except (TypeError, ValueError):
        return None


class FleetHealthDetector(object):
    def __init__(self, missing_polls=5, unresponsive_samples=3,
                 warn_c=85.0, crit_c=92.0, warn_sustain=10, crit_sustain=3, hysteresis_c=3.0,
                 learn_samples=300, ema_alpha=0.1, degrade_c=8.0, degrade_sustain=60,
                 refire_samples=600, min_peers=3):
        self.missing_polls = missing_polls
        self.unresponsive_samples = unresponsive_samples
        self.warn_c, self.crit_c = warn_c, crit_c
        self.warn_sustain, self.crit_sustain = warn_sustain, crit_sustain
        self.hysteresis_c = hysteresis_c
        self.learn_samples = learn_samples
        self.ema_alpha = ema_alpha
        self.degrade_c = degrade_c
        self.degrade_sustain = degrade_sustain
        self.refire_samples = refire_samples
        self.min_peers = min_peers
        self.n = 0
        self.gpus = {}
        self._pending = []

    @staticmethod
    def _key(row):
        for f in ("uuid", "index"):
            k = row.get(f)
            if k not in (None, ""):
                return str(k)
        return "default"

    def _state(self, k, row):
        st = self.gpus.get(k)
        if st is None:
            st = dict(index=row.get("index"), last_seen=self.n, missing=False, nulls=0,
                      unresp=False, warn_run=0, crit_run=0, warn_on=False, crit_on=False,
                      ema=None, learn=[], fit=None, res=None, res_n=None,
                      deg_run=0, since_deg=None)
            self.gpus[k] = st
        return st

    def _alert(self, kind, sev, st, message, **extra):
        a = dict(type=kind, severity=sev, gpu=st["index"], message=message, automated_action="none")
        a.update(extra)
        self._pending.append(a)

    def update(self, row):
        self.n += 1
        k = self._key(row)
        st = self._state(k, row)
        st["last_seen"] = self.n
        if st["missing"]:
            st["missing"] = False
        n_gpu = max(1, len(self.gpus))

        # 1a. GPUs that stopped reporting while this one keeps going
        for k2, s2 in self.gpus.items():
            if k2 != k and not s2["missing"] and self.n - s2["last_seen"] > self.missing_polls * n_gpu:
                s2["missing"] = True
                self._alert("GPU_MISSING", "CRITICAL", s2,
                            "GPU%s has stopped reporting while other GPUs on this node continue "
                            "(%d polls). Consistent with a dead GPU, a GPU that fell off the bus, "
                            "or a driver fault on this card." % (s2["index"], self.missing_polls),
                            cannot_distinguish=["hardware failure", "fell off the PCIe bus",
                                                "per-GPU driver or sampling fault"])

        temp, power = _num(row, "temperature.gpu"), _num(row, "power.draw")

        # 1b. blank readings
        if temp is None and power is None:
            st["nulls"] += 1
            if st["nulls"] >= self.unresponsive_samples and not st["unresp"]:
                st["unresp"] = True
                self._alert("GPU_UNRESPONSIVE", "CRITICAL", st,
                            "GPU%s is reporting blank temperature and power for %d samples in a row."
                            % (st["index"], st["nulls"]),
                            cannot_distinguish=["GPU lost / hardware fault", "driver fault",
                                                "telemetry path fault"])
        else:
            st["nulls"], st["unresp"] = 0, False

        if temp is not None:
            self._check_heat(st, temp)
        if temp is not None and power is not None:
            self._check_wear(st, temp, power, n_gpu)
        return self._pending.pop(0) if self._pending else None

    def _check_heat(self, st, temp):
        st["crit_run"] = st["crit_run"] + 1 if temp >= self.crit_c else 0
        st["warn_run"] = st["warn_run"] + 1 if temp >= self.warn_c else 0
        if st["crit_on"] and temp < self.crit_c - self.hysteresis_c:
            st["crit_on"] = False
        if st["warn_on"] and temp < self.warn_c - self.hysteresis_c:
            st["warn_on"] = False
        if st["crit_run"] >= self.crit_sustain and not st["crit_on"]:
            st["crit_on"] = st["warn_on"] = True
            self._alert("GPU_THERMAL_EXTREME", "CRITICAL", st,
                        "GPU%s at %.0f C for %d samples -- at or above the critical setting (%.0f C)."
                        % (st["index"], temp, st["crit_run"], self.crit_c),
                        temp_c=temp, threshold_c=self.crit_c,
                        cannot_distinguish=["cooling failure", "blocked airflow", "sensor fault"])
        elif st["warn_run"] >= self.warn_sustain and not st["warn_on"]:
            st["warn_on"] = True
            self._alert("GPU_THERMAL_EXTREME", "WARNING", st,
                        "GPU%s at %.0f C for %d samples -- above the warning setting (%.0f C)."
                        % (st["index"], temp, st["warn_run"], self.warn_c),
                        temp_c=temp, threshold_c=self.warn_c,
                        cannot_distinguish=["heavy sustained load", "cooling degradation",
                                            "high room temperature"])

    def _check_wear(self, st, temp, power, n_gpu):
        st["ema"] = power if st["ema"] is None else st["ema"] + self.ema_alpha * (power - st["ema"])
        if st["since_deg"] is not None:
            st["since_deg"] += 1
        if st["fit"] is None:
            st["learn"].append((st["ema"], temp))
            if len(st["learn"]) >= self.learn_samples:
                xs = [x for x, _ in st["learn"]]
                ys = [y for _, y in st["learn"]]
                mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
                vx = sum((x - mx) ** 2 for x in xs) / len(xs)
                b = (sum((x - mx) * (y - my) for x, y in st["learn"]) / len(xs) / vx) if vx > 25 else 0.0
                st["fit"] = (my - b * mx, b)
                st["learn"] = []
            return
        a, b = st["fit"]
        st["res"], st["res_n"] = temp - (a + b * st["ema"]), self.n
        fresh = [s["res"] for s in self.gpus.values()
                 if s["res"] is not None and self.n - s["res_n"] <= 2 * n_gpu]
        carve = len(fresh) >= self.min_peers
        med = sorted(fresh)[len(fresh) // 2] if carve else 0.0
        excess = st["res"] - med
        st["deg_run"] = st["deg_run"] + 1 if excess >= self.degrade_c else 0
        if st["deg_run"] >= self.degrade_sustain and (st["since_deg"] is None or st["since_deg"] >= self.refire_samples):
            st["since_deg"] = 0
            self._alert("GPU_COOLING_DEGRADED", "WARNING", st,
                        "GPU%s runs %.1f C hotter at the same power than its own learned history, "
                        "sustained %d samples%s." % (
                            st["index"], excess, st["deg_run"],
                            ", beyond any room-wide change (%d GPUs compared)" % len(fresh) if carve
                            else " -- too few GPUs reporting to rule out a room-wide change"),
                        excess_c=round(excess, 2), room_wide_drift_c=round(med, 2),
                        room_wide_carve_out=carve,
                        cannot_distinguish=["dried thermal paste or pads", "failing fan or pump",
                                            "blocked airflow at this slot", "temperature sensor fault"])
