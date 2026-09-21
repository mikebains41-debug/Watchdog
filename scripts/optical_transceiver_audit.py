#!/usr/bin/env python3
"""
Watchdog — Optical Transceiver Audit (OPT category)
Author: Manmohan (Mike) Bains / GPU Optimizer Inc.

READ-ONLY. Runs `ethtool -m` (and optionally `ethtool -S`) on physical
interfaces, parses digital optical monitoring for SFP / QSFP / CMIS modules,
learns a per-module baseline, and reports changes.

It never writes to a module, never disables a port, never resets anything.
Every finding carries what it CANNOT distinguish, because an Rx power drop
looks the same whether it is a dirty connector, a bent fibre, or a tap.

WHY BASELINES AND NOT THRESHOLDS
Typical DOM accuracy is +/-3 C, +/-2 to +/-3 dB on optical power, +/-10% on
laser bias. A 1 dB change is inside the error bar of one absolute reading. A
single module's readings are far more repeatable than they are accurate, so
every check here compares a module against its own learned history.

WHAT IT CANNOT DO
A skilled cladding-coupling tap can change received power by 0.04 dB or less.
No power-based method detects that. OTDR and polarization monitoring are the
tools for that class.

USAGE
  sudo python3 scripts/optical_transceiver_audit.py
  sudo python3 scripts/optical_transceiver_audit.py --json out.json
  python3 scripts/optical_transceiver_audit.py --fixture saved_ethtool_m.txt --iface eth0
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

DEFAULT_STATE = os.path.expanduser("~/.watchdog/optical_baseline.json")
SKIP_PREFIXES = ("lo", "veth", "docker", "br-", "virbr", "tun", "tap",
                 "wg", "cni", "flannel", "cali", "vxlan", "dummy", "bond")

DEFAULTS = {
    "min_samples": 5,        # readings before a baseline is trusted
    "keep_samples": 20,      # early readings kept for the median
    "rx_drop_warn_db": 1.0,
    "rx_drop_crit_db": 3.0,
    "tx_drop_warn_db": 1.0,
    "bias_rise_pct": 10.0,
    "temp_rise_c": 10.0,
}

RX_DROP_LIMITS = [
    "dirty or damaged connector end-face (the most common real cause)",
    "fibre bend or crushed patch cable",
    "patch or path change",
    "far-end transmitter weakening",
    "inline passive TAP or bend coupler (roughly 1 dB or more)",
]
TAP_BLINDSPOT = ("A skilled cladding-coupling tap can change received power "
                 "by 0.04 dB or less and is NOT detectable by this or any "
                 "power-based method. Use OTDR / polarization monitoring.")


# --------------------------------------------------------------------------
# Running ethtool, safely
# --------------------------------------------------------------------------

def run(cmd, timeout=5):
    """Never hangs, never raises. Returns (code, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", "not installed"
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as e:                       # pragma: no cover
        return 1, "", "%s: %s" % (type(e).__name__, e)


def physical_interfaces():
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []
    return [n for n in names if not n.startswith(SKIP_PREFIXES)]


# --------------------------------------------------------------------------
# Parsing ethtool -m
# --------------------------------------------------------------------------

_CHAN = re.compile(r"\(\s*chan(?:nel)?\s*(\d+)\s*\)", re.I)
_DBM = re.compile(r"(-?\d+(?:\.\d+)?|-inf)\s*dBm", re.I)
_MW = re.compile(r"(\d+(?:\.\d+)?)\s*mW", re.I)
_TEMP = re.compile(r"(-?\d+(?:\.\d+)?)\s*degrees\s*C", re.I)
_VOLT = re.compile(r"(\d+(?:\.\d+)?)\s*V\b")
_MA = re.compile(r"(\d+(?:\.\d+)?)\s*mA", re.I)


def _power_dbm(val):
    m = _DBM.search(val)
    if m:
        return float("-inf") if m.group(1).lower() == "-inf" else float(m.group(1))
    m = _MW.search(val)
    if m:
        mw = float(m.group(1))
        return float("-inf") if mw <= 0 else 10.0 * math.log10(mw)
    return None


def _num(rx, val):
    m = rx.search(val)
    return float(m.group(1)) if m else None


def parse_ethtool_m(text):
    """Tolerant parser. Unknown lines are ignored, never fatal."""
    out = {"identity": {}, "module": {}, "lanes": {}, "firmware": {},
           "alarms": [], "thresholds": {}, "parsed_lines": 0}

    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        k = key.lower()
        if not k:
            continue
        out["parsed_lines"] += 1

        # Thresholds first: "Laser bias current high alarm threshold" contains
        # "bias current" and must NOT be read as a lane measurement.
        if "threshold" in k:
            out["thresholds"][key] = val
            continue

        if k in ("vendor name",):
            out["identity"]["vendor"] = val
        elif k in ("vendor pn",):
            out["identity"]["pn"] = val
        elif k in ("vendor sn",):
            out["identity"]["sn"] = val
        elif k in ("vendor rev",):
            out["identity"]["rev"] = val
        elif k.startswith("date code"):
            out["identity"]["date_code"] = val
        elif k == "identifier":
            out["identity"]["identifier"] = val
        elif "firmware" in k:
            out["firmware"][key] = val
        elif ("alarm" in k or "warning" in k) and val.lower() in ("on", "yes", "1", "true"):
            out["alarms"].append(key)
        elif ("alarm" in k or "warning" in k):
            continue
        elif "module temperature" in k:
            out["module"]["temp_c"] = _num(_TEMP, val)
        elif "module voltage" in k or k == "vcc":
            out["module"]["voltage_v"] = _num(_VOLT, val)
        else:
            m = _CHAN.search(key)
            lane = int(m.group(1)) if m else 1
            metric = None
            if "bias" in k and "current" in k:
                metric, value = "bias_ma", _num(_MA, val)
            elif ("receiver signal" in k or "rcvr signal" in k
                  or "rx power" in k or "rx optical power" in k):
                metric, value = "rx_dbm", _power_dbm(val)
            elif ("output power" in k or "transmit avg optical power" in k
                  or "tx power" in k or "tx optical power" in k):
                metric, value = "tx_dbm", _power_dbm(val)
            if metric and value is not None:
                out["lanes"].setdefault(lane, {})[metric] = value

    return out


def looks_like_optical_module(parsed):
    return bool(parsed["lanes"]) or bool(parsed["identity"].get("sn"))


# --------------------------------------------------------------------------
# FEC counters (best-effort; names vary by driver)
# --------------------------------------------------------------------------

_FEC_CORR = re.compile(r"fec.*corr(?!.*uncorr)", re.I)
_FEC_UNCORR = re.compile(r"fec.*uncorr", re.I)


def parse_fec(text):
    corr = uncorr = 0
    found = False
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        try:
            n = int(val.strip())
        except ValueError:
            continue
        if _FEC_UNCORR.search(key):
            uncorr += n
            found = True
        elif _FEC_CORR.search(key):
            corr += n
            found = True
    return {"corrected": corr, "uncorrectable": uncorr} if found else None


# --------------------------------------------------------------------------
# Baseline store
# --------------------------------------------------------------------------

def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, path)


def _median(xs):
    xs = sorted(x for x in xs if x is not None and not math.isinf(x))
    if not xs:
        return None
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2.0


def _finding(kind, severity, iface, detail, cannot_distinguish=None,
             recommend=None, lane=None, extra=None):
    f = {"type": kind, "severity": severity, "iface": iface,
         "detail": detail,
         "cannot_distinguish": cannot_distinguish or [],
         "recommend": recommend or "log only",
         "automated_action": "none"}
    if lane is not None:
        f["lane"] = lane
    if extra:
        f.update(extra)
    return f


# --------------------------------------------------------------------------
# The checks
# --------------------------------------------------------------------------

def assess(iface, parsed, port_state, cfg, fec=None):
    """Returns (findings, updated_port_state). Pure function: no I/O."""
    findings = []
    ident = parsed["identity"]
    sn = ident.get("sn") or ""
    now = datetime.now(timezone.utc).isoformat()

    # --- DOM read failure vs dark fibre ---------------------------------
    lanes = parsed["lanes"]
    temp = parsed["module"].get("temp_c")
    volt = parsed["module"].get("voltage_v")
    all_power_dead = lanes and all(
        (v.get("rx_dbm") is None or math.isinf(v.get("rx_dbm", 0)))
        and (v.get("tx_dbm") is None or math.isinf(v.get("tx_dbm", 0)))
        for v in lanes.values())
    everything_zero = all_power_dead and (temp in (None, 0.0)) and (volt in (None, 0.0))
    if everything_zero:
        findings.append(_finding(
            "DOM_READ_FAILURE_SUSPECTED", "WARNING", iface,
            "Every diagnostic field reads zero at once (power -inf, 0 C, 0 V). "
            "That pattern means the diagnostics did not read, not that the "
            "link is dark. Link state is unknown from DOM.",
            ["diagnostics read failure", "module without DOM support",
             "unpowered or half-seated module"],
            "Check link state from the NIC, reseat the module, re-read."))
        return findings, port_state      # nothing below is meaningful

    # --- identity / firmware -------------------------------------------
    if not any(ident.get(k) for k in ("vendor", "pn", "sn")):
        findings.append(_finding(
            "BLANK_IDENTITY", "INFO", iface,
            "Vendor, part number and serial are all empty.",
            ["generic or unprogrammed module", "EEPROM read issue"],
            "Note it. EEPROM contents can be programmed to anything, so "
            "identity alone cannot prove or disprove authenticity."))

    fw = parsed["firmware"]
    prev_sn = port_state.get("sn")
    if prev_sn and sn and prev_sn != sn:
        findings.append(_finding(
            "MODULE_IDENTITY_CHANGE", "INFO", iface,
            "Serial changed %s -> %s: the module on this port was swapped. "
            "Baseline reset so the new module is not compared with the old one."
            % (prev_sn, sn),
            ["planned replacement", "unplanned swap"],
            "Confirm against the change record."))
        port_state = {}
    elif prev_sn and sn == prev_sn and fw and port_state.get("firmware") \
            and port_state["firmware"] != fw:
        findings.append(_finding(
            "FIRMWARE_CHANGE_SAME_SERIAL", "WARNING", iface,
            "Firmware changed on the same module (serial %s): %s -> %s. "
            "CMIS allows in-service firmware updates without removing the module."
            % (sn, port_state["firmware"], fw),
            ["authorised maintenance update", "unauthorised update"],
            "Confirm the update against the change record and the vendor's "
            "published image."))

    port_state["sn"] = sn
    port_state["identity"] = ident
    if fw:
        port_state["firmware"] = fw
    port_state["last_seen"] = now

    # --- module's own alarms -------------------------------------------
    for a in parsed["alarms"]:
        findings.append(_finding(
            "MODULE_ALARM", "WARNING", iface,
            "Module reports its own threshold alarm/warning: %s" % a,
            ["genuine out-of-range condition", "vendor thresholds set tight"],
            "Read the module thresholds alongside the current value."))

    # --- per-lane baseline checks ---------------------------------------
    hist = port_state.setdefault("history", {})
    for lane, vals in sorted(lanes.items()):
        lk = str(lane)
        h = hist.setdefault(lk, {"rx_dbm": [], "tx_dbm": [], "bias_ma": []})
        rx, tx, bias = vals.get("rx_dbm"), vals.get("tx_dbm"), vals.get("bias_ma")

        if rx is not None and math.isinf(rx) and tx is not None and not math.isinf(tx):
            findings.append(_finding(
                "RX_LOSS_OF_LIGHT", "CRITICAL", iface,
                "No received light while this module's own transmitter is "
                "working. The fault is on the fibre or at the far end.",
                ["fibre unplugged or cut", "far-end module down",
                 "far-end port disabled", "inline device removed or failed"],
                "Check the far end, then the span.", lane=lane))
            continue

        base_rx = _median(h["rx_dbm"]) if len(h["rx_dbm"]) >= cfg["min_samples"] else None
        base_tx = _median(h["tx_dbm"]) if len(h["tx_dbm"]) >= cfg["min_samples"] else None
        base_b = _median(h["bias_ma"]) if len(h["bias_ma"]) >= cfg["min_samples"] else None

        if base_rx is not None and rx is not None and not math.isinf(rx):
            drop = base_rx - rx
            tx_stable = (base_tx is None or tx is None or math.isinf(tx)
                         or (base_tx - tx) < cfg["tx_drop_warn_db"])
            if drop >= cfg["rx_drop_warn_db"]:
                sev = "CRITICAL" if drop >= cfg["rx_drop_crit_db"] else "WARNING"
                findings.append(_finding(
                    "RX_POWER_DROP", sev, iface,
                    "Received power %.2f dB below this module's baseline "
                    "(%.2f -> %.2f dBm)%s. %s"
                    % (drop, base_rx, rx,
                       "; own transmitter steady, so the loss is on the "
                       "link or far end" if tx_stable else "",
                       TAP_BLINDSPOT),
                    RX_DROP_LIMITS,
                    "Inspect and clean both connector end-faces first. If it "
                    "persists, OTDR the span.",
                    lane=lane, extra={"drop_db": round(drop, 2)}))

        if base_tx is not None and tx is not None and not math.isinf(tx):
            tdrop = base_tx - tx
            if tdrop >= cfg["tx_drop_warn_db"]:
                findings.append(_finding(
                    "TX_POWER_DECAY", "WARNING", iface,
                    "This module's own transmit power is %.2f dB below its "
                    "baseline. The module, not the fibre." % tdrop,
                    ["laser aging", "thermal issue", "module fault"],
                    "Plan replacement; watch bias current.", lane=lane))

        if base_b and bias is not None:
            rise = 100.0 * (bias - base_b) / base_b
            if rise >= cfg["bias_rise_pct"]:
                findings.append(_finding(
                    "LASER_BIAS_DRIFT", "WARNING", iface,
                    "Laser bias %.1f%% above baseline (%.2f -> %.2f mA). The "
                    "laser is working harder for the same output." % (rise, base_b, bias),
                    ["laser aging", "rising temperature",
                     "degraded thermal interface", "bad production batch"],
                    "Trend it. Sustained rise often precedes failure.",
                    lane=lane))

        # Learn only from early, healthy-looking readings, so a slow fault
        # cannot drag the baseline along with it.
        for key, v in (("rx_dbm", rx), ("tx_dbm", tx), ("bias_ma", bias)):
            if v is not None and not math.isinf(v) and len(h[key]) < cfg["keep_samples"]:
                h[key].append(v)

    # --- module temperature ---------------------------------------------
    th = port_state.setdefault("temp_hist", [])
    if temp is not None:
        base_t = _median(th) if len(th) >= cfg["min_samples"] else None
        if base_t is not None and temp - base_t >= cfg["temp_rise_c"]:
            findings.append(_finding(
                "MODULE_THERMAL_RISE", "WARNING", iface,
                "Module %.1f C above its baseline (%.1f -> %.1f C)."
                % (temp - base_t, base_t, temp),
                ["airflow change", "neighbouring load", "module fault"],
                "Check airflow and the cage."))
        if len(th) < cfg["keep_samples"]:
            th.append(temp)

    # --- FEC trend -------------------------------------------------------
    if fec:
        prev = port_state.get("fec")
        if prev:
            du = fec["uncorrectable"] - prev.get("uncorrectable", 0)
            dc = fec["corrected"] - prev.get("corrected", 0)
            if du > 0:
                findings.append(_finding(
                    "FEC_UNCORRECTABLE_INCREASE", "WARNING", iface,
                    "%d new uncorrectable FEC blocks since last read. Data "
                    "was lost on this link." % du,
                    ["marginal optics", "dirty connector", "EMI", "counter reset"],
                    "Correlate with Rx power and flaps."))
            elif dc > 0:
                findings.append(_finding(
                    "FEC_CORRECTED_ACTIVITY", "INFO", iface,
                    "%d corrected FEC blocks since last read. The link is "
                    "working to stay clean — normal at low rates, a precursor "
                    "if it climbs." % dc,
                    ["normal operating margin", "early degradation"],
                    "Trend it."))
        port_state["fec"] = fec

    return findings, port_state


# --------------------------------------------------------------------------

def audit(args, cfg):
    report = {"timestamp": datetime.now(timezone.utc).isoformat(),
              "status": None, "ports": {}, "findings": [], "notes": []}
    state = load_state(args.state)

    if args.fixture:
        with open(args.fixture) as f:
            text = f.read()
        targets = [(args.iface or "fixture0", text, None)]
    else:
        code, _, err = run(["ethtool", "--version"])
        if code == 127:
            report["status"] = "ETHTOOL_NOT_INSTALLED"
            report["notes"].append("Install ethtool (apt install ethtool). Nothing was checked.")
            return report
        targets = []
        denied = 0
        for iface in physical_interfaces():
            code, out, err = run(["ethtool", "-m", iface])
            if code != 0:
                if "permission" in err.lower() or "not permitted" in err.lower():
                    denied += 1
                continue
            fec_txt = ""
            if not args.no_fec:
                c2, fec_txt, _ = run(["ethtool", "-S", iface])
                if c2 != 0:
                    fec_txt = ""
            targets.append((iface, out, fec_txt))
        if denied:
            report["notes"].append("%d interface(s) refused: run with sudo "
                                   "(ethtool -m needs CAP_NET_ADMIN)." % denied)

    any_optical = False
    for iface, text, fec_txt in targets:
        parsed = parse_ethtool_m(text)
        if not looks_like_optical_module(parsed):
            continue
        any_optical = True
        fec = parse_fec(fec_txt) if fec_txt else None
        findings, state[iface] = assess(iface, parsed, state.get(iface, {}), cfg, fec)
        report["ports"][iface] = {"identity": parsed["identity"],
                                  "lanes": {str(k): v for k, v in parsed["lanes"].items()},
                                  "module": parsed["module"],
                                  "firmware": parsed["firmware"]}
        report["findings"].extend(findings)

    if not any_optical:
        report["status"] = "NO_OPTICAL_MODULES_FOUND"
        report["notes"].append(
            "No pluggable optical modules with readable diagnostics. Expected "
            "on a phone, laptop, cloud VM or container: virtual NICs have no "
            "transceivers, and hosts usually hide the physical NIC. Needs bare "
            "metal with SFP/QSFP/OSFP optics.")
    else:
        report["status"] = "OK" if not report["findings"] else "FINDINGS"
        if not args.dry_run:
            save_state(args.state, state)
    report["limits"] = [
        "DOM accuracy is roughly +/-2-3 dB and +/-3 C, so only change against a "
        "module's own baseline is meaningful; the first %d readings per module "
        "are learning, not detection." % cfg["min_samples"],
        TAP_BLINDSPOT,
        "EEPROM identity cannot prove a module is genuine.",
        "Read-only. No port, module or link is ever changed by this tool.",
    ]
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only optical transceiver audit")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--fixture", help="parse a saved `ethtool -m` output instead of live")
    ap.add_argument("--iface", help="interface name to use with --fixture")
    ap.add_argument("--no-fec", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="do not update the baseline file")
    ap.add_argument("--json", help="write the full report to this path")
    ap.add_argument("--fail-on-critical", action="store_true")
    for k, v in DEFAULTS.items():
        ap.add_argument("--" + k.replace("_", "-"), type=type(v), default=v)
    a = ap.parse_args(argv)
    cfg = {k: getattr(a, k) for k in DEFAULTS}

    rep = audit(a, cfg)
    print("OPTICAL TRANSCEIVER AUDIT  %s" % rep["timestamp"])
    print("status: %s   ports: %d   findings: %d"
          % (rep["status"], len(rep["ports"]), len(rep["findings"])))
    for n in rep["notes"]:
        print("  note: %s" % n)
    for f in rep["findings"]:
        lane = " lane %s" % f["lane"] if "lane" in f else ""
        print("\n[%s] %s  %s%s" % (f["severity"], f["type"], f["iface"], lane))
        print("  %s" % f["detail"])
        if f["cannot_distinguish"]:
            print("  cannot distinguish: %s" % "; ".join(f["cannot_distinguish"]))
        print("  recommend: %s   (automated action: none)" % f["recommend"])
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rep, fh, indent=2)
        print("\nwritten: %s" % a.json)
    if a.fail_on_critical and any(f["severity"] == "CRITICAL" for f in rep["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
