#!/usr/bin/env python3
"""
Tests for scripts/optical_transceiver_audit.py.

Fixtures reproduce real `ethtool -m` output shapes for SFP (SFF-8472), QSFP
(SFF-8636) and CMIS modules, plus the all-zeros read-failure pattern seen on
real hardware in the SONiC issue tracker. No hardware, no network, no root.
"""

import copy
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (os.path.join(HERE, "..", "scripts"), os.path.join(HERE, ".."), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import optical_transceiver_audit as ota  # noqa: E402

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", name, "" if cond else detail))


SFP = """\
\tIdentifier                                : 0x03 (SFP)
\tVendor name                               : FINISAR CORP.
\tVendor PN                                 : FTLX8571D3BCL
\tVendor SN                                 : ABC12345
\tVendor rev                                : A
\tDate code                                 : 170605
\tLaser bias current                        : 6.200 mA
\tLaser output power                        : 0.7461 mW / -1.27 dBm
\tReceiver signal average optical power     : 0.4630 mW / -3.34 dBm
\tModule temperature                        : 40.55 degrees C / 104.99 degrees F
\tModule voltage                            : 3.2823 V
\tLaser bias current high alarm             : Off
\tLaser bias current low alarm              : Off
\tLaser bias current high alarm threshold   : 12.000 mA
\tLaser rx power low warning threshold      : 0.0200 mW / -16.99 dBm
"""

SFP_ZERO = """\
\tIdentifier                                : 0x03 (SFP)
\tVendor name                               : Hisense
\tVendor PN                                 : LTF8507-PC03-HW1
\tVendor SN                                 : S50763H002Y
\tLaser bias current                        : 0.000 mA
\tLaser output power                        : 0.0000 mW / -inf dBm
\tReceiver signal average optical power     : 0.0000 mW / -inf dBm
\tModule temperature                        : 0.00 degrees C / 32.00 degrees F
\tModule voltage                            : 0.0000 V
"""

QSFP = """\
\tIdentifier                                : 0x11 (QSFP28)
\tVendor name                               : ACME OPTICS
\tVendor PN                                 : Q28-SR4
\tVendor SN                                 : QS9001
\tModule temperature                        : 38.10 degrees C / 100.58 degrees F
\tModule voltage                            : 3.3000 V
\tLaser tx bias current (Channel 1)         : 6.800 mA
\tLaser tx bias current (Channel 2)         : 6.900 mA
\tLaser tx bias current (Channel 3)         : 7.000 mA
\tLaser tx bias current (Channel 4)         : 6.700 mA
\tTransmit avg optical power (Channel 1)    : 0.8000 mW / -0.97 dBm
\tTransmit avg optical power (Channel 2)    : 0.8100 mW / -0.92 dBm
\tTransmit avg optical power (Channel 3)    : 0.7900 mW / -1.02 dBm
\tTransmit avg optical power (Channel 4)    : 0.8200 mW / -0.86 dBm
\tRcvr signal avg optical power(Channel 1)  : 0.6000 mW / -2.22 dBm
\tRcvr signal avg optical power(Channel 2)  : 0.6100 mW / -2.15 dBm
\tRcvr signal avg optical power(Channel 3)  : 0.5900 mW / -2.29 dBm
\tRcvr signal avg optical power(Channel 4)  : 0.6200 mW / -2.08 dBm
"""

CMIS = """\
\tIdentifier                                : 0x18 (QSFP-DD)
\tVendor name                               : ACME OPTICS
\tVendor PN                                 : DD-800G-DR8
\tVendor SN                                 : DD4242
\tActive firmware version                   : 2.7
\tInactive firmware version                 : 2.6
\tModule temperature                        : 45.00 degrees C / 113.00 degrees F
\tModule voltage                            : 3.3100 V
\tLaser tx bias current (Channel 1)         : 7.500 mA
\tTransmit avg optical power (Channel 1)    : 1.0000 mW / 0.00 dBm
\tRcvr signal avg optical power (Channel 1) : 0.8000 mW / -0.97 dBm
"""

CFG = dict(ota.DEFAULTS)


def with_rx(text, new_dbm):
    """Replace the SFP Rx line with a new dBm value."""
    mw = 10 ** (new_dbm / 10.0)
    out = []
    for line in text.splitlines():
        if line.strip().startswith("Receiver signal average optical power"):
            line = "\tReceiver signal average optical power     : %.4f mW / %.2f dBm" % (mw, new_dbm)
        out.append(line)
    return "\n".join(out) + "\n"


def with_bias(text, ma):
    return "\n".join(
        ("\tLaser bias current                        : %.3f mA" % ma)
        if l.strip().startswith("Laser bias current  ") or l.strip().startswith("Laser bias current :")
        or (l.strip().startswith("Laser bias current") and "alarm" not in l and "threshold" not in l)
        else l for l in text.splitlines()) + "\n"


def learn(text, n=6):
    st = {}
    for _ in range(n):
        _, st = ota.assess("eth0", ota.parse_ethtool_m(text), st, CFG)
    return st


def types(findings):
    return [f["type"] for f in findings]


def test_parse():
    p = ota.parse_ethtool_m(SFP)
    lane = p["lanes"].get(1, {})
    check("sfp: rx dBm parsed", abs(lane.get("rx_dbm", 99) - (-3.34)) < 1e-6, str(lane))
    check("sfp: tx dBm parsed", abs(lane.get("tx_dbm", 99) - (-1.27)) < 1e-6)
    check("sfp: bias mA parsed", abs(lane.get("bias_ma", 0) - 6.2) < 1e-6)
    check("sfp: temperature parsed", abs(p["module"]["temp_c"] - 40.55) < 1e-6)
    check("sfp: voltage parsed", abs(p["module"]["voltage_v"] - 3.2823) < 1e-6)
    check("sfp: serial parsed", p["identity"].get("sn") == "ABC12345")
    check("sfp: threshold lines NOT read as measurements",
          len(p["lanes"]) == 1 and abs(lane.get("bias_ma", 0) - 6.2) < 1e-6,
          "threshold 12.0 mA leaked into lane data")
    check("sfp: 'Off' alarms not reported as active", p["alarms"] == [])

    q = ota.parse_ethtool_m(QSFP)
    check("qsfp: four lanes parsed", sorted(q["lanes"]) == [1, 2, 3, 4], str(sorted(q["lanes"])))
    check("qsfp: channel 3 rx correct", abs(q["lanes"][3]["rx_dbm"] - (-2.29)) < 1e-6)

    c = ota.parse_ethtool_m(CMIS)
    check("cmis: firmware fields captured",
          c["firmware"].get("Active firmware version") == "2.7")

    z = ota.parse_ethtool_m(SFP_ZERO)
    check("zero: -inf parsed as -inf, no crash",
          math.isinf(z["lanes"][1]["rx_dbm"]) and z["lanes"][1]["rx_dbm"] < 0)

    check("garbage input: no crash, nothing parsed",
          ota.parse_ethtool_m("no colon here\n\n  :\n")["lanes"] == {})


def test_read_failure():
    f, _ = ota.assess("eth0", ota.parse_ethtool_m(SFP_ZERO), {}, CFG)
    check("all-zeros -> DOM_READ_FAILURE_SUSPECTED",
          "DOM_READ_FAILURE_SUSPECTED" in types(f), str(types(f)))
    check("all-zeros is NOT reported as loss of light",
          "RX_LOSS_OF_LIGHT" not in types(f))


def test_loss_of_light():
    st = learn(SFP)
    dark = SFP.replace("0.4630 mW / -3.34 dBm", "0.0000 mW / -inf dBm")
    f, _ = ota.assess("eth0", ota.parse_ethtool_m(dark), st, CFG)
    check("rx dark, own tx alive -> RX_LOSS_OF_LIGHT CRITICAL",
          any(x["type"] == "RX_LOSS_OF_LIGHT" and x["severity"] == "CRITICAL" for x in f),
          str(types(f)))


def test_rx_drop():
    st = learn(SFP)
    f, _ = ota.assess("eth0", ota.parse_ethtool_m(with_rx(SFP, -3.64)), copy.deepcopy(st), CFG)
    check("0.3 dB drop is below the bar -> silent", "RX_POWER_DROP" not in types(f), str(types(f)))

    f, _ = ota.assess("eth0", ota.parse_ethtool_m(with_rx(SFP, -4.84)), copy.deepcopy(st), CFG)
    drops = [x for x in f if x["type"] == "RX_POWER_DROP"]
    check("1.5 dB drop -> RX_POWER_DROP WARNING",
          drops and drops[0]["severity"] == "WARNING", str(types(f)))
    check("rx drop names dirty connector first",
          drops and "connector" in drops[0]["cannot_distinguish"][0])
    check("rx drop states the cladding-tap blind spot",
          drops and "0.04 dB" in drops[0]["detail"])
    check("rx drop takes no automated action",
          drops and drops[0]["automated_action"] == "none")

    f, _ = ota.assess("eth0", ota.parse_ethtool_m(with_rx(SFP, -7.0)), copy.deepcopy(st), CFG)
    check("3.7 dB drop -> CRITICAL",
          any(x["type"] == "RX_POWER_DROP" and x["severity"] == "CRITICAL" for x in f))


def test_no_detection_while_learning():
    f, _ = ota.assess("eth0", ota.parse_ethtool_m(with_rx(SFP, -9.0)), {}, CFG)
    check("first reading ever: no baseline, no RX_POWER_DROP",
          "RX_POWER_DROP" not in types(f))


def test_swap():
    st = learn(SFP)
    other = with_rx(SFP.replace("ABC12345", "ZZZ99999"), -8.0)
    f, st2 = ota.assess("eth0", ota.parse_ethtool_m(other), st, CFG)
    check("serial change -> MODULE_IDENTITY_CHANGE", "MODULE_IDENTITY_CHANGE" in types(f))
    check("swap does NOT raise a false RX_POWER_DROP vs the old module",
          "RX_POWER_DROP" not in types(f), str(types(f)))
    check("baseline reset to the new serial", st2.get("sn") == "ZZZ99999")


def test_firmware():
    st = learn(CMIS)
    upd = CMIS.replace("Active firmware version                   : 2.7",
                       "Active firmware version                   : 2.8")
    f, _ = ota.assess("eth0", ota.parse_ethtool_m(upd), st, CFG)
    check("same serial, new firmware -> FIRMWARE_CHANGE_SAME_SERIAL",
          "FIRMWARE_CHANGE_SAME_SERIAL" in types(f), str(types(f)))
    f, _ = ota.assess("eth0", ota.parse_ethtool_m(CMIS), learn(CMIS), CFG)
    check("unchanged firmware -> silent", "FIRMWARE_CHANGE_SAME_SERIAL" not in types(f))


def test_bias():
    st = learn(SFP)
    f, _ = ota.assess("eth0", ota.parse_ethtool_m(with_bias(SFP, 7.2)), st, CFG)
    check("bias +16% -> LASER_BIAS_DRIFT", "LASER_BIAS_DRIFT" in types(f), str(types(f)))


def test_alarm():
    hot = SFP.replace("Laser bias current high alarm             : Off",
                      "Laser bias current high alarm             : On")
    f, _ = ota.assess("eth0", ota.parse_ethtool_m(hot), {}, CFG)
    check("module's own alarm 'On' -> MODULE_ALARM", "MODULE_ALARM" in types(f))


def test_fec():
    s1 = "     rx_fec_corrected_blocks: 100\n     rx_fec_uncorrectable_blocks: 0\n"
    s2 = "     rx_fec_corrected_blocks: 150\n     rx_fec_uncorrectable_blocks: 0\n"
    s3 = "     rx_fec_corrected_blocks: 150\n     rx_fec_uncorrectable_blocks: 3\n"
    check("fec parse", ota.parse_fec(s1) == {"corrected": 100, "uncorrectable": 0},
          str(ota.parse_fec(s1)))
    p = ota.parse_ethtool_m(SFP)
    _, st = ota.assess("eth0", p, {}, CFG, ota.parse_fec(s1))
    f, st = ota.assess("eth0", p, st, CFG, ota.parse_fec(s2))
    check("fec corrected rising -> INFO", "FEC_CORRECTED_ACTIVITY" in types(f))
    f, st = ota.assess("eth0", p, st, CFG, ota.parse_fec(s3))
    check("fec uncorrectable rising -> WARNING", "FEC_UNCORRECTABLE_INCREASE" in types(f))
    check("no fec counters -> None, not zero", ota.parse_fec("tx_packets: 5\n") is None)


def test_every_finding_is_honest():
    st = learn(SFP)
    f, _ = ota.assess("eth0", ota.parse_ethtool_m(with_rx(SFP, -7.0)), st, CFG)
    f2, _ = ota.assess("eth0", ota.parse_ethtool_m(SFP_ZERO), {}, CFG)
    allf = f + f2
    check("every finding lists what it cannot distinguish",
          all(x["cannot_distinguish"] for x in allf))
    check("no finding takes an automated action",
          all(x["automated_action"] == "none" for x in allf))


def test_environment():
    real_run = ota.run
    try:
        ota.run = lambda cmd, timeout=5: (127, "", "not installed")

        class A: pass
        a = A()
        a.state, a.fixture, a.iface, a.no_fec, a.dry_run = "/tmp/_ota_t.json", None, None, True, True
        rep = ota.audit(a, CFG)
        check("no ethtool -> ETHTOOL_NOT_INSTALLED, nothing claimed",
              rep["status"] == "ETHTOOL_NOT_INSTALLED" and not rep["findings"])

        ota.run = lambda cmd, timeout=5: (0, "ethtool version 6.1", "") if "--version" in cmd \
            else (1, "", "Operation not supported")
        rep = ota.audit(a, CFG)
        check("no optical modules -> NO_OPTICAL_MODULES_FOUND with explanation",
              rep["status"] == "NO_OPTICAL_MODULES_FOUND" and rep["notes"])
    finally:
        ota.run = real_run


def main():
    print("=" * 64)
    print("OPTICAL TRANSCEIVER AUDIT — TESTS")
    print("=" * 64)
    for fn in (test_parse, test_read_failure, test_loss_of_light, test_rx_drop,
               test_no_detection_while_learning, test_swap, test_firmware,
               test_bias, test_alarm, test_fec, test_every_finding_is_honest,
               test_environment):
        print("\n--- %s ---" % fn.__name__)
        fn()
    print("\n" + "=" * 64)
    print("PASSED: %d FAILED: %d" % (len(PASSED), len(FAILED)))
    for x in FAILED:
        print("  FAILED: %s" % x)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
