#!/usr/bin/env python3
"""
Watchdog — Unified Runner
Executes all security modules, collects JSON events, generates dashboard.html.
"""
import glob, json, os, subprocess, sys
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.join(BASE, "modules")
OUTPUT_JSONL = os.path.join(BASE, "watchdog_output.jsonl")
DASHBOARD_HTML = os.path.join(BASE, "dashboard.html")

HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Watchdog Dashboard</title>
<style>
body{{font-family:monospace;background:#0a0a0a;color:#0f0;padding:16px;margin:0}}
h1{{color:#0f0;border-bottom:2px solid #0f0;font-size:1.2em}}
.module{{background:#111;margin:8px 0;padding:10px;border-left:4px solid #444;border-radius:4px}}
.CRITICAL{{border-left-color:#f00;color:#f00}}
.WARN{{border-left-color:#ff0;color:#ff0}}
.OK{{border-left-color:#0f0}}
.timestamp{{color:#888;font-size:0.75em}}
pre{{margin:4px 0 0;white-space:pre-wrap;word-break:break-all;font-size:0.85em}}
.summary{{background:#1a1a1a;padding:12px;border-radius:4px;margin-bottom:16px}}
</style></head><body>
<h1>Watchdog Quantum Security Suite</h1>
<div class="summary">
  <b>Generated:</b> {timestamp}<br>
  <b>Modules:</b> {module_count} | <b>Events:</b> {event_count} | <b>Alerts:</b> {alert_count}
</div>
<div id="content">{content}</div>
</body></html>"""


def run_module(path: str) -> list:
    name = os.path.basename(path)
    results = []
    try:
        proc = subprocess.run(
            [sys.executable, path],
            capture_output=True,
            text=True,
            timeout=30,
            stdin=subprocess.DEVNULL
        )
        for line in proc.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                data = {"event": "RAW_OUTPUT", "raw": line}
            data["_module"] = name
            data["_collected_at"] = datetime.now(timezone.utc).isoformat()
            results.append(data)
        if proc.returncode != 0 and proc.stderr:
            results.append({
                "_module": name, "event": "MODULE_ERROR",
                "severity": "WARN",
                "stderr": proc.stderr[-400:],
                "_collected_at": datetime.now(timezone.utc).isoformat()
            })
    except subprocess.TimeoutExpired:
        results.append({
            "_module": name,
            "event": "MODULE_TIMEOUT",
            "severity": "WARN",
            "error": "Timed out after 30s",
            "_collected_at": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        results.append({
            "_module": name, "event": "RUNNER_ERROR",
            "severity": "CRITICAL",
            "error": str(e),
            "_collected_at": datetime.now(timezone.utc).isoformat()
        })
    return results


def generate_dashboard(events: list):
    rows = []
    alert_count = 0
    for ev in events:
        evt = ev.get("event", "UNKNOWN")
        sev = ev.get("severity", "")
        css = "OK"
        if "CRITICAL" in str(sev) or any(x in evt for x in ["DETECTED", "TAMPER", "DEGRADATION", "DRAIN"]):
            css = "CRITICAL"
            alert_count += 1
        elif "WARN" in str(sev) or any(x in evt for x in ["SPIKE", "FAILED", "TIMEOUT"]):
            css = "WARN"
            alert_count += 1
        rows.append(
            '<div class="module ' + css + '">'
            '<div class="timestamp">' + ev.get("_collected_at","") + ' | ' + ev.get("_module","") + ' | ' + evt + '</div>'
            '<pre>' + json.dumps(ev, indent=2) + '</pre></div>'
        )

    html = HTML_TEMPLATE.format(
        timestamp=datetime.now(timezone.utc).isoformat(),
        module_count=len(set(e["_module"] for e in events)),
        event_count=len(events),
        alert_count=alert_count,
        content="\n".join(rows) if rows else "<p>No events captured.</p>"
    )
    with open(DASHBOARD_HTML, "w") as f:
        f.write(html)
    return DASHBOARD_HTML


def main():
    modules = sorted(glob.glob(os.path.join(MODULES_DIR, "module*.py")))
    all_events = []
    for mod in modules:
        if os.path.basename(mod).startswith("test_"):
            continue
        print("Running " + os.path.basename(mod), file=sys.stderr)
        all_events.extend(run_module(mod))

    with open(OUTPUT_JSONL, "w") as f:
        for ev in all_events:
            f.write(json.dumps(ev) + "\n")

    dash = generate_dashboard(all_events)

    counts = {}
    for ev in all_events:
        counts[ev.get("event", "UNKNOWN")] = counts.get(ev.get("event", "UNKNOWN"), 0) + 1

    print("\n=== Watchdog Run Summary ===")
    print("Modules: " + str(len(set(e["_module"] for e in all_events))))
    print("Events:  " + str(len(all_events)))
    print("Alerts:  " + str(sum(1 for e in all_events if e.get("severity") in ("CRITICAL","WARN"))))
    print("JSONL:   " + OUTPUT_JSONL)
    print("Dashboard: " + dash)
    print("\nTop events:")
    for ev, c in sorted(counts.items(), key=lambda x: -x[1])[:8]:
        print("  " + ev + ": " + str(c))


if __name__ == "__main__":
    main()
