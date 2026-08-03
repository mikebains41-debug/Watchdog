#!/usr/bin/env python3
"""M_quantum_prometheus_exporter.py - emits cryo efficiency as Prometheus metrics.
STATUS: AWAITING_HARDWARE_TEST. Values modeled, not live. Serves :9093/metrics.
Ref: ~6.25 W/qubit (arXiv:2304.14344)."""

from http.server import BaseHTTPRequestHandler, HTTPServer

PUBLISHED_W_PER_QUBIT = 6.25
ROOM_TEMP_K = 300.0
MIXING_K = 0.015
PORT = 9093

def carnot_amp(t=MIXING_K): return (ROOM_TEMP_K - t) / t

def wpq(q, w): return w / q if q else 0.0
def carnot_pct(w, cold):
    ideal = cold * carnot_amp()
    return (ideal / w * 100) if w else 0.0
def score(q, w, cold):
    v = wpq(q, w)
    r = v / PUBLISHED_W_PER_QUBIT if v else 0
    wq = max(0, min(100, 100 / r)) if r > 0 else 0
    return int(round(0.6 * wq + 0.4 * min(100, carnot_pct(w, cold))))

FLEET = [
    ("fridge-01", 4158, 26000.0, 1.0),
    ("fridge-02", 4158, 28000.0, 1.0),
    ("fridge-03", 4158, 45000.0, 0.8),
]

def render():
    L = []
    L.append("# TYPE quantum_exporter_status gauge")
    L.append("quantum_exporter_status 1")
    L.append("# TYPE quantum_fridge_watts_per_qubit gauge")
    for u,q,w,c in FLEET:
        L.append('quantum_fridge_watts_per_qubit{unit="%s"} %.3f' % (u, wpq(q,w)))
    L.append("# TYPE quantum_fridge_carnot_efficiency_pct gauge")
    for u,q,w,c in FLEET:
        L.append('quantum_fridge_carnot_efficiency_pct{unit="%s"} %.4f' % (u, carnot_pct(w,c)))
    L.append("# TYPE quantum_fridge_efficiency_score gauge")
    for u,q,w,c in FLEET:
        L.append('quantum_fridge_efficiency_score{unit="%s"} %d' % (u, score(q,w,c)))
    tq = sum(f[1] for f in FLEET)
    tw = sum(f[2] for f in FLEET)
    fs = int(round(sum(score(f[1],f[2],f[3])*f[1] for f in FLEET)/tq)) if tq else 0
    L.append("# TYPE quantum_fleet_efficiency_score gauge")
    L.append("quantum_fleet_efficiency_score %d" % fs)
    L.append("# TYPE quantum_fleet_watts_per_qubit gauge")
    L.append("quantum_fleet_watts_per_qubit %.3f" % (tw/tq if tq else 0))
    return "\n".join(L) + "\n"

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404); self.end_headers(); return
        b = render().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass

if __name__ == "__main__":
    print(render())
    print("# Serving :%d/metrics (Ctrl+C to stop). STATUS: AWAITING_HARDWARE_TEST" % PORT)
    try:
        HTTPServer(("0.0.0.0", PORT), H).serve_forever()
    except KeyboardInterrupt:
        print("\n# Stopped.")
