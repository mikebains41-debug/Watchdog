# Author: Manmohan (Mike) Bains -- Watchdog
"""detection/job_correlation.py -- turns a load-shaped alert into
explained/unexplained/unauthorized by checking the compute_apps list
telemetry already collects. Corroboration, never proof."""

_LOAD_SHAPED_TYPES = {
    'COVERT_MINING_PATTERN', 'GHOST_POWER', 'GHOST_POWER_PREDICTED',
    'INFERENCE_POWER_ANOMALY', 'SEQUENTIAL_VRAM_READ', 'PROMPT_INJECTION',
    'MINING', 'NVLINK_CONTENTION',
}


def _norm(pid_container):
    pids = []
    if not pid_container:
        return pids
    for item in pid_container:
        v = item.get('pid') if isinstance(item, dict) else item
        try:
            pids.append(int(v))
        except (TypeError, ValueError):
            continue
    return pids


def correlate_alert(alert, compute_apps, authorized_pids=None):
    atype = (alert or {}).get('type', '')

    if atype not in _LOAD_SHAPED_TYPES:
        return {'status': 'not_applicable', 'priority': 'info',
                'reason': f"{atype or 'alert'} is not a load-shaped signal; "
                          "process correlation does not apply.",
                'processes': []}

    if compute_apps is None:
        return {'status': 'unknown', 'priority': 'medium',
                'reason': "Process list was not collected for this sample, "
                          "so the anomaly can be neither explained nor ruled "
                          "suspicious. Treat as unresolved.",
                'processes': []}

    pids = _norm(compute_apps)

    if not pids:
        return {'status': 'unexplained', 'priority': 'high',
                'reason': "Load-shaped anomaly with NO visible GPU process. "
                          "Consistent with a hidden/unattended workload -- "
                          "worth investigating. Not proof: a privileged "
                          "process can evade the compute-apps list.",
                'processes': []}

    if authorized_pids is None:
        return {'status': 'explained', 'priority': 'low',
                'reason': f"Visible GPU process(es) {pids} were running during "
                          "the anomaly, which plausibly accounts for the load. "
                          "No allow-list supplied, so authorization was not "
                          "checked -- only presence.",
                'processes': pids}

    authorized = set(int(p) for p in authorized_pids)
    unknown = [p for p in pids if p not in authorized]
    if unknown:
        return {'status': 'unauthorized_process', 'priority': 'high',
                'reason': f"GPU process(es) {unknown} were running that are not "
                          "on the authorized list. Load-shaped anomaly plus an "
                          "unrecognized process -- investigate.",
                'processes': pids}

    return {'status': 'explained', 'priority': 'low',
            'reason': f"All GPU process(es) {pids} during the anomaly are on the "
                      "authorized list -- most consistent with a legitimate "
                      "workload change.",
            'processes': pids}


def _selftest():
    r = correlate_alert({'type': 'PACKAGE_CRACK_PREDICTED'}, [])
    assert r['status'] == 'not_applicable', r
    r = correlate_alert({'type': 'COVERT_MINING_PATTERN'}, None)
    assert r['status'] == 'unknown' and r['priority'] == 'medium', r
    r = correlate_alert({'type': 'COVERT_MINING_PATTERN'}, [])
    assert r['status'] == 'unexplained' and r['priority'] == 'high', r
    r = correlate_alert({'type': 'GHOST_POWER'}, [{'pid': 2222, 'used_memory': 2244.0}])
    assert r['status'] == 'explained' and r['priority'] == 'low', r
    r = correlate_alert({'type': 'GHOST_POWER'}, [{'pid': 2222, 'used_memory': 1.0}],
                        authorized_pids={2222})
    assert r['status'] == 'explained', r
    r = correlate_alert({'type': 'GHOST_POWER'}, [{'pid': 9999, 'used_memory': 1.0}],
                        authorized_pids={2222})
    assert r['status'] == 'unauthorized_process' and r['priority'] == 'high', r
    r = correlate_alert({'type': 'MINING'}, [1234])
    assert r['processes'] == [1234], r
    print("[selftest] PASS -- job_correlation distinguishes explained / "
          "unexplained / unauthorized / unknown, and never treats None as empty")


if __name__ == '__main__':
    _selftest()
