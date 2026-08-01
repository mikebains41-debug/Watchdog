# Author: Manmohan (Mike) Bains -- Watchdog
"""intelligence/swarm/arch_detect.py -- fixes the B200-logged-as-H200
mislabel. Derives arch from the real GPU name string and supplies an
idle floor OBSERVED in this repo's own captures, not a spec sheet
number."""

_IDLE_FLOOR_W = {
    'B200': 182.1,
    'H200': 80.36,
}


def normalize_arch(gpu_name):
    if not gpu_name:
        return 'UNKNOWN'
    s = str(gpu_name).upper()
    for token in ('B200', 'B100', 'H200', 'H100', 'A100', 'L40S',
                  'L40', 'A10G', 'A10', 'V100', 'T4'):
        if token in s:
            return token
    return 'UNKNOWN'


def idle_floor_for(arch, default=None):
    return _IDLE_FLOOR_W.get(arch, default)


def resolve(gpu_name, fallback_idle_floor_w=None):
    arch = normalize_arch(gpu_name)
    return arch, idle_floor_for(arch, default=fallback_idle_floor_w)


def _selftest():
    assert normalize_arch('0, NVIDIA B200') == 'B200'
    assert normalize_arch('NVIDIA B200') == 'B200'
    assert normalize_arch('NVIDIA H200') == 'H200'
    assert normalize_arch('NVIDIA H100 80GB HBM3') == 'H100'
    assert normalize_arch('') == 'UNKNOWN'
    assert normalize_arch(None) == 'UNKNOWN'
    assert idle_floor_for('B200') == 182.1
    assert idle_floor_for('H200') == 80.36
    assert idle_floor_for('UNKNOWN') is None
    assert idle_floor_for('UNKNOWN', default=100.0) == 100.0
    arch, floor = resolve('0, NVIDIA B200')
    assert arch == 'B200' and floor == 182.1, (arch, floor)
    print("[selftest] PASS -- B200 is detected as B200 with a 182.1W observed "
          "idle floor, not H200/80.36W")


if __name__ == '__main__':
    _selftest()
