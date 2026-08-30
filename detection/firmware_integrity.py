# Author: Manmohan (Mike) Bains -- Watchdog
"""
detection/firmware_integrity.py

Tracks this GPU's VBIOS version (a real, standard nvidia-smi field:
`nvidia-smi --query-gpu=vbios_version --format=csv`) and flags any
change from the first value observed.

SCOPE, stated precisely: this is the realistic slice of "firmware
integrity checking" buildable from what a rented GPU instance actually
exposes. It is NOT the broader BMC/EEPROM firmware verification
described in some vendor security products -- that needs IPMI or
Redfish access to the physical host's baseboard management
controller, which a tenant on rented cloud GPU infrastructure does not
have. This checks one specific, real, accessible field: whether the
VBIOS version string this GPU reports has changed since Watchdog first
observed it.

WHY THIS MATTERS, stated honestly: this has no "known-good baseline"
to compare against -- no external database of legitimate VBIOS
versions was available to build this against. It can only detect a
CHANGE from whatever was first observed, the same limitation
BootAttestation already has for driver/UUID hashes elsewhere in this
project. A GPU that already had a tampered VBIOS before Watchdog's
first sample would never be flagged -- this catches new changes during
a monitored session, not pre-existing compromise.
"""
import subprocess
from datetime import datetime


class VBIOSIntegrityDetector:
    """Detects unauthorized VBIOS or firmware modifications on the GPU.

    Research basis (2026): "A Security Look at NVIDIA GPU Confidential
    Computing" (arXiv 2507.02770, April 2026) documents that adversaries
    may flash the GPU VBIOS or update firmware via in-band tools (nvTrust)
    or out-of-band interfaces (BMC), reassign GPUs between CVMs, or detach
    and reattach GPUs from PCIe buses. GPU-CC enforces a secure boot chain
    (CEC EROT -> SEC2) requiring cryptographic signatures, but this chain
    is only validated at boot -- runtime VBIOS state requires active
    monitoring to detect post-boot tampering.

    Supply chain compromise targeting GPU firmware is documented as an
    emerging threat in AI infrastructure security (Introl, December 2025).
    """
    def __init__(self):
        self.known_vbios = {}

    def update(self, row):
        """
        Adapter matching every other engine's standard update(row)
        interface, so this can sit in the same self.engines list as
        everything else. Delegates to check(), which does the real
        work and predates this wrapper.
        """
        return self.check(gpu_index=int(row.get('index', 0)))

    def check(self, gpu_index=0):
        version = self._query_vbios(gpu_index)
        if version is None:
            return None
        if gpu_index not in self.known_vbios:
            self.known_vbios[gpu_index] = version
            return None
        if self.known_vbios[gpu_index] != version:
            old = self.known_vbios[gpu_index]
            self.known_vbios[gpu_index] = version
            return {
                'type': 'VBIOS_VERSION_CHANGE',
                'severity': 'CRITICAL',
                'gpu': gpu_index,
                'previous_vbios': old,
                'current_vbios': version,
                'timestamp': datetime.now().isoformat(),
                'message': (f"VBIOS version changed from {old} to {version} "
                            f"during a monitored session -- possible firmware "
                            f"update, possible tampering. No known-good "
                            f"baseline exists to distinguish the two; this "
                            f"only detects that a change occurred, not "
                            f"whether it was authorized."),
            }
        return None

    def _query_vbios(self, gpu_index):
        try:
            r = subprocess.run(
                ['nvidia-smi', f'--id={gpu_index}',
                 '--query-gpu=vbios_version', '--format=csv,noheader'],
                capture_output=True, text=True, timeout=5
            )
            out = r.stdout.strip()
            if not out or out == '[N/A]':
                return None
            return out
        except Exception:
            return None
