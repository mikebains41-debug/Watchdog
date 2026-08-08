import os
from .base import QuantumProvider, CalibrationSnapshot, JobRecord, QueueStatus
try:
    from .ibm_provider import IBMQuantumProvider
except ImportError:
    IBMQuantumProvider = None
try:
    from .dwave_provider import DWaveProvider
except ImportError:
    DWaveProvider = None
try:
    from .braket_provider import BraketProvider
except ImportError:
    BraketProvider = None
try:
    from .openquantum_provider import OpenQuantumProvider
except ImportError:
    OpenQuantumProvider = None
from .mock_provider import MockQuantumProvider

__all__ = [
    "QuantumProvider", "CalibrationSnapshot", "JobRecord", "QueueStatus",
    "IBMQuantumProvider", "DWaveProvider", "BraketProvider", "OpenQuantumProvider",
    "MockQuantumProvider", "get_provider"
]

def get_provider():
    ibm_token = os.getenv("IBM_QUANTUM_TOKEN")
    dwave_token = os.getenv("DWAVE_API_TOKEN")
    braket_region = os.getenv("AWS_DEFAULT_REGION")
    oq_id = os.getenv("OPENQUANTUM_CLIENT_ID")
    oq_secret = os.getenv("OPENQUANTUM_CLIENT_SECRET")

    if ibm_token and IBMQuantumProvider is not None:
        try:
            return IBMQuantumProvider(token=ibm_token)
        except Exception as e:
            print(f"[get_provider] IBM init failed: {e}")

    if dwave_token and DWaveProvider is not None:
        try:
            return DWaveProvider(token=dwave_token)
        except Exception as e:
            print(f"[get_provider] D-Wave init failed: {e}")

    if braket_region and BraketProvider is not None:
        try:
            return BraketProvider(region=braket_region)
        except Exception as e:
            print(f"[get_provider] Braket init failed: {e}")

    if oq_id and oq_secret and OpenQuantumProvider is not None:
        try:
            return OpenQuantumProvider(client_id=oq_id, client_secret=oq_secret)
        except Exception as e:
            print(f"[get_provider] OpenQuantum init failed: {e}")

    print("[get_provider] No credentials — falling back to Mock")
    return MockQuantumProvider()
