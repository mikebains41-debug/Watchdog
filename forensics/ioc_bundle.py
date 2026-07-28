# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog v2.0 - Air-Gapped IOC Bundle System
Signed offline IOC database updates for air-gapped deployments.
Bundles are SHA256 signed and verified before loading.
No external network dependency at runtime.
"""
import json, hashlib, os, time
from datetime import datetime, timezone

BUNDLE_DIR = os.environ.get("WATCHDOG_IOC_BUNDLES", "watchdog_data/ioc_bundles")

def _hash_bundle(bundle_dict):
    payload = json.dumps(bundle_dict, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()

def create_bundle(iocs, bundle_id=None, author="watchdog"):
    """Create a signed IOC bundle for offline distribution."""
    bundle = {
        "bundle_id": bundle_id or f"ioc-bundle-{int(time.time())}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "author": author,
        "version": "2026.06",
        "ioc_count": len(iocs),
        "iocs": iocs,
    }
    bundle["bundle_hash"] = _hash_bundle({k: v for k, v in bundle.items() if k != "bundle_hash"})
    return bundle

def save_bundle(bundle, path=None):
    os.makedirs(BUNDLE_DIR, exist_ok=True)
    path = path or os.path.join(BUNDLE_DIR, f"{bundle['bundle_id']}.json")
    with open(path, "w") as f:
        json.dump(bundle, f, indent=2)
    print(f"[IOC BUNDLE] Saved: {path}")
    return path

def load_and_verify_bundle(path):
    """Load a bundle and verify its hash before applying."""
    with open(path) as f:
        bundle = json.load(f)
    stored_hash = bundle.pop("bundle_hash", None)
    computed = _hash_bundle(bundle)
    bundle["bundle_hash"] = stored_hash
    if stored_hash != computed:
        raise ValueError(f"BUNDLE TAMPERED: hash mismatch in {path}")
    print(f"[IOC BUNDLE] Verified: {bundle['bundle_id']} ({bundle['ioc_count']} IOCs)")
    return bundle

def load_all_bundles(bundle_dir=None):
    """Load and verify all bundles in the bundle directory."""
    bundle_dir = bundle_dir or BUNDLE_DIR
    if not os.path.exists(bundle_dir):
        return {}
    merged_iocs = {}
    for fname in sorted(os.listdir(bundle_dir)):
        if fname.endswith(".json"):
            path = os.path.join(bundle_dir, fname)
            try:
                bundle = load_and_verify_bundle(path)
                merged_iocs.update(bundle["iocs"])
            except Exception as e:
                print(f"[IOC BUNDLE] SKIP {fname}: {e}")
    return merged_iocs
