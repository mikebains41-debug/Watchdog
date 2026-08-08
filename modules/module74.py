#!/usr/bin/env python3
import json, os, sys
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from quantum_providers import get_provider

def emit(event_type, details):
    print(json.dumps({
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **details
    }))

def main():
    provider = get_provider()
    emit("MODULE_DISABLED", {
        "module": os.path.basename(__file__),
        "reason": "Fast stub – no hang",
        "provider": provider.provider_name
    })

if __name__ == "__main__":
    main()
