#!/bin/bash
set -e
echo "Setting up Watchdog Quantum..."
./scripts/install_deps.sh
./scripts/start_monitor.sh
echo "✅ Setup complete. Run 'make status' to check."
