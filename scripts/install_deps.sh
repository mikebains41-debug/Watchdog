#!/bin/bash
set -e
echo "Installing dependencies for Watchdog Quantum..."

# Detect OS
if [ -n "$TERMUX_VERSION" ]; then
    echo "Termux detected."
    pkg update -y
    pkg install -y python rust python-scipy rust-bin || true
elif [ -f /etc/debian_version ]; then
    echo "Debian/Ubuntu detected."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv build-essential rustc cargo
else
    echo "Non-Debian/Termux system. Please install Python 3.10+ and Rust manually."
fi

# Python packages
pip3 install --upgrade pip
pip3 install -r requirements.txt || {
    echo "Some pip packages failed – you may need to install them manually."
    echo "Try: pip install qiskit qiskit-ibm-runtime dwave-ocean-sdk amazon-braket-sdk"
}

echo "✅ Dependencies installed."
