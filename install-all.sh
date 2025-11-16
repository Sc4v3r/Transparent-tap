#!/bin/bash
#
# NAC-Tap - Complete Installation Script
# Installs dependencies, sets up Wi-Fi AP, and provides next steps
# Run as root: sudo bash install-all.sh
#

set -e

echo "========================================"
echo "NAC-Tap - Complete Installation"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo bash install-all.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "This script will:"
echo "  1. Install system dependencies"
echo "  2. (Optional) Setup Wi-Fi management AP"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 1
fi

echo ""
echo "========================================"
echo "Step 1: Installing Dependencies"
echo "========================================"
echo ""

# Run dependency installation
if [ -f "$SCRIPT_DIR/install-dependencies.sh" ]; then
    bash "$SCRIPT_DIR/install-dependencies.sh"
else
    echo "❌ install-dependencies.sh not found!"
    exit 1
fi

echo ""
echo "========================================"
echo "Step 2: Wi-Fi Management AP Setup"
echo "========================================"
echo ""
echo "Do you want to setup a Wi-Fi management AP on wlan0?"
echo "This allows you to connect wirelessly to manage the device."
echo ""
read -p "Setup Wi-Fi AP? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f "$SCRIPT_DIR/setup-wifi-ap.sh" ]; then
        bash "$SCRIPT_DIR/setup-wifi-ap.sh"
    else
        echo "❌ setup-wifi-ap.sh not found!"
        echo "You can run it manually later: sudo bash setup-wifi-ap.sh"
    fi
else
    echo "Skipping Wi-Fi AP setup. You can run it later:"
    echo "  sudo bash setup-wifi-ap.sh"
fi

echo ""
echo "========================================"
echo "✅ Installation Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Start NAC-Tap:"
echo "   sudo python3 nac-tap.py"
echo ""
echo "2. Access web interface:"
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "   Via Wi-Fi: http://172.31.250.1:8080"
fi
echo "   Via localhost: http://localhost:8080"
echo ""
echo "3. For detailed usage instructions:"
echo "   See SETUP.md and QUICKSTART.md"
echo ""
echo "4. Optional - Install PCredz for credential extraction:"
echo "   sudo git clone https://github.com/lgandx/PCredz.git /opt/PCredz"
echo "   cd /opt/PCredz && sudo pip3 install -r requirements.txt"
echo ""


