#!/bin/bash
#
# Install systemd service for NAC-Tap
# Makes nac-tap.py start automatically on boot
#
# Usage: sudo bash install-service.sh
#

set -e

echo "========================================"
echo "NAC-Tap - Systemd Service Installation"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo bash install-service.sh"
    exit 1
fi

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for service file in current directory or systemd subdirectory
if [ -f "$SCRIPT_DIR/systemd/nac-tap.service" ]; then
    SERVICE_FILE="$SCRIPT_DIR/systemd/nac-tap.service"
elif [ -f "$SCRIPT_DIR/nac-tap.service" ]; then
    SERVICE_FILE="$SCRIPT_DIR/nac-tap.service"
else
    echo "❌ Service file not found. Expected:"
    echo "   $SCRIPT_DIR/systemd/nac-tap.service"
    echo "   or"
    echo "   $SCRIPT_DIR/nac-tap.service"
    exit 1
fi

# Check if nac-tap.py exists
NAC_TAP_SCRIPT="$SCRIPT_DIR/nac-tap.py"
if [ ! -f "$NAC_TAP_SCRIPT" ]; then
    echo "❌ nac-tap.py not found: $NAC_TAP_SCRIPT"
    exit 1
fi

echo "=== Creating service file with correct paths ==="
# Create a temporary service file with correct paths
TEMP_SERVICE="/tmp/nac-tap.service.tmp"
cp "$SERVICE_FILE" "$TEMP_SERVICE"

# Update paths in temporary service file
sed -i "s|WorkingDirectory=.*|WorkingDirectory=$SCRIPT_DIR|g" "$TEMP_SERVICE"
sed -i "s|ExecStart=.*|ExecStart=/usr/bin/python3 $NAC_TAP_SCRIPT|g" "$TEMP_SERVICE"

SERVICE_FILE="$TEMP_SERVICE"

echo "=== Installing systemd service ==="
# Copy service file to systemd directory
cp "$SERVICE_FILE" /etc/systemd/system/nac-tap.service

# Reload systemd
systemctl daemon-reload

echo ""
echo "=== Enabling services ==="
# Ensure hostapd and dnsmasq are enabled (for AP)
systemctl enable hostapd 2>/dev/null || echo "⚠️  hostapd not found - make sure AP is set up first"
systemctl enable dnsmasq 2>/dev/null || echo "⚠️  dnsmasq not found - make sure AP is set up first"

# Enable nac-tap service
systemctl enable nac-tap.service

echo ""
echo "========================================"
echo "✅ Service Installation Complete!"
echo "========================================"
echo ""
echo "Service Status:"
echo "  AP (hostapd):    $(systemctl is-enabled hostapd 2>/dev/null || echo 'not configured')"
echo "  DHCP (dnsmasq):  $(systemctl is-enabled dnsmasq 2>/dev/null || echo 'not configured')"
echo "  NAC-Tap:         $(systemctl is-enabled nac-tap.service)"
echo ""
echo "To start NAC-Tap now:"
echo "  sudo systemctl start nac-tap.service"
echo ""
echo "To check status:"
echo "  sudo systemctl status nac-tap.service"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u nac-tap.service -f"
echo ""
echo "To stop NAC-Tap:"
echo "  sudo systemctl stop nac-tap.service"
echo ""
echo "To disable auto-start:"
echo "  sudo systemctl disable nac-tap.service"
echo ""
echo "⚠️  IMPORTANT: Make sure the AP is set up first:"
echo "  sudo bash setup-wifi-ap.sh"
echo ""

