#!/bin/bash
#
# Wi-Fi Access Point Setup Script for NAC Tap Device
# Creates a management AP on wlan0 for remote access
# Tested on Ubuntu/Debian ARM (NanoPi, Raspberry Pi, etc.)
#
# Usage: sudo bash setup-wifi-ap.sh
#

set -e

echo "========================================"
echo "NAC Tap - Wi-Fi AP Setup"
echo "Management Interface Configuration"
echo "========================================"
echo ""
echo "NOTE: This script should be run AFTER installing dependencies:"
echo "      sudo bash install-dependencies.sh"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo bash setup-wifi-ap.sh"
    exit 1
fi

echo "=== Installing required packages ==="
apt update
apt install -y hostapd dnsmasq

echo ""
echo "=== Stopping services temporarily ==="
systemctl stop hostapd dnsmasq 2>/dev/null || true
systemctl disable hostapd dnsmasq 2>/dev/null || true
systemctl mask hostapd 2>/dev/null || true

echo ""
# Prompt for SSID and Password
read -p "Enter the SSID for your AP: " AP_SSID
while true; do
    read -s -p "Enter the WPA2 password (min 8 chars): " AP_PASS
    echo
    read -s -p "Confirm the WPA2 password: " AP_PASS2
    echo
    if [ "$AP_PASS" = "$AP_PASS2" ] && [ ${#AP_PASS} -ge 8 ]; then
        break
    else
        echo "❌ Passwords do not match or are too short, try again."
    fi
done

echo ""
echo "=== Configuring static IP for wlan0 ==="
rm -f /etc/netplan/99-wlan-ap.yaml 2>/dev/null || true

cat > /etc/systemd/network/25-wlan0.network <<EOF
[Match]
Name=wlan0

[Network]
Address=172.31.250.1/24
IPForward=yes
EOF

systemctl restart systemd-networkd

# Create systemd service to bring up wlan0 on boot and ensure IP is assigned
cat > /etc/systemd/system/wlan0-up.service <<'EOF'
[Unit]
Description=Bring up wlan0 interface for AP and assign IP
Before=hostapd.service dnsmasq.service
After=network-online.target systemd-networkd.service

[Service]
Type=oneshot
RemainAfterExit=yes
# Wait for interface to exist, then bring it up
ExecStart=/bin/bash -c 'for i in {1..30}; do if [ -d /sys/class/net/wlan0 ]; then break; fi; sleep 1; done; ip link set wlan0 up || true'
ExecStartPost=/bin/sleep 3
# Wait for systemd-networkd to assign IP (it may take a moment)
ExecStartPost=/bin/bash -c 'for i in {1..20}; do if ip addr show wlan0 | grep -q "172.31.250.1"; then exit 0; fi; sleep 1; done; echo "Warning: wlan0 IP not assigned yet"'
# If IP still not assigned, assign it manually
ExecStartPost=/bin/bash -c 'if ! ip addr show wlan0 | grep -q "172.31.250.1"; then ip addr add 172.31.250.1/24 dev wlan0 || true; fi'
ExecStartPost=/bin/sleep 1
# Verify interface is up
ExecStartPost=/bin/bash -c 'ip link show wlan0 | grep -q "state UP" || (echo "Warning: wlan0 may not be UP" && exit 0)'

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wlan0-up.service
systemctl start wlan0-up.service

# Also bring it up now
ip link set wlan0 up
sleep 2

echo ""
echo "=== Configuring dnsmasq for DHCP ==="
systemctl stop dnsmasq 2>/dev/null || true
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null || true

cat > /etc/dnsmasq.conf <<EOF
# NAC Tap Management Interface DHCP
port=0
interface=wlan0
dhcp-range=172.31.250.50,172.31.250.150,12h
dhcp-option=3,172.31.250.1
dhcp-option=6,172.31.250.1
EOF

# Make dnsmasq wait for wlan0 to have an IP
mkdir -p /etc/systemd/system/dnsmasq.service.d
cat > /etc/systemd/system/dnsmasq.service.d/wait-for-wlan0-ip.conf <<'EOF'
[Unit]
After=wlan0-up.service
Requires=wlan0-up.service

[Service]
# Wait a bit more to ensure wlan0 has IP
ExecStartPre=/bin/bash -c 'for i in {1..10}; do if ip addr show wlan0 | grep -q "172.31.250.1"; then exit 0; fi; sleep 1; done; echo "Warning: wlan0 IP check timeout"'
ExecStartPre=/bin/sleep 1
EOF

systemctl daemon-reload
systemctl start dnsmasq
systemctl enable dnsmasq

echo ""
echo "=== Configuring hostapd ==="
cat > /etc/hostapd/hostapd.conf <<EOF
# NAC Tap Management AP Configuration
# Configured for macOS compatibility (2.4GHz only)
interface=wlan0
ssid=${AP_SSID}
hw_mode=g
channel=6
# Force 2.4GHz band (g = 2.4GHz, a = 5GHz)
# macOS compatibility: use 2.4GHz to avoid connection issues
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=${AP_PASS}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
# Additional macOS compatibility settings
ieee80211n=1
ht_capab=[HT20][SHORT-GI-20][SHORT-GI-40]
# Disable 5GHz features to ensure 2.4GHz only
country_code=US
EOF

# Configure hostapd to use our config file
cat > /etc/default/hostapd <<EOF
# Configuration file for hostapd
DAEMON_CONF="/etc/hostapd/hostapd.conf"

# Additional options (leave empty if not needed)
DAEMON_OPTS=""
EOF

# Enable hostapd service (persistent across reboots)
# Make sure it starts after wlan0 is up
systemctl unmask hostapd

# Modify hostapd service to wait for wlan0
# Create override directory
mkdir -p /etc/systemd/system/hostapd.service.d
cat > /etc/systemd/system/hostapd.service.d/wait-for-wlan0.conf <<'EOF'
[Unit]
After=wlan0-up.service
Requires=wlan0-up.service

[Service]
# Add a delay to ensure wlan0 is fully up and has IP
ExecStartPre=/bin/bash -c 'for i in {1..10}; do if ip link show wlan0 | grep -q "state UP" && ip addr show wlan0 | grep -q "172.31.250.1"; then exit 0; fi; sleep 1; done; echo "Warning: wlan0 may not be ready"'
ExecStartPre=/bin/sleep 2
EOF

systemctl daemon-reload
systemctl enable hostapd
systemctl enable wlan0-up.service

# Start wlan0-up first, then restart dnsmasq and hostapd
systemctl start wlan0-up.service
sleep 4
# Verify wlan0 is up and has IP before starting services
if ip link show wlan0 | grep -q "state UP" && ip addr show wlan0 | grep -q "172.31.250.1"; then
    echo "✓ wlan0 is UP with IP 172.31.250.1"
    # Restart dnsmasq to pick up the IP
    systemctl restart dnsmasq
    echo "✓ dnsmasq restarted"
    systemctl start hostapd
    echo "✓ hostapd started"
else
    echo "⚠️  Warning: wlan0 may not be ready"
    echo "   Interface state: $(ip link show wlan0 2>/dev/null | grep -o 'state [A-Z]*' || echo 'unknown')"
    echo "   IP address: $(ip addr show wlan0 2>/dev/null | grep 'inet ' || echo 'none')"
    # Try to assign IP manually if missing
    if ! ip addr show wlan0 2>/dev/null | grep -q "172.31.250.1"; then
        echo "   Attempting to assign IP manually..."
        ip addr add 172.31.250.1/24 dev wlan0 2>/dev/null || true
        sleep 1
    fi
    systemctl restart dnsmasq || echo "❌ dnsmasq failed to restart"
    systemctl start hostapd || echo "❌ hostapd failed to start"
fi

echo ""
echo "========================================"
echo "✅ Wi-Fi AP Setup Complete!"
echo "========================================"
echo ""
echo "Network Details:"
echo "  SSID: $AP_SSID"
echo "  Static IP: 172.31.250.1"
echo "  DHCP Range: 172.31.250.50-150"
echo "  Band: 2.4GHz (macOS compatible)"
echo "  Channel: 6"
echo ""
echo "Access NAC Tap Web Interface:"
echo "  1. Connect to Wi-Fi: $AP_SSID"
echo "  2. Open browser: http://172.31.250.1:8080"
echo ""
echo "SSH Access:"
echo "  ssh user@172.31.250.1"
echo ""
echo "macOS Compatibility:"
echo "  ✓ Configured for 2.4GHz band (hw_mode=g)"
echo "  ✓ 802.11n (HT) enabled for better compatibility"
echo "  ✓ Channel 6 (non-overlapping 2.4GHz channel)"
echo ""
echo "AP will start automatically on boot (systemd enabled)"
echo ""
echo "To start NAC Tap monitoring:"
echo "  sudo python3 nac-tap.py"
echo ""
echo "Or install as systemd service for auto-start:"
echo "  sudo bash install-service.sh"
echo ""
echo "To check AP status:"
echo "  systemctl status hostapd"
echo "  systemctl status dnsmasq"
echo ""
echo "To verify AP starts on boot:"
echo "  systemctl is-enabled hostapd"
echo "  systemctl is-enabled dnsmasq"
echo ""

