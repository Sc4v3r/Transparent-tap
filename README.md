# NAC-Tap - Network Access Control Transparent Tap

A transparent Layer 2 network bridge with packet capture, MITM attack capabilities, and credential extraction for penetration testing engagements.

## Table of Contents

- [Quick Start](#quick-start)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Setup](#setup)
- [Usage](#usage)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Network Topology](#network-topology)
- [Security Notes](#security-notes)
- [Additional Resources](#additional-resources)

---

## Quick Start

```bash
# 1. Install dependencies
sudo bash install-dependencies.sh

# 2. Setup Wi-Fi management AP (optional but recommended)
sudo bash setup-wifi-ap.sh

# 3. Start NAC-Tap
sudo python3 nac-tap.py

# 4. Access web interface
# http://172.31.250.1:8080 (via Wi-Fi) or http://localhost:8080
```

---

## System Requirements

- **OS**: Linux (Debian/Ubuntu, RedHat/CentOS, or compatible)
- **Python**: 3.7 or higher
- **Privileges**: Must run as root (requires network bridge control)
- **Hardware**: 
  - 2+ Ethernet interfaces (eth0, eth1) for bridge
  - 1+ Wi-Fi interface (wlan0) for management AP
  - Additional Wi-Fi interface (wlan1/wlan2) for external internet (optional)
- **CPU**: Any ARM/x86 with 2+ cores
- **RAM**: 512MB+ (1GB+ recommended for large captures)
- **Storage**: 8GB+ (depends on capture size)

---

## Installation

### Automated Installation (Recommended)

```bash
sudo bash install-dependencies.sh
```

**What this installs:**
- Python 3 and pip
- Network tools: `tcpdump`, `iproute2`, `bridge-utils`, `ethtool`
- Analysis tools: `wireshark-common` (for capinfos)
- Firewall tools: `iptables`, `ebtables`
- Network utilities: `net-tools`
- WiFi tools: `wpa_supplicant`, `wireless-tools`, `isc-dhcp-client`
- **PCredz** (automatically installed in virtual environment at `/opt/PCredz`)

**Verification:**
```bash
# Check Python version (must be 3.7+)
python3 --version

# Verify tools are installed
which tcpdump ip bridge ethtool capinfos iptables ebtables

# Check PCredz
sudo /opt/PCredz/pcredz-wrapper.sh --help
```

### Manual Installation

#### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y python3 tcpdump iproute2 bridge-utils ethtool wireshark-common net-tools iptables ebtables wpa_supplicant wireless-tools isc-dhcp-client
```

#### RedHat/CentOS
```bash
sudo yum install -y python3 tcpdump iproute bridge-utils ethtool wireshark-cli net-tools iptables ebtables wpa_supplicant wireless-tools dhclient
```

### Python Dependencies

The script uses **only Python standard library** - no pip packages required!

Imports used:
- os, sys, json, subprocess, re, time, signal, threading
- datetime, http.server, urllib.parse

---

## Setup

### Step 1: Install System Dependencies

```bash
sudo bash install-dependencies.sh
```

This installs all required packages and automatically sets up PCredz in a virtual environment.

### Step 2: Setup Wi-Fi Management Access Point (Recommended)

This creates a Wi-Fi network on `wlan0` that you can connect to for managing the device remotely. This is especially useful when the Ethernet interfaces are in bridge mode.

```bash
sudo bash setup-wifi-ap.sh
```

**What you'll be prompted for:**
- **SSID**: Network name (e.g., "NAC-Tap-MGMT")
- **WPA2 Password**: Minimum 8 characters

**What this configures:**
- Wi-Fi AP on `wlan0` (2.4GHz, macOS compatible)
- Static IP: `172.31.250.1/24`
- DHCP server: `172.31.250.50-150`
- DNS server: `172.31.250.1`

**After setup:**
- Connect to the Wi-Fi network from your laptop/phone
- Access web interface: **http://172.31.250.1:8080**
- SSH access: `ssh user@172.31.250.1`

**Verification:**
```bash
# Check AP status
systemctl status hostapd
systemctl status dnsmasq

# Check Wi-Fi interface
iw dev wlan0 info
ip addr show wlan0
```

**Note:** The AP setup is **optional** but highly recommended. You can skip this if you prefer to manage via Ethernet or SSH port forwarding.

### Step 3: Start NAC-Tap

#### Option A: Manual Start (Recommended for Testing)

```bash
sudo python3 nac-tap.py
```

The script will:
- Auto-detect Ethernet interfaces (eth0, eth1)
- Create transparent bridge (br0)
- Start web server on port 8080
- Display status and logs

**Access web interface:**
- Via Wi-Fi AP: **http://172.31.250.1:8080**
- Via localhost: **http://localhost:8080**
- Via Ethernet: **http://<device-ip>:8080**

#### Option B: Systemd Service (Auto-start on Boot)

```bash
# Copy files to system location
sudo mkdir -p /opt/nac-tap
sudo cp nac-tap.py /opt/nac-tap/
sudo cp -r app /opt/nac-tap/
sudo cp test-webui.html /opt/nac-tap/  # Optional, for debugging

# Install systemd service
sudo cp systemd/nac-tap.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start service
sudo systemctl enable nac-tap.service
sudo systemctl start nac-tap.service

# Check status
sudo systemctl status nac-tap.service
```

**Service management:**
```bash
# Start/stop/restart
sudo systemctl start nac-tap.service
sudo systemctl stop nac-tap.service
sudo systemctl restart nac-tap.service

# View logs
sudo journalctl -u nac-tap.service -f
```

---

## Usage

### Basic Packet Capture

1. **Start Capture**
   - Click **"Start Capture"** button in Status tab
   - Bridge automatically created between eth0 and eth1
   - Packets captured to `/var/log/nac-captures/capture-*.pcap`

2. **Monitor Traffic**
   - Watch packet count and file size increase
   - View logs in real-time
   - Check interface status

3. **Stop Capture**
   - Click **"Stop Capture"** button
   - Bridge remains active (transparent)
   - PCAP file saved and ready for download

4. **View Credentials (Loot Tab)**
   - Click **🎣 Loot** tab
   - Click **🔍 Analyze PCAP Now**
   - View raw PCredz output (includes NTLMv2 hashes, passwords, etc.)
   - Click **⬇️ Export Output (TXT)** to download

5. **Download PCAP**
   - Click **⬇️ Download PCAP**
   - Analyze offline with Wireshark

### MITM Attacks

1. **Enable MITM Mode**
   - Click **🎭 MITM** tab
   - (Optional) Enter remote VM IP if routing to external Kali/Responder
   - Click **🎭 Enable MITM**
   - Wait 30s for victim learning
   - Bridge learns victim MAC/IP automatically

2. **Intercept Protocols**
   - Click protocol cards to intercept:
     - **SMB/NetBIOS** (ports 137, 138, 139, 445)
     - **Name Resolution** (LLMNR, mDNS)
     - **HTTP** (port 80)
   - Traffic redirected to:
     - **Local**: Bridge IP 10.200.66.1 (run Responder/ntlmrelayx on device)
     - **Remote**: Your external attack VM (via WiFi)

3. **Run Attack Tools**
   ```bash
   # On bridge IP (local)
   sudo responder -I br0 -wrf
   
   # Or ntlmrelayx
   ntlmrelayx.py -t smb://target -smb2support
   
   # Remote VM gets traffic forwarded automatically
   ```

4. **Disable MITM**
   - Click **🛑 Disable MITM**
   - All rules and spoofing cleaned up automatically

**For detailed MITM attack instructions, see [MITM-FEATURES.md](MITM-FEATURES.md)**

### Upload to Slack

1. **Connect to WiFi** (optional, for internet access)
   - Click **📤 Upload** tab
   - Select WLAN interface (wlan1 or wlan2)
   - Click **Scan for APs** to find networks
   - Enter SSID and password
   - Click **Connect**
   - Test internet connectivity using the test button

2. **Configure Slack Upload**
   - Enter **Slack Webhook URL** (for notifications)
   - Enter **Slack Bot Token** (for file uploads)
   - Enter **Slack Channel** name
   - Enable **Auto Upload** to automatically send captures
   - Click **Save Configuration**

3. **Manual Upload**
   - Click **Upload Now** to manually trigger upload
   - Select what to upload: PCAP files and/or PCredz output

---

## Deployment

### Required Files

When deploying to a target device, ensure you have:
- ✓ `nac-tap.py` (main script)
- ✓ `app/static/index.html` (web UI)
- ✓ `test-webui.html` (optional, for debugging)
- ✓ `install-dependencies.sh` (installation script)
- ✓ `setup-wifi-ap.sh` (optional, for AP setup)
- ✓ `systemd/nac-tap.service` (optional, for service)

### Deployment Steps

```bash
# 1. Copy all files to target device
scp -r nac-tap.py app/ test-webui.html install-*.sh setup-*.sh systemd/ user@target-device:/opt/nac-tap/

# 2. SSH to target device
ssh user@target-device

# 3. Install dependencies
cd /opt/nac-tap
chmod +x install-dependencies.sh
sudo ./install-dependencies.sh

# 4. (Optional) Setup WiFi AP
sudo ./setup-wifi-ap.sh

# 5. Start NAC-Tap
sudo python3 nac-tap.py
```

### Access Web UI

- **From target device**: `http://localhost:8080`
- **From another computer**: `http://TARGET_DEVICE_IP:8080`
- **Via WiFi AP**: `http://172.31.250.1:8080`
- **Test page** (for debugging): `http://TARGET_DEVICE_IP:8080/test`

### Notes

- All file paths in `nac-tap.py` are relative/dynamic
- No hardcoded paths to edit
- Works on any device, any path, any user
- Keep all files together in the same directory

---

## Network Interface Configuration

### Interface Roles

- **wlan0**: Management AP (always active when eth interfaces are in bridge mode)
  - IP: `172.31.250.1/24`
  - Purpose: Remote management access
  - Configured by: `setup-wifi-ap.sh`

- **wlan1/wlan2**: Client interface (for external internet/Slack APIs)
  - Auto-detected by the script
  - Purpose: External communications when connected to an AP
  - Used for: Slack uploads, internet access

- **eth0/eth1**: Bridge members (transparent tap)
  - No IP addresses (pure L2 bridge)
  - Purpose: Transparent network monitoring
  - Configured automatically by NAC-Tap

- **br0**: Bridge interface
  - IP: `10.200.66.1/24` (for MITM attacks)
  - Purpose: Transparent Layer 2 bridge
  - Created automatically by NAC-Tap

---

## File Locations

- **PCAP files**: `/var/log/nac-captures/capture-*.pcap`
- **Credentials (PCredz)**: `/var/log/nac-captures/loot_raw.txt`
- **Logs**: `/var/log/auto-nac-bridge.log`
- **State/Config**: `/var/run/auto-nac-state.conf`
- **Upload Config**: `/var/log/nac-captures/upload-config.json`
- **PCredz**: `/opt/PCredz/` (virtual environment)

---

## Troubleshooting

### NAC-Tap Won't Start

```bash
# Check logs
sudo tail -f /var/log/auto-nac-bridge.log

# Verify Python version
python3 --version  # Must be 3.7+

# Check if running as root
sudo python3 nac-tap.py

# Verify dependencies
which tcpdump ip bridge ethtool
```

### Bridge Not Created

```bash
# Check interface detection
ip link show

# Verify Ethernet interfaces exist
ip link show eth0
ip link show eth1

# Check for errors in logs
sudo tail -20 /var/log/auto-nac-bridge.log
```

### Wi-Fi AP Not Working

```bash
# Check services
systemctl status hostapd
systemctl status dnsmasq

# View logs
journalctl -u hostapd -f
journalctl -u dnsmasq -f

# Verify interface
iw dev wlan0 info
ip addr show wlan0

# Restart services
sudo systemctl restart hostapd dnsmasq
```

### Can't Access Web Interface

```bash
# Check if NAC-Tap is running
ps aux | grep nac-tap

# Check if port 8080 is listening
sudo netstat -tlnp | grep 8080
# or
sudo ss -tlnp | grep 8080

# Check firewall
sudo iptables -L -n | grep 8080

# Try different access methods
# - Via Wi-Fi: http://172.31.250.1:8080
# - Via localhost: http://localhost:8080
# - Via SSH tunnel: ssh -L 8080:localhost:8080 user@device-ip
```

### Interface Conflicts

If you see DNS or routing conflicts:

```bash
# Check interface roles
ip link show

# Verify wlan0 is AP (not client)
iw dev wlan0 info

# Check DNS configuration
cat /etc/resolv.conf
resolvectl status

# Check routing
ip route show
```

### PCredz Installation Issues

If PCredz wasn't installed automatically:

```bash
# Check if PCredz directory exists
ls -la /opt/PCredz

# Manual installation
sudo apt-get install -y libpcap-dev file git
sudo git clone https://github.com/lgandx/PCredz.git /opt/PCredz
cd /opt/PCredz
sudo python3 -m venv venv
sudo venv/bin/pip install --upgrade pip
sudo venv/bin/pip install Cython python-libpcap

# Create wrapper script
sudo tee /opt/PCredz/pcredz-wrapper.sh > /dev/null << 'EOF'
#!/bin/bash
cd /opt/PCredz
/opt/PCredz/venv/bin/python3 Pcredz "$@"
EOF
sudo chmod +x /opt/PCredz/pcredz-wrapper.sh

# Test installation
sudo /opt/PCredz/pcredz-wrapper.sh --help
```

### Missing Tools

```bash
# Debian/Ubuntu
sudo apt-get install wireshark-common  # for capinfos

# RedHat/CentOS
sudo yum install wireshark-cli  # for capinfos
```

### Permission Denied Errors

Ensure you're running with sudo:
```bash
sudo python3 nac-tap.py
```

---

## Network Topology

```
┌─────────────────────────────────────────────────────────┐
│                    NAC-Tap Device                       │
│                                                          │
│  Client Device ←→ [eth0 ←→ br0 ←→ eth1] ←→ Network     │
│                            ↓                            │
│                        tcpdump                          │
│                            ↓                            │
│                    PCAP files                          │
│                            ↓                            │
│                       PCredz                           │
│                            ↓                            │
│                    Credentials                          │
│                                                          │
│  Management:                                             │
│    wlan0 (172.31.250.1) ← Wi-Fi AP                     │
│                                                          │
│  External (Optional):                                    │
│    wlan1/wlan2 ← Client mode for internet/Slack         │
└─────────────────────────────────────────────────────────┘
```

---

## Security Notes

- **Root Required**: Script requires root for network bridge control
- **PCAP Files**: Contain sensitive network traffic (stored with 600 permissions)
- **Credentials**: Restricted to root only (600 permissions)
- **Web Interface**: Runs on port 8080 (configurable in script)
- **Wi-Fi AP**: Use strong WPA2 password
- **Management Network**: Keep wlan0 on isolated network (172.31.250.0/24)
- **Regular Cleanup**: Clear old PCAP files to save space

---

## Additional Resources

- **[MITM-FEATURES.md](MITM-FEATURES.md)** - Detailed MITM attack techniques and usage
- **[PENTEST-PLAYBOOK.md](PENTEST-PLAYBOOK.md)** - Penetration testing workflows and engagement playbooks

---

## Support

- **Logs**: `/var/log/auto-nac-bridge.log`
- **Status**: Check web interface Status tab
- **Service**: `sudo systemctl status nac-tap.service`
- **Test Page**: `http://<device-ip>:8080/test` (for debugging JavaScript)

---

## First Run Checklist

After completing setup, verify everything works:

- [ ] Dependencies installed (`install-dependencies.sh` completed)
- [ ] Wi-Fi AP configured (if using) - can connect from laptop
- [ ] NAC-Tap starts without errors (`sudo python3 nac-tap.py`)
- [ ] Web interface accessible (http://172.31.250.1:8080 or http://localhost:8080)
- [ ] Bridge created successfully (check Status tab)
- [ ] Can start capture (click "Start Capture" button)
- [ ] PCAP files being created (`ls -lh /var/log/nac-captures/`)
