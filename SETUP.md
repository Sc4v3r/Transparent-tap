# NAC-Tap - Complete Setup Guide

This guide walks you through the complete setup process from a fresh system to a fully operational NAC-Tap device.

## Prerequisites

- **Hardware**: 
  - 2+ Ethernet interfaces (eth0, eth1) for bridge
  - 1+ Wi-Fi interface (wlan0) for management AP (optional but recommended)
  - Additional Wi-Fi interface (wlan1/wlan2) for external internet (optional)
- **OS**: Debian/Ubuntu or compatible Linux distribution
- **Access**: Root/sudo privileges
- **Network**: Internet connection for initial package installation

## Quick Start (TL;DR)

```bash
# 1. Install dependencies
sudo bash install-dependencies.sh

# 2. Setup Wi-Fi management AP (optional but recommended)
sudo bash setup-wifi-ap.sh

# 3. Start NAC-Tap
sudo python3 nac-tap.py

# 4. Access web interface
# Via Wi-Fi AP: http://172.31.250.1:8080
# Via localhost: http://localhost:8080
```

## Detailed Setup Steps

### Step 1: Install System Dependencies

Install all required system packages and tools:

```bash
sudo bash install-dependencies.sh
```

**What this installs:**
- Python 3 and pip
- Network tools: `tcpdump`, `iproute2`, `bridge-utils`, `ethtool`
- Analysis tools: `wireshark-common` (for capinfos)
- Firewall tools: `iptables`, `ebtables`
- Network utilities: `net-tools`

**Verification:**
```bash
# Check Python version (must be 3.7+)
python3 --version

# Verify tools are installed
which tcpdump ip bridge ethtool capinfos iptables ebtables
```

**Troubleshooting:**
- If `capinfos` is missing: `sudo apt-get install wireshark-common`
- If tools are missing: Re-run `install-dependencies.sh`

---

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

**Troubleshooting:**
- If AP doesn't start: Check logs with `journalctl -u hostapd -f`
- If can't connect: Verify SSID/password, check `iw dev wlan0 info`
- macOS connection issues: The script is configured for 2.4GHz (macOS compatible)

**Note:** The AP setup is **optional** but highly recommended. You can skip this if you prefer to manage via Ethernet or SSH port forwarding.

---

### Step 3: Optional - Install PCredz (Credential Extraction)

PCredz automatically extracts credentials (NTLM hashes, passwords, etc.) from PCAP files:

```bash
# Clone PCredz
sudo git clone https://github.com/lgandx/PCredz.git /opt/PCredz

# Install PCredz dependencies
cd /opt/PCredz
sudo pip3 install -r requirements.txt

# Create wrapper script
sudo tee /opt/PCredz/pcredz-wrapper.sh > /dev/null << 'EOF'
#!/bin/bash
cd /opt/PCredz
python3 Pcredz "$@"
EOF

sudo chmod +x /opt/PCredz/pcredz-wrapper.sh
```

**Verification:**
```bash
# Test PCredz
sudo /opt/PCredz/pcredz-wrapper.sh --help
```

**Note:** PCredz is optional. The NAC-Tap will work without it, but you won't get automatic credential extraction.

---

### Step 4: Start NAC-Tap

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

## Network Interface Configuration

### Interface Roles

The NAC-Tap uses a specific interface role configuration:

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

### Interface Detection

The script automatically:
- Detects available Ethernet interfaces
- Excludes wireless interfaces from bridge
- Assigns roles based on configuration
- Prevents conflicts between AP and client WLAN

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

---

## Using NAC-Tap

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

4. **Download/Analyze**
   - Click **"Download PCAP"** to download file
   - Or analyze on device with PCredz (Loot tab)

### MITM Attacks

See [MITM-FEATURES.md](MITM-FEATURES.md) for detailed MITM attack instructions.

### Upload to Slack

See [QUICKSTART.md](QUICKSTART.md) for Slack integration setup.

---

## File Locations

- **PCAP files**: `/var/log/nac-captures/capture-*.pcap`
- **Credentials (PCredz)**: `/var/log/nac-captures/loot_raw.txt`
- **Logs**: `/var/log/auto-nac-bridge.log`
- **State/Config**: `/var/run/auto-nac-state.conf`
- **Upload Config**: `/var/log/nac-captures/upload-config.json`

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

## Next Steps

1. ✅ Complete setup (dependencies, AP, start NAC-Tap)
2. 📖 Read [QUICKSTART.md](QUICKSTART.md) for usage instructions
3. 🎭 Read [MITM-FEATURES.md](MITM-FEATURES.md) for attack techniques
4. 📊 Read [PENTEST-PLAYBOOK.md](PENTEST-PLAYBOOK.md) for engagement workflows

---

## Support

- **Logs**: `/var/log/auto-nac-bridge.log`
- **Status**: Check web interface Status tab
- **Service**: `sudo systemctl status nac-tap.service`
- **Documentation**: See other `.md` files in repository


