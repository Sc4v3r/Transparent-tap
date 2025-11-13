# NAC-Tap Custom Phishlets

This directory contains custom Evilginx2 phishlets optimized for **DNS poisoning attacks** in transparent MITM scenarios.

## 🎯 DNS Poisoning vs Traditional Phishing

### Traditional Phishing (Domain Fronting)
- Uses fake domain (e.g., `micr0soft-login.com`)
- Requires email lure with link to fake domain
- Victim sees suspicious domain in browser
- High detection rate

### DNS Poisoning (NAC-Tap Method)
- Uses **real domain** (e.g., `login.microsoftonline.com`)
- No lure needed - automatic redirect via DNS
- Victim sees legitimate domain in browser
- Very low detection rate
- Transparent MITM attack

## 📋 Custom Phishlets

### `o365.yaml` - Microsoft 365 / Azure AD
**Optimized for DNS poisoning attacks**

**Features:**
- Matching subdomains (`phish_sub = orig_sub`)
- Captures Microsoft session cookies (ESTSAUTH, etc.)
- Forces "Keep me signed in" for persistent access
- Minimal complexity - only essential Microsoft domains
- No GoDaddy/Okta/third-party clutter

**Captured Tokens:**
- `ESTSAUTH` - Primary Microsoft authentication cookie
- `ESTSAUTHPERSISTENT` - Persistent login cookie
- `MSPAuth` - Microsoft account session
- `WLSSC` - Windows Live session
- OAuth tokens and refresh tokens

**Usage:**
```bash
# Automatically installed by install-evilginx.sh
# Or manually:
cp o365.yaml /opt/evilginx2/phishlets/o365.yaml
```

## 🔧 How It Works

1. **DNS Poisoning**: `dnsmasq` redirects `login.microsoftonline.com` → Bridge IP (10.200.66.1)
2. **TLS Interception**: Evilginx presents valid SSL certificate
3. **Transparent Proxy**: User authenticates normally, doesn't see any difference
4. **Session Capture**: All cookies and tokens captured to database
5. **Real Access**: Attacker can use captured session to access victim's Microsoft 365

## ⚠️ Key Differences from Standard Phishlets

| Standard Phishlet | NAC-Tap Phishlet |
|-------------------|------------------|
| `phish_sub: "phish"` | `phish_sub: "login"` |
| Fake domain in lure | Real domain in DNS |
| Email/SMS lure required | No lure needed |
| Obvious to victim | Transparent |
| Multiple proxy_hosts | Minimal essential hosts |
| Complex sub_filters | Simple filters |

## 📝 Creating Custom Phishlets

When creating phishlets for DNS poisoning:

1. **Match subdomains**: `phish_sub` must equal `orig_sub`
   ```yaml
   proxy_hosts:
     - { phish_sub: 'login', orig_sub: 'login', domain: 'target.com' }
   ```

2. **Use real domains**: No fake domains in configuration

3. **Minimize complexity**: Only include essential domains for authentication

4. **Focus on cookies**: Capture session tokens, not just credentials

5. **Test with NAC-Tap**: Use the debug output to verify captures

## 🛠️ Installation

Custom phishlets are automatically installed by `install-evilginx.sh`:

```bash
sudo ./install-evilginx.sh
```

The script will:
1. Backup original phishlets (`.orig`)
2. Copy NAC-Tap optimized phishlets
3. Verify installation

## 📊 Debugging Session Capture

When sessions aren't captured, check:

1. **Database location**:
   ```bash
   ls -la ~/.evilginx/data.db
   ls -la /root/.evilginx/data.db
   ```

2. **Phishlet configuration**:
   ```bash
   cat /opt/evilginx2/phishlets/o365.yaml | grep "author: '@nac-tap'"
   ```

3. **NAC-Tap logs**: Look for:
   - `Found Evilginx database: /path/to/data.db`
   - `Session columns: id, phishlet, username, ...`
   - `NEW SESSION CAPTURED!`

## 🔐 Security Note

These phishlets are designed for **authorized security testing and research only**. 

Unauthorized access to computer systems is illegal. Only use these tools on systems you own or have explicit written permission to test.

## 📚 References

- [Evilginx2 Documentation](https://github.com/kgretzky/evilginx2)
- [NAC-Tap Documentation](../README.md)
- [Phishlet Development Guide](https://help.evilginx.com/docs/getting-started/phishlet-format)

