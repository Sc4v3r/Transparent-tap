#!/bin/bash
#
# NAC Bridge Monitor - Dependency Installation Script
# Run as root: sudo bash install-dependencies.sh
#

# Don't exit on error - we'll handle failures gracefully
set +e

echo "========================================"
echo "NAC Bridge Monitor - Installing Dependencies"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo bash install-dependencies.sh"
    exit 1
fi

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
    echo "✓ Detected Debian/Ubuntu-based system"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    echo "✓ Detected RedHat/CentOS-based system"
else
    echo "⚠️  Unknown OS - attempting Debian/Ubuntu installation"
    OS="debian"
fi

echo ""
echo "Installing system packages..."
echo ""

if [ "$OS" = "debian" ]; then
    # Update package list
    apt-get update
    
    # Core packages (required)
    echo "Installing core packages..."
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        git \
        tcpdump \
        iproute2 \
        bridge-utils \
        ethtool \
        wireshark-common \
        iptables \
        ebtables \
        libpcap-dev \
        file
    
    # WiFi packages (may have different names or already be installed)
    echo "Installing WiFi packages..."
    INSTALLED_WIFI=0
    
    # Try wpa_supplicant (standard name)
    if apt-get install -y wpa_supplicant 2>/dev/null; then
        INSTALLED_WIFI=1
    else
        # Check if already installed
        if command -v wpa_supplicant >/dev/null 2>&1; then
            echo "✓ wpa_supplicant already installed"
            INSTALLED_WIFI=1
        else
            echo "⚠️  wpa_supplicant not found in repositories, but may already be installed"
        fi
    fi
    
    # Try wireless-tools (may be obsolete, replaced by iw)
    if apt-get install -y wireless-tools 2>/dev/null; then
        echo "✓ wireless-tools installed"
    else
        # Check if iw is available (modern replacement)
        if command -v iw >/dev/null 2>&1; then
            echo "✓ iw available (modern replacement for wireless-tools)"
        else
            echo "⚠️  wireless-tools not found, installing iw instead"
            apt-get install -y iw 2>/dev/null || true
        fi
    fi
    
    # Try isc-dhcp-client (may be named differently)
    if apt-get install -y isc-dhcp-client 2>/dev/null; then
        echo "✓ isc-dhcp-client installed"
    else
        # Try alternative names
        if apt-get install -y dhcp-client 2>/dev/null; then
            echo "✓ dhcp-client installed"
        elif command -v dhclient >/dev/null 2>&1; then
            echo "✓ dhclient already available"
        else
            echo "⚠️  DHCP client not found, but may already be installed"
        fi
    fi
    
    echo ""
    echo "✓ Debian/Ubuntu packages installed"
    
elif [ "$OS" = "redhat" ]; then
    # Install required packages
    echo "Installing core packages..."
    yum install -y \
        python3 \
        python3-pip \
        python3-venv \
        git \
        tcpdump \
        iproute \
        bridge-utils \
        ethtool \
        wireshark-cli \
        iptables \
        ebtables \
        libpcap-devel \
        file \
        dhclient
    
    # Try wpa_supplicant
    echo "Installing WiFi packages..."
    if yum install -y wpa_supplicant 2>/dev/null; then
        echo "✓ wpa_supplicant installed"
    elif command -v wpa_supplicant >/dev/null 2>&1; then
        echo "✓ wpa_supplicant already installed"
    else
        echo "⚠️  wpa_supplicant not found, but may already be installed"
    fi
    
    # Try iw (modern wireless tools)
    if yum install -y iw 2>/dev/null; then
        echo "✓ iw installed"
    elif command -v iw >/dev/null 2>&1; then
        echo "✓ iw already installed"
    fi
    
    echo ""
    echo "✓ RedHat/CentOS packages installed"
fi

echo ""
echo "Verifying installations..."
echo ""

# Verify tools
MISSING=""
for tool in python3 tcpdump ip bridge ethtool capinfos tail iptables ebtables; do
    if command -v $tool >/dev/null 2>&1; then
        VERSION=$(command -v $tool)
        echo "✓ $tool: $VERSION"
    else
        echo "✗ $tool: NOT FOUND"
        MISSING="$MISSING $tool"
    fi
done

# Verify WiFi tools (optional but recommended)
echo ""
echo "Verifying WiFi tools..."
WIFI_TOOLS_OK=1
for tool in wpa_supplicant; do
    if command -v $tool >/dev/null 2>&1; then
        echo "✓ $tool: $(command -v $tool)"
    else
        echo "⚠️  $tool: NOT FOUND (WiFi client features may not work)"
        WIFI_TOOLS_OK=0
    fi
done

# Check for iw or iwconfig (wireless tools)
if command -v iw >/dev/null 2>&1; then
    echo "✓ iw: $(command -v iw)"
elif command -v iwconfig >/dev/null 2>&1; then
    echo "✓ iwconfig: $(command -v iwconfig)"
else
    echo "⚠️  Wireless tools (iw/iwconfig): NOT FOUND (WiFi scanning may not work)"
fi

# Check for DHCP client
if command -v dhclient >/dev/null 2>&1; then
    echo "✓ dhclient: $(command -v dhclient)"
elif command -v dhcpcd >/dev/null 2>&1; then
    echo "✓ dhcpcd: $(command -v dhcpcd)"
else
    echo "⚠️  DHCP client: NOT FOUND (WiFi client DHCP may not work)"
fi

echo ""
echo "Creating directories..."
mkdir -p /var/log/nac-captures
chmod 700 /var/log/nac-captures
echo "✓ /var/log/nac-captures created"

echo ""
echo "========================================"
if [ -z "$MISSING" ]; then
    echo "✅ All dependencies installed successfully!"
else
    echo "⚠️  Missing tools:$MISSING"
    echo "You may need to install these manually."
fi
echo "========================================"
echo ""

# Install PCredz with virtual environment
echo "Installing PCredz for credential extraction..."
echo ""

PCREDZ_DIR="/opt/PCredz"
PCREDZ_WRAPPER="$PCREDZ_DIR/pcredz-wrapper.sh"

if [ -d "$PCREDZ_DIR" ]; then
    echo "⚠️  PCredz directory already exists at $PCREDZ_DIR"
    echo "   Skipping PCredz installation. To reinstall, remove the directory first."
else
    # Check if git is available
    if ! command -v git >/dev/null 2>&1; then
        echo "⚠️  git not found - skipping PCredz installation"
        echo "   Install git manually and run: git clone https://github.com/lgandx/PCredz.git $PCREDZ_DIR"
    else
        echo "Cloning PCredz repository..."
        if git clone https://github.com/lgandx/PCredz.git "$PCREDZ_DIR" 2>&1; then
            echo "✓ PCredz cloned successfully"
            
            # Note: libpcap-dev and file are already installed above
            echo "✓ PCredz system dependencies available (libpcap-dev, file)"
            
            # Create virtual environment
            echo "Creating Python virtual environment..."
            if python3 -m venv "$PCREDZ_DIR/venv" 2>&1; then
                echo "✓ Virtual environment created"
                
                # Install PCredz Python dependencies in venv
                echo "Installing PCredz Python dependencies in virtual environment..."
                if "$PCREDZ_DIR/venv/bin/pip" install --upgrade pip >/dev/null 2>&1 && \
                   "$PCREDZ_DIR/venv/bin/pip" install Cython python-libpcap >/dev/null 2>&1; then
                    echo "✓ PCredz Python dependencies installed (Cython, python-libpcap)"
                else
                    echo "⚠️  Failed to install PCredz Python dependencies"
                    echo "   You may need to install them manually:"
                    echo "   cd $PCREDZ_DIR && venv/bin/pip install Cython python-libpcap"
                fi
                
                # Create wrapper script that uses venv
                echo "Creating PCredz wrapper script..."
                cat > "$PCREDZ_WRAPPER" << 'EOF'
#!/bin/bash
# PCredz wrapper script - uses virtual environment
cd /opt/PCredz
/opt/PCredz/venv/bin/python3 Pcredz "$@"
EOF
                chmod +x "$PCREDZ_WRAPPER"
                echo "✓ Wrapper script created at $PCREDZ_WRAPPER"
                
                # Verify installation
                if "$PCREDZ_WRAPPER" --help >/dev/null 2>&1; then
                    echo "✅ PCredz installed and verified successfully!"
                else
                    echo "⚠️  PCredz installed but verification failed"
                    echo "   You can test manually: $PCREDZ_WRAPPER --help"
                fi
            else
                echo "⚠️  Failed to create virtual environment"
                echo "   Falling back to system Python"
                # Fallback: use system Python
                echo "Installing PCredz Python dependencies (system Python)..."
                if pip3 install Cython python-libpcap >/dev/null 2>&1; then
                    echo "✓ PCredz Python dependencies installed (system Python)"
                else
                    echo "⚠️  Failed to install PCredz Python dependencies"
                fi
                # Create wrapper without venv
                cat > "$PCREDZ_WRAPPER" << 'EOF'
#!/bin/bash
cd /opt/PCredz
python3 Pcredz "$@"
EOF
                chmod +x "$PCREDZ_WRAPPER"
                echo "✓ Wrapper script created (using system Python)"
            fi
        else
            echo "⚠️  Failed to clone PCredz repository"
            echo "   You can install it manually:"
            echo "   git clone https://github.com/lgandx/PCredz.git $PCREDZ_DIR"
        fi
    fi
fi

echo ""
echo "Next steps:"
echo "  1. Setup Wi-Fi Management AP (required):"
echo "     sudo bash setup-wifi-ap.sh"
echo ""
echo "  2. Start NAC-Tap:"
echo "     sudo python3 nac-tap.py"
echo ""
echo "  3. Access web interface:"
echo "     Via Wi-Fi AP: http://172.31.250.1:8080"
echo "     Via localhost: http://localhost:8080"
echo ""
echo "For complete setup instructions, see README.md"
echo ""

