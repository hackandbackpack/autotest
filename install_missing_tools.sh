#!/bin/bash
#
# Quick installer for missing AutoTest tools
# Handles modern Python externally-managed environments
#

echo "AutoTest Missing Tools Installer"
echo "================================="

# Function to install Python packages with fallbacks
install_python_package() {
    local package=$1
    echo "Installing $package..."
    
    # Try system package first
    system_package="python3-$(echo $package | tr '_' '-')"
    echo "  Trying system package: $system_package"
    if sudo apt-get update && sudo apt-get install -y "$system_package"; then
        echo "  ✓ Installed $package via system package"
        return 0
    fi
    
    # Try pipx
    echo "  Trying pipx..."
    if ! command -v pipx >/dev/null 2>&1; then
        echo "  Installing pipx..."
        sudo apt-get install -y pipx
    fi
    
    if pipx install "$package"; then
        echo "  ✓ Installed $package via pipx"
        return 0
    fi
    
    # Try --user with --break-system-packages
    echo "  Trying pip --user --break-system-packages..."
    if pip3 install --user --break-system-packages "$package"; then
        echo "  ✓ Installed $package with --user --break-system-packages"
        return 0
    fi
    
    echo "  ✗ Failed to install $package"
    return 1
}

# Install ssh-audit
echo "1. Installing ssh-audit..."
install_python_package "ssh-audit"

# Install testssl.sh
echo "2. Installing testssl.sh..."
if sudo git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh; then
    echo "  ✓ Installed testssl.sh to /opt/testssl.sh"
elif git clone https://github.com/drwetter/testssl.sh.git ~/testssl.sh && mkdir -p ~/.local/bin && ln -sf ~/testssl.sh/testssl.sh ~/.local/bin/testssl.sh; then
    echo "  ✓ Installed testssl.sh to ~/testssl.sh"
    echo "  Make sure ~/.local/bin is in your PATH"
else
    echo "  ✗ Failed to install testssl.sh"
fi

# Install sslyze
echo "3. Installing sslyze..."
install_python_package "sslyze"

# Install netexec
echo "4. Installing netexec..."
install_python_package "netexec"

echo ""
echo "Installation complete!"
echo "Run 'python3 autotest.py --check-tools' to verify all tools are available."

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo ""
    echo "NOTE: ~/.local/bin is not in your PATH."
    echo "Add this line to your ~/.bashrc or ~/.zshrc:"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo "Then run: source ~/.bashrc"
fi