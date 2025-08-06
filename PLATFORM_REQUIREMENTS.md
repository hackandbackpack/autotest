# AutoTest Platform Requirements

## Linux-Only Security Testing Framework

**AutoTest is designed exclusively for Linux penetration testing environments.**

### Supported Operating Systems
- ✅ **Linux distributions** (Ubuntu, Debian, Kali, Parrot, etc.)
- ❌ **Windows** (Not supported)
- ❌ **macOS** (Not supported)

### Why Linux-Only?

1. **Security Tool Ecosystem**: Most penetration testing tools are designed for Linux
2. **Package Management**: Standardized package managers (apt, yum, dnf) for tool installation  
3. **Shell Environment**: Relies on bash, standard Linux utilities, and POSIX compliance
4. **Target Compatibility**: Designed to test both Linux and Windows targets from a Linux host
5. **Simplified Codebase**: Removing cross-platform complexity improves maintainability

### Minimum System Requirements

#### Required Linux Components
- **Operating System**: Linux kernel 3.10+ (64-bit)
- **Python**: Python 3.8+ with pip3
- **Shell**: Bash 4.0+
- **Network**: Direct network access to target systems
- **Privileges**: Sudo access for tool installation

#### Essential System Tools
```bash
# These tools must be available on your Linux system:
bash, grep, awk, sed, curl, wget, git
```

#### Package Manager Support
AutoTest supports multiple Linux package managers:
- **Debian/Ubuntu**: `apt-get`, `apt`
- **RHEL/CentOS**: `yum`, `dnf`  
- **Arch Linux**: `pacman`
- **Python packages**: `pip3`

### Recommended Linux Distributions

#### Penetration Testing Focused
- **Kali Linux** (Recommended) - Pre-installed security tools
- **Parrot Security** - Lightweight pentesting distro
- **BlackArch** - Arch-based security distribution

#### General Purpose Linux
- **Ubuntu 20.04+ LTS** - Good compatibility and package support
- **Debian 11+** - Stable base with security tools available
- **CentOS/RHEL 8+** - Enterprise environment testing

### Installation Prerequisites

Before running AutoTest, ensure your Linux system has:

```bash
# Update package lists
sudo apt-get update

# Install essential development tools
sudo apt-get install build-essential python3 python3-pip git

# Install common networking tools
sudo apt-get install dnsutils net-tools nmap

# For compiling tools from source
sudo apt-get install make gcc g++ cmake
```

### Tool Installation

AutoTest provides comprehensive tool installation:

```bash
# Enhanced installation (recommended)
python3 enhanced_installation.py

# Basic installation  
python3 installation.py

# Via autotest setup
python3 autotest.py --setup
```

### Network Requirements

- **Outbound Internet**: For downloading tools and updates
- **Target Network Access**: Direct routing to target systems
- **Port Access**: Ability to perform port scans (may require root for some scans)
- **DNS Resolution**: For hostname resolution and DNS enumeration

### Security Considerations

1. **Run as Regular User**: Most operations don't require root privileges
2. **Use Sudo for Installation**: Tool installation may require sudo access  
3. **Network Isolation**: Consider running in isolated network environments
4. **Tool Verification**: All tools are downloaded from official sources
5. **Legal Authorization**: Only scan systems you own or have explicit permission to test

### Platform Detection

AutoTest will automatically detect and verify the Linux environment:

```bash
# The framework will exit with an error on non-Linux systems
[-] ERROR: AutoTest requires a Linux system.
    Windows and macOS are not supported.
```

### Migration from Cross-Platform Tools

If migrating from cross-platform security frameworks:

1. **Set up Linux VM**: Use VirtualBox/VMware for dedicated testing environment
2. **Use Kali Linux**: Pre-configured with most security tools
3. **Container Option**: Docker containers with Linux-based security tools
4. **WSL2**: Windows Subsystem for Linux 2 (basic compatibility)

### Support and Documentation

- **Installation Issues**: Check `enhanced_installation.py --help`
- **Tool Problems**: Run `python3 autotest.py --check-tools`
- **Linux Setup**: Refer to your distribution's documentation
- **Security Best Practices**: Follow responsible disclosure guidelines

---

**Note**: This Linux-only requirement ensures optimal performance, security, and compatibility with the penetration testing ecosystem while maintaining a clean, maintainable codebase.