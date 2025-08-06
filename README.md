# AutoTest - Automated Network Penetration Testing Framework

AutoTest is a comprehensive automated penetration testing framework that orchestrates multiple security tools to perform reconnaissance, vulnerability scanning, and exploitation of network targets.

**🐧 Linux-Only Framework**: AutoTest is designed exclusively for Linux penetration testing environments. Windows and macOS are not supported.

## Features

- **Automated Workflow**: Seamlessly integrates multiple security tools in a logical testing sequence
- **Parallel Processing**: Efficient scanning with configurable concurrency
- **Interactive TUI**: Real-time progress monitoring with a terminal user interface
- **Flexible Configuration**: YAML-based configuration for easy customization
- **Multiple Output Formats**: JSON, HTML, and XML reporting
- **Modular Architecture**: Easily extend with new tools and modules
- **Smart Target Parsing**: Supports IPs, CIDR ranges, hostnames, and target files

## Installation

### Prerequisites

- **Linux Operating System** (Ubuntu, Debian, Kali, etc.)
- **Python 3.8+** with pip3
- **Sudo privileges** for tool installation  
- **Network access** to target systems

See [PLATFORM_REQUIREMENTS.md](PLATFORM_REQUIREMENTS.md) for detailed system requirements.
- Required tools will be installed automatically

### Install from Source

```bash
git clone https://github.com/hackandbackpack/autotest.git
cd autotest
pip install -r requirements.txt

# Run the installation script to set up required tools
python3 installation.py
```

### Tool Setup

AutoTest requires several security tools. The installation scripts will:
- Check for required tools (nmap, masscan, nikto, hydra, etc.)
- Install tools via Linux package managers (apt, yum, dnf)
- Install Python-based tools via pip3
- Verify tool installation and paths
- Save tool configurations for AutoTest to use

Run the comprehensive installer:
```bash
# Comprehensive installation (recommended)
python3 installation.py

# Interactive installation with options
python3 installation.py --categories  # Show available tools
python3 installation.py --check       # Check tools only
python3 installation.py --auto        # Automatic installation
python3 installation.py --high        # Install high priority tools only

# Or use the built-in setup
python3 autotest.py --setup
```

## Usage

### Basic Usage

```bash
# Scan a single target
python autotest.py 192.168.1.1

# Scan a network range
python autotest.py 192.168.1.0/24

# Scan multiple targets
python autotest.py 10.0.0.1 10.0.0.2 example.com

# Skip tool checking (if tools are already installed)
python autotest.py --skip-tool-check 192.168.1.1

# Scan from file
autotest targets.txt
```

### Advanced Options

```bash
# Use custom configuration
autotest -c myconfig.yaml 192.168.1.0/24

# Quick scan mode
autotest --quick 192.168.1.1

# Stealth mode
autotest --stealth 192.168.1.1

# Specify output format
autotest -f json xml 192.168.1.1

# Increase verbosity
autotest -vv 192.168.1.1

# Disable UI
autotest --no-ui 192.168.1.1
```

### Module Control

```bash
# List available modules
autotest --list-modules

# Enable specific modules
autotest --enable nmap nuclei 192.168.1.1

# Disable specific modules
autotest --disable metasploit 192.168.1.1
```

## Configuration

AutoTest uses YAML configuration files to customize behavior:

```yaml
# autotest.yaml
general:
  max_concurrent_scans: 10
  timeout: 3600
  stealth_mode: false

modules:
  nmap:
    enabled: true
    options:
      scan_type: "-sS -sV"
      ports: "1-65535"
  
  nuclei:
    enabled: true
    options:
      severity: "critical,high,medium"
      templates: "cves,vulnerabilities"

reporting:
  formats:
    - json
    - html
  include_raw_output: false
```

## Module Architecture

AutoTest modules follow a standard interface:

```python
class MyModule(BaseModule):
    async def run(self, target: str, options: dict) -> dict:
        # Implementation
        return results
```

## Output

Results are saved in the specified output directory with the following structure:

```
autotest_results/
├── autotest_20240121_120000.json
├── autotest_20240121_120000.html
├── raw/
│   ├── nmap/
│   ├── nuclei/
│   └── ...
└── logs/
    └── autotest.log
```

## Security Considerations

- **Authorization**: Only use AutoTest on networks you own or have explicit permission to test
- **Rate Limiting**: Configure appropriate delays to avoid overwhelming targets
- **Stealth Mode**: Use stealth options for more covert testing
- **Network Impact**: Be aware of the potential impact on network performance

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for authorized security testing only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse or damage caused by this tool.

## Support

- Documentation: https://autotest.readthedocs.io
- Issues: https://github.com/example/autotest/issues
- Wiki: https://github.com/example/autotest/wiki