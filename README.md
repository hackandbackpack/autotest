# AutoTest - Automated Network Penetration Testing Framework

AutoTest is a comprehensive automated penetration testing framework that orchestrates multiple security tools to perform reconnaissance, vulnerability scanning, and exploitation of network targets.

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

- Python 3.8+
- Linux operating system (Kali Linux recommended)
- Security tools: nmap, nuclei, metasploit, nikto, dirb, etc.

### Install from Source

```bash
git clone https://github.com/example/autotest.git
cd autotest
pip install -r requirements.txt
python setup.py install
```

### Quick Install

```bash
pip install autotest-pentest
```

## Usage

### Basic Usage

```bash
# Scan a single target
autotest 192.168.1.1

# Scan a network range
autotest 192.168.1.0/24

# Scan multiple targets
autotest 10.0.0.1 10.0.0.2 example.com

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