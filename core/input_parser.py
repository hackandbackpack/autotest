"""
Input parsing and validation for AutoTest framework.
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from .utils import (
    validate_ip, validate_cidr, validate_port,
    parse_port_range, cidr_to_ip_list
)
from .exceptions import ValidationError


class InputParser:
    """
    Parser for AutoTest input specifications.
    
    Handles parsing and validation of targets, ports, and options.
    """
    
    def __init__(self):
        """Initialize the input parser."""
        self.targets: List[str] = []
        self.ports: List[int] = []
        self.options: Dict[str, Any] = {}
    
    def parse_targets(self, target_spec: str) -> List[str]:
        """
        Parse target specification into a list of IP addresses.
        
        Supports:
        - Single IP: "192.168.1.1"
        - CIDR notation: "192.168.1.0/24"
        - Comma-separated: "192.168.1.1,192.168.1.2"
        - File input: "@targets.txt"
        - Hostnames: "example.com"
        
        Args:
            target_spec: Target specification string
            
        Returns:
            List of target IP addresses
            
        Raises:
            ValidationError: If target specification is invalid
        """
        if not target_spec:
            raise ValidationError("Target specification cannot be empty")
        
        targets = []
        
        # Check if it's a file input
        if target_spec.startswith('@'):
            targets.extend(self._parse_target_file(target_spec[1:]))
        else:
            # Split by comma and process each part
            parts = target_spec.split(',')
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                
                if validate_ip(part):
                    # Single IP address
                    targets.append(part)
                elif validate_cidr(part):
                    # CIDR notation
                    targets.extend(cidr_to_ip_list(part))
                elif self._is_hostname(part):
                    # Hostname - resolve to IP
                    try:
                        import socket
                        ip = socket.gethostbyname(part)
                        targets.append(ip)
                    except socket.error:
                        raise ValidationError(f"Cannot resolve hostname: {part}")
                else:
                    raise ValidationError(f"Invalid target specification: {part}")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_targets = []
        for target in targets:
            if target not in seen:
                seen.add(target)
                unique_targets.append(target)
        
        if not unique_targets:
            raise ValidationError("No valid targets found")
        
        self.targets = unique_targets
        return unique_targets
    
    def parse_ports(self, port_spec: str) -> List[int]:
        """
        Parse port specification into a list of ports.
        
        Args:
            port_spec: Port specification string
            
        Returns:
            List of port numbers
            
        Raises:
            ValidationError: If port specification is invalid
        """
        if not port_spec:
            return []
        
        try:
            ports = parse_port_range(port_spec)
            self.ports = ports
            return ports
        except ValueError as e:
            raise ValidationError(f"Invalid port specification: {e}")
    
    def parse_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse and validate options.
        
        Args:
            options: Options dictionary
            
        Returns:
            Validated options dictionary
            
        Raises:
            ValidationError: If options are invalid
        """
        validated = {}
        
        # Validate common options
        if 'timeout' in options:
            timeout = options['timeout']
            if not isinstance(timeout, (int, float)) or timeout <= 0:
                raise ValidationError("Timeout must be a positive number")
            validated['timeout'] = timeout
        
        if 'threads' in options:
            threads = options['threads']
            if not isinstance(threads, int) or threads < 1:
                raise ValidationError("Threads must be a positive integer")
            validated['threads'] = threads
        
        if 'output_format' in options:
            output_format = options['output_format']
            valid_formats = ['json', 'xml', 'csv', 'txt']
            if output_format not in valid_formats:
                raise ValidationError(f"Output format must be one of: {valid_formats}")
            validated['output_format'] = output_format
        
        if 'scan_type' in options:
            scan_type = options['scan_type']
            valid_types = ['ping', 'port', 'full', 'web', 'vuln']
            if scan_type not in valid_types:
                raise ValidationError(f"Scan type must be one of: {valid_types}")
            validated['scan_type'] = scan_type
        
        # Add any other options without validation
        for key, value in options.items():
            if key not in validated:
                validated[key] = value
        
        self.options = validated
        return validated
    
    def parse_command_line(self, args: List[str]) -> Dict[str, Any]:
        """
        Parse command line arguments.
        
        Args:
            args: List of command line arguments
            
        Returns:
            Dictionary with parsed targets, ports, and options
            
        Raises:
            ValidationError: If arguments are invalid
        """
        result = {
            'targets': [],
            'ports': [],
            'options': {}
        }
        
        # Simple argument parsing
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg in ['-t', '--target']:
                if i + 1 >= len(args):
                    raise ValidationError(f"Missing value for {arg}")
                result['targets'] = self.parse_targets(args[i + 1])
                i += 2
            elif arg in ['-p', '--port']:
                if i + 1 >= len(args):
                    raise ValidationError(f"Missing value for {arg}")
                result['ports'] = self.parse_ports(args[i + 1])
                i += 2
            elif arg in ['--timeout']:
                if i + 1 >= len(args):
                    raise ValidationError(f"Missing value for {arg}")
                try:
                    result['options']['timeout'] = float(args[i + 1])
                except ValueError:
                    raise ValidationError("Timeout must be a number")
                i += 2
            elif arg in ['--threads']:
                if i + 1 >= len(args):
                    raise ValidationError(f"Missing value for {arg}")
                try:
                    result['options']['threads'] = int(args[i + 1])
                except ValueError:
                    raise ValidationError("Threads must be an integer")
                i += 2
            elif arg in ['-o', '--output']:
                if i + 1 >= len(args):
                    raise ValidationError(f"Missing value for {arg}")
                result['options']['output'] = args[i + 1]
                i += 2
            elif arg in ['--scan-type']:
                if i + 1 >= len(args):
                    raise ValidationError(f"Missing value for {arg}")
                result['options']['scan_type'] = args[i + 1]
                i += 2
            elif arg.startswith('--'):
                # Generic option handling
                key = arg[2:].replace('-', '_')
                if i + 1 < len(args) and not args[i + 1].startswith('-'):
                    result['options'][key] = args[i + 1]
                    i += 2
                else:
                    result['options'][key] = True
                    i += 1
            else:
                # Assume it's a target if no flag
                if not result['targets']:
                    result['targets'] = self.parse_targets(arg)
                i += 1
        
        return result
    
    def _parse_target_file(self, filename: str) -> List[str]:
        """
        Parse targets from a file.
        
        Args:
            filename: Path to file containing targets
            
        Returns:
            List of targets
            
        Raises:
            ValidationError: If file cannot be read or contains invalid targets
        """
        targets = []
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse each line as a target specification
                    if validate_ip(line):
                        targets.append(line)
                    elif validate_cidr(line):
                        targets.extend(cidr_to_ip_list(line))
                    elif self._is_hostname(line):
                        try:
                            import socket
                            ip = socket.gethostbyname(line)
                            targets.append(ip)
                        except socket.error:
                            # Skip unresolvable hostnames
                            continue
                    
        except FileNotFoundError:
            raise ValidationError(f"Target file not found: {filename}")
        except Exception as e:
            raise ValidationError(f"Error reading target file: {e}")
        
        return targets
    
    def _is_hostname(self, value: str) -> bool:
        """
        Check if a value appears to be a hostname.
        
        Args:
            value: Value to check
            
        Returns:
            True if value looks like a hostname
        """
        # Basic hostname validation
        if not value or len(value) > 255:
            return False
        
        # Remove trailing dot
        if value.endswith('.'):
            value = value[:-1]
        
        # Check each label
        labels = value.split('.')
        if not labels:
            return False
        
        for label in labels:
            if not label or len(label) > 63:
                return False
            
            # Label must start with alphanumeric
            if not label[0].isalnum():
                return False
            
            # Label must end with alphanumeric
            if not label[-1].isalnum():
                return False
            
            # Label can contain alphanumeric and hyphens
            if not all(char.isalnum() or char == '-' for char in label):
                return False
        
        return True
    
    def validate_scan_request(self, targets: List[str], ports: List[int], 
                            scan_type: str = "full") -> Tuple[bool, Optional[str]]:
        """
        Validate a complete scan request.
        
        Args:
            targets: List of target IPs
            ports: List of ports to scan
            scan_type: Type of scan to perform
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not targets:
            return False, "No targets specified"
        
        if scan_type in ['port', 'full', 'web'] and not ports:
            return False, f"No ports specified for {scan_type} scan"
        
        # Check for too many targets/ports
        if len(targets) > 1000:
            return False, "Too many targets (maximum 1000)"
        
        if len(ports) > 65535:
            return False, "Too many ports specified"
        
        return True, None