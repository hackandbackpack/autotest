"""
Utility functions for AutoTest framework.
"""

import re
import ipaddress
import os
import json
import time
from datetime import datetime
from typing import List, Tuple, Optional, Any, Dict
import socket
import struct


def validate_ip(ip: str) -> bool:
    """
    Validate if a string is a valid IP address.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """
    Validate if a port number is valid.
    
    Args:
        port: Port number to validate
        
    Returns:
        True if valid port (1-65535), False otherwise
    """
    return isinstance(port, int) and 1 <= port <= 65535


def validate_cidr(cidr: str) -> bool:
    """
    Validate if a string is a valid CIDR notation.
    
    Args:
        cidr: CIDR string to validate (e.g., "192.168.1.0/24")
        
    Returns:
        True if valid CIDR, False otherwise
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def parse_port_range(port_spec: str) -> List[int]:
    """
    Parse a port specification into a list of ports.
    
    Supports:
    - Single ports: "80"
    - Ranges: "80-443"
    - Lists: "80,443,8080"
    - Mixed: "80,443-445,8080"
    
    Args:
        port_spec: Port specification string
        
    Returns:
        List of port numbers
        
    Raises:
        ValueError: If port specification is invalid
    """
    ports = set()
    
    # Handle empty or None input
    if not port_spec:
        return []
    
    # Split by comma
    parts = port_spec.split(',')
    
    for part in parts:
        part = part.strip()
        
        # Check if it's a range
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start = int(start.strip())
                end = int(end.strip())
                
                if not (validate_port(start) and validate_port(end)):
                    raise ValueError(f"Invalid port range: {part}")
                
                if start > end:
                    start, end = end, start
                
                ports.update(range(start, end + 1))
            except ValueError as e:
                raise ValueError(f"Invalid port range: {part}") from e
        else:
            # Single port
            try:
                port = int(part)
                if not validate_port(port):
                    raise ValueError(f"Invalid port: {port}")
                ports.add(port)
            except ValueError as e:
                raise ValueError(f"Invalid port: {part}") from e
    
    return sorted(list(ports))


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is in a private range.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if IP is private, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def get_timestamp(format_string: str = "%Y-%m-%d_%H-%M-%S") -> str:
    """
    Get current timestamp as a formatted string.
    
    Args:
        format_string: strftime format string
        
    Returns:
        Formatted timestamp string
    """
    return datetime.now().strftime(format_string)


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds to a human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string (e.g., "1h 23m 45s")
    """
    if seconds < 1:
        return f"{seconds:.2f}s"
    
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")
    
    return " ".join(parts)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing/replacing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename safe for filesystem use
    """
    # Remove or replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext
    
    return filename or "unnamed"


def create_directory(path: str) -> None:
    """
    Create a directory if it doesn't exist.
    
    Args:
        path: Directory path to create
        
    Raises:
        OSError: If directory creation fails
    """
    os.makedirs(path, exist_ok=True)


def load_json_file(filepath: str) -> Dict[str, Any]:
    """
    Load JSON data from a file.
    
    Args:
        filepath: Path to JSON file
        
    Returns:
        Parsed JSON data
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file contains invalid JSON
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json_file(filepath: str, data: Dict[str, Any], indent: int = 2) -> None:
    """
    Save data to a JSON file.
    
    Args:
        filepath: Path to save JSON file
        data: Data to save
        indent: JSON indentation level
        
    Raises:
        OSError: If file write fails
    """
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)


def cidr_to_ip_list(cidr: str) -> List[str]:
    """
    Convert CIDR notation to a list of IP addresses.
    
    Args:
        cidr: CIDR notation string (e.g., "192.168.1.0/24")
        
    Returns:
        List of IP addresses in the range
        
    Raises:
        ValueError: If CIDR notation is invalid
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # Exclude network and broadcast addresses for /30 and larger
        if network.num_addresses > 2:
            return [str(ip) for ip in network.hosts()]
        else:
            return [str(ip) for ip in network]
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {cidr}") from e


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if a port is open on a host.
    
    Args:
        host: Target host
        port: Target port
        timeout: Connection timeout in seconds
        
    Returns:
        True if port is open, False otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    except socket.error:
        return False
    finally:
        sock.close()


def get_local_ip() -> str:
    """
    Get the local IP address of the machine.
    
    Returns:
        Local IP address string
    """
    try:
        # Create a socket and connect to a public DNS server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split a list into chunks of specified size.
    
    Args:
        lst: List to chunk
        chunk_size: Size of each chunk
        
    Returns:
        List of chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def merge_port_ranges(ports: List[int]) -> str:
    """
    Merge a list of ports into a compact range representation.
    
    Args:
        ports: List of port numbers
        
    Returns:
        Compact port specification string
    """
    if not ports:
        return ""
    
    sorted_ports = sorted(set(ports))
    ranges = []
    start = sorted_ports[0]
    end = sorted_ports[0]
    
    for port in sorted_ports[1:]:
        if port == end + 1:
            end = port
        else:
            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{end}")
            start = port
            end = port
    
    # Add the last range
    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{end}")
    
    return ",".join(ranges)