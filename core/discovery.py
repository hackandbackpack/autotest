"""
Discovery module for host and port scanning.
"""

import socket
import struct
import subprocess
import platform
import concurrent.futures
import time
from typing import List, Dict, Tuple, Optional, Set
from .utils import is_port_open, chunk_list
from .exceptions import DiscoveryError, NetworkError


class Discovery:
    """
    Network discovery functionality for AutoTest.
    
    Handles host discovery (ping) and port scanning.
    """
    
    def __init__(self, max_threads: int = 10, timeout: float = 1.0):
        """
        Initialize Discovery module.
        
        Args:
            max_threads: Maximum concurrent threads
            timeout: Default timeout for network operations
        """
        self.max_threads = max_threads
        self.timeout = timeout
        self.is_windows = platform.system() == "Windows"
    
    def ping_host(self, host: str, timeout: Optional[float] = None) -> bool:
        """
        Check if a host responds to ping.
        
        Args:
            host: Target host IP address
            timeout: Ping timeout (uses default if not specified)
            
        Returns:
            True if host responds, False otherwise
        """
        timeout = timeout or self.timeout
        
        # Platform-specific ping command
        if self.is_windows:
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]
        
        try:
            # Run ping command
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1  # Add buffer to subprocess timeout
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def discover_hosts(self, targets: List[str], 
                      progress_callback: Optional[callable] = None) -> List[str]:
        """
        Discover live hosts from a list of targets.
        
        Args:
            targets: List of target IP addresses
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of live host IP addresses
        """
        live_hosts = []
        total = len(targets)
        completed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all ping tasks
            future_to_host = {
                executor.submit(self.ping_host, host): host 
                for host in targets
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                completed += 1
                
                try:
                    if future.result():
                        live_hosts.append(host)
                except Exception:
                    # Skip hosts that cause errors
                    pass
                
                # Update progress
                if progress_callback:
                    progress_callback(completed, total, host)
        
        return sorted(live_hosts)
    
    def scan_port(self, host: str, port: int, timeout: Optional[float] = None) -> bool:
        """
        Check if a specific port is open on a host.
        
        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            
        Returns:
            True if port is open, False otherwise
        """
        return is_port_open(host, port, timeout or self.timeout)
    
    def scan_ports(self, host: str, ports: List[int], 
                  progress_callback: Optional[callable] = None) -> List[int]:
        """
        Scan multiple ports on a single host.
        
        Args:
            host: Target host
            ports: List of ports to scan
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of open ports
        """
        open_ports = []
        total = len(ports)
        completed = 0
        
        # Use more threads for port scanning
        port_threads = min(self.max_threads * 10, 100, len(ports))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=port_threads) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self.scan_port, host, port): port 
                for port in ports
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    # Skip ports that cause errors
                    pass
                
                # Update progress
                if progress_callback:
                    progress_callback(completed, total, f"{host}:{port}")
        
        return sorted(open_ports)
    
    def scan_network(self, targets: List[str], ports: List[int],
                    progress_callback: Optional[callable] = None) -> Dict[str, List[int]]:
        """
        Scan multiple hosts and ports.
        
        Args:
            targets: List of target hosts
            ports: List of ports to scan
            progress_callback: Optional callback for progress updates
            
        Returns:
            Dictionary mapping hosts to their open ports
        """
        results = {}
        
        # First, discover live hosts
        if progress_callback:
            progress_callback(0, len(targets), "Discovering live hosts...")
        
        live_hosts = self.discover_hosts(targets, progress_callback)
        
        if not live_hosts:
            return results
        
        # Then scan ports on live hosts
        total_scans = len(live_hosts) * len(ports)
        completed_scans = 0
        
        for i, host in enumerate(live_hosts):
            if progress_callback:
                progress_callback(
                    completed_scans, 
                    total_scans, 
                    f"Scanning ports on {host}"
                )
            
            # Define progress callback for port scanning
            def port_progress(done, total, info):
                nonlocal completed_scans
                if done == total:
                    completed_scans += total
                    if progress_callback:
                        progress_callback(completed_scans, total_scans, info)
            
            open_ports = self.scan_ports(host, ports, port_progress)
            if open_ports:
                results[host] = open_ports
        
        return results
    
    def quick_scan(self, targets: List[str], 
                  common_ports: Optional[List[int]] = None) -> Dict[str, List[int]]:
        """
        Perform a quick scan of common ports.
        
        Args:
            targets: List of target hosts
            common_ports: List of common ports (uses default if not provided)
            
        Returns:
            Dictionary mapping hosts to their open ports
        """
        if common_ports is None:
            # Default common ports
            common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
                          143, 443, 445, 993, 995, 1723, 3306, 3389, 
                          5900, 8080]
        
        return self.scan_network(targets, common_ports)
    
    def get_service_name(self, port: int) -> str:
        """
        Get the common service name for a port.
        
        Args:
            port: Port number
            
        Returns:
            Service name or "unknown"
        """
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        
        return common_services.get(port, "unknown")
    
    def identify_os(self, host: str, open_ports: List[int]) -> str:
        """
        Attempt to identify OS based on open ports and responses.
        
        Args:
            host: Target host
            open_ports: List of open ports
            
        Returns:
            Probable OS identification
        """
        # Simple OS fingerprinting based on common port combinations
        port_set = set(open_ports)
        
        # Windows indicators
        if {135, 139, 445}.issubset(port_set):
            if 3389 in port_set:
                return "Windows (with RDP)"
            return "Windows"
        
        # Linux/Unix indicators
        if 22 in port_set:
            if 111 in port_set:
                return "Linux/Unix (with RPC)"
            return "Linux/Unix"
        
        # Web server
        if {80, 443}.intersection(port_set):
            return "Web Server"
        
        # Database server
        if {3306, 5432, 1433}.intersection(port_set):
            return "Database Server"
        
        return "Unknown"
    
    def get_banner(self, host: str, port: int, timeout: Optional[float] = None) -> Optional[str]:
        """
        Attempt to grab a banner from a service.
        
        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            
        Returns:
            Banner string or None
        """
        timeout = timeout or self.timeout
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send a basic probe
            if port in [80, 8080, 443, 8443]:
                # HTTP probe
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                # Generic probe
                sock.send(b"\r\n")
            
            # Receive response
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def enhanced_scan(self, host: str, ports: List[int]) -> Dict[str, Any]:
        """
        Perform an enhanced scan with service detection.
        
        Args:
            host: Target host
            ports: List of ports to scan
            
        Returns:
            Detailed scan results with service information
        """
        results = {
            'host': host,
            'open_ports': [],
            'services': {},
            'os_guess': 'Unknown',
            'scan_time': time.time()
        }
        
        # Scan ports
        open_ports = self.scan_ports(host, ports)
        results['open_ports'] = open_ports
        
        # Get service information
        for port in open_ports:
            service_info = {
                'port': port,
                'service': self.get_service_name(port),
                'banner': None
            }
            
            # Try to grab banner
            banner = self.get_banner(host, port)
            if banner:
                service_info['banner'] = banner
            
            results['services'][port] = service_info
        
        # OS identification
        if open_ports:
            results['os_guess'] = self.identify_os(host, open_ports)
        
        return results