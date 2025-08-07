"""
Discovery module for host and port scanning.
"""

import socket
import struct
import subprocess
import platform
import concurrent.futures
import time
import logging
from typing import List, Dict, Tuple, Optional, Set, Any
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
        self._shutdown = False
    
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
            logging.debug(f"Ping timeout for host {host}")
            return False
        except Exception as e:
            logging.debug(f"Ping failed for host {host}: {e}")
            return False
    
    def discover_hosts(self, targets: List[str], ports: Optional[str] = None,
                      progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Discover live hosts and their open ports from a list of targets.
        
        Args:
            targets: List of target hosts (IPs or hostnames)
            ports: Port specification string (e.g., "22,80,443" or "1-1000")
            progress_callback: Optional callback for progress updates
            
        Returns:
            Dictionary of discovered hosts with their open ports and services
        """
        discovered_hosts = {}
        total = len(targets)
        completed = 0
        
        # Parse port specification
        if ports:
            port_list = self._parse_port_spec(ports)
            use_masscan = len(port_list) > 1000  # Use masscan for large port ranges
        else:
            # Scan all ports (1-65535) when no port range specified - use masscan for performance
            logging.warning("Full port range scan (1-65535) requested - this will generate significant network traffic")
            port_list = list(range(1, 65536))
            use_masscan = True
            
        # Memory usage estimation for scan planning
        if use_masscan:
            estimated_memory_mb = 150  # Masscan uses constant memory regardless of scale
            logging.info(f"Using masscan for {len(targets)} hosts × {len(port_list)} ports (est. memory: ~{estimated_memory_mb}MB)")
        else:
            # Threaded scanning: base memory + thread overhead + minimal socket buffers
            estimated_memory_mb = 100 + (self.max_threads * 8) + min(len(port_list) * 0.1, 50)
            if len(targets) * len(port_list) > 50000:  # Large scan threshold
                logging.warning(f"Large threaded scan: {len(targets)} hosts × {len(port_list)} ports")
                logging.warning(f"Estimated memory usage: ~{estimated_memory_mb:.0f}MB - consider using masscan for better performance")
        logging.info(f"Starting host discovery on {total} targets...")
        logging.info(f"Using {self.max_threads} concurrent threads")
        
        # Log port filter information
        if ports:
            # Format the port list for display
            if len(port_list) <= 10:
                port_display = ', '.join(map(str, port_list))
            else:
                # Show first 10 ports and indicate there are more
                port_display = ', '.join(map(str, port_list[:10])) + f'... ({len(port_list)} total)'
            logging.info(f"Port filter active: Only scanning port(s) [{port_display}]")
        else:
            logging.info(f"Scanning all ports: 1-65535 ({len(port_list)} total) - Using masscan for performance")
        
        # Progress tracking
        last_progress_update = time.time()
        progress_interval = 10  # Update every 10 seconds
        start_time = time.time()
        
        # First, do a ping sweep to find live hosts
        logging.info("Phase 1a: Ping sweep to identify live hosts...")
        live_hosts = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all ping tasks
            future_to_host = {
                executor.submit(self.ping_host, h): h for h in targets
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_host):
                if self._shutdown:
                    logging.info("Discovery cancelled by user")
                    # Cancel remaining futures
                    for f in future_to_host:
                        f.cancel()
                    return {}
                    
                host = future_to_host[future]
                completed += 1
                
                try:
                    if future.result():
                        live_hosts.append(host)
                except Exception as e:
                    logging.debug(f"Error processing host {host}: {e}")
                    # Skip hosts that cause errors
                
                # Update progress
                if progress_callback:
                    progress_callback(completed, total, host)
                
                # Log progress updates periodically
                current_time = time.time()
                if current_time - last_progress_update >= progress_interval:
                    percent_complete = (completed / total) * 100
                    logging.info(f"Ping sweep progress: {completed}/{total} hosts checked ({percent_complete:.1f}%) - {len(live_hosts)} hosts responding")
                    last_progress_update = current_time
        
        logging.info(f"Ping sweep complete: {len(live_hosts)} hosts responded to ping")
        
        # Phase 2: Port scan live hosts
        if live_hosts:
            if use_masscan:
                logging.info(f"Phase 1b: Port scanning {len(live_hosts)} live hosts on {len(port_list)} ports using masscan...")
                # Use masscan for large port ranges for better performance
                discovered = self._masscan_port_scan(live_hosts, port_list)
            else:
                logging.info(f"Phase 1b: Port scanning {len(live_hosts)} live hosts on {len(port_list)} ports...")
                
                # Reset for port scanning phase
                completed = 0
                total = len(live_hosts)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    # Submit port scan tasks for each live host
                    future_to_host = {
                        executor.submit(self.scan_ports, host, port_list): host 
                        for host in live_hosts
                    }
                    
                    # Process results as they complete
                    for future in concurrent.futures.as_completed(future_to_host):
                        if self._shutdown:
                            logging.info("Port scan cancelled by user")
                            # Cancel remaining futures
                            for f in future_to_host:
                                f.cancel()
                            break
                            
                        host = future_to_host[future]
                        completed += 1
                        
                        try:
                            open_ports = future.result()
                            if open_ports:
                                discovered_hosts[host] = {
                                    'ports': open_ports,
                                    'services': {}
                                }
                                
                                # Try to identify services
                                for port in open_ports:
                                    service = self.get_service_name(port)
                                    discovered_hosts[host]['services'][str(port)] = service
                                    
                                logging.info(f"Host {host}: Found {len(open_ports)} open ports: {', '.join(map(str, open_ports[:10]))}{'...' if len(open_ports) > 10 else ''}")
                        except Exception as e:
                            logging.debug(f"Error scanning {host}: {e}")
                        
                        # Log port scan progress
                        current_time = time.time()
                        if current_time - last_progress_update >= progress_interval:
                            percent_complete = (completed / total) * 100
                            logging.info(f"Port scan progress: {completed}/{total} hosts scanned ({percent_complete:.1f}%) - {len(discovered_hosts)} hosts with open ports")
                            last_progress_update = current_time
        
        # Store for export
        self._discovered_hosts = discovered_hosts
        self._total_hosts = len(targets)
        self._live_hosts_count = len(live_hosts)
        self._total_ports = len(port_list) * len(live_hosts)
        self._open_ports_count = sum(len(h['ports']) for h in discovered_hosts.values())
        
        # Final summary
        elapsed = time.time() - start_time
        logging.info(f"Discovery complete in {elapsed:.1f} seconds")
        logging.info(f"Results: {len(live_hosts)} hosts responded to ping, {len(discovered_hosts)} hosts have open ports")
        logging.info(f"Total open ports discovered: {self._open_ports_count}")
        
        return discovered_hosts
    
    def shutdown(self):
        """Signal shutdown to stop discovery and cancel operations."""
        logging.info("Discovery shutdown requested")
        self._shutdown = True
        
        # Additional cleanup could be added here if needed
        # For example, forcefully canceling any running subprocess operations
    
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
                executor.submit(self.scan_port, host, p): p for p in ports
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    logging.debug(f"Error checking port {port}: {e}")
                    # Skip ports that cause errors
                
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
            
        except Exception as e:
            logging.debug(f"Failed to identify service: {e}")
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
    
    def export_discovery_results(self, filepath: str) -> None:
        """
        Export discovery results to a JSON file.
        
        Args:
            filepath: Path to save the results
        """
        import json
        
        # Gather all discovery results
        results = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'scan_summary': {
                'total_hosts_scanned': getattr(self, '_total_hosts', 0),
                'live_hosts_found': getattr(self, '_live_hosts_count', 0),
                'total_ports_scanned': getattr(self, '_total_ports', 0),
                'open_ports_found': getattr(self, '_open_ports_count', 0)
            },
            'hosts': getattr(self, '_discovered_hosts', {}),
            'scan_configuration': {
                'max_threads': self.max_threads,
                'timeout': self.timeout
            }
        }
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
    
    def _parse_port_spec(self, port_spec: str) -> List[int]:
        """
        Parse a port specification string into a list of ports.
        
        Args:
            port_spec: Port specification (e.g., "22,80,443" or "1-1000")
            
        Returns:
            List of port numbers
        """
        ports = []
        
        # Split by comma
        for part in port_spec.split(','):
            part = part.strip()
            
            # Check for range
            if '-' in part:
                start, end = part.split('-', 1)
                try:
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    ports.extend(range(start_port, end_port + 1))
                except ValueError:
                    logging.debug(f"Invalid port range format: {part}")
                    continue
            else:
                # Single port
                try:
                    ports.append(int(part))
                except ValueError:
                    logging.debug(f"Invalid port range format: {part}")
                    continue
        
        # Remove duplicates and sort
        return sorted(list(set(ports)))
    
    def _masscan_port_scan(self, hosts: List[str], port_list: List[int]) -> Dict[str, Dict]:
        """
        Use masscan for efficient large-scale port scanning.
        
        Args:
            hosts: List of hosts to scan
            port_list: List of ports to scan
            
        Returns:
            Dictionary of discovered hosts with port information
        """
        import subprocess
        import json
        import tempfile
        import os
        from pathlib import Path
        
        discovered_hosts = {}
        
        try:
            # Create temporary files for masscan
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as hosts_file:
                hosts_file.write('\n'.join(hosts))
                hosts_file_path = hosts_file.name
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
                output_file_path = output_file.name
            
            # Build masscan command
            port_spec = ','.join(map(str, port_list))
            if len(port_spec) > 10000:  # If port list is very long, use range notation
                port_spec = f"1-65535"
            
            masscan_cmd = [
                'masscan',
                '-iL', hosts_file_path,
                '-p', port_spec,
                '--rate', '15000',  # User's preferred rate
                '-oJ', output_file_path,
                '--wait', '3',  # Wait for late packets
                '--open-only'  # Only report open ports
            ]
            
            logging.info(f"Running masscan: {' '.join(masscan_cmd[:6])}... (truncated)")
            
            # Run masscan
            result = subprocess.run(
                masscan_cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10-minute timeout
            )
            
            if result.returncode != 0:
                if "permission denied" in result.stderr.lower() or "need to sudo" in result.stderr.lower():
                    logging.warning("Masscan requires elevated privileges - falling back to threaded scanning")
                    logging.info("Hint: Run with sudo for masscan support, or use smaller port ranges for threaded scanning")
                else:
                    logging.error(f"Masscan failed: {result.stderr}")
                # Fall back to regular scanning
                logging.info("Falling back to regular port scanning...")
                return self._fallback_port_scan(hosts, port_list)
            
            # Parse masscan JSON output
            if os.path.exists(output_file_path) and os.path.getsize(output_file_path) > 0:
                with open(output_file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or not line.startswith('{'):
                            continue
                        
                        try:
                            record = json.loads(line)
                            if 'ip' in record and 'ports' in record:
                                ip = record['ip']
                                
                                if ip not in discovered_hosts:
                                    discovered_hosts[ip] = {
                                        'ports': [],
                                        'services': {}
                                    }
                                
                                for port_info in record['ports']:
                                    if 'port' in port_info:
                                        port = port_info['port']
                                        if port not in discovered_hosts[ip]['ports']:
                                            discovered_hosts[ip]['ports'].append(port)
                                            discovered_hosts[ip]['services'][str(port)] = self.get_service_name(port)
                                
                        except json.JSONDecodeError:
                            continue
            
            # Log results
            total_open_ports = sum(len(host_info['ports']) for host_info in discovered_hosts.values())
            logging.info(f"Masscan complete: {len(discovered_hosts)} hosts with open ports, {total_open_ports} total open ports")
            
        except subprocess.TimeoutExpired:
            logging.error("Masscan timeout - falling back to regular scanning")
            return self._fallback_port_scan(hosts, port_list)
        except Exception as e:
            logging.error(f"Masscan error: {e} - falling back to regular scanning")
            return self._fallback_port_scan(hosts, port_list)
        finally:
            # Cleanup temporary files
            try:
                if 'hosts_file_path' in locals():
                    os.unlink(hosts_file_path)
                if 'output_file_path' in locals():
                    os.unlink(output_file_path)
            except:
                pass
        
        return discovered_hosts
    
    def _fallback_port_scan(self, hosts: List[str], port_list: List[int]) -> Dict[str, Dict]:
        """
        Fallback to regular port scanning when masscan fails.
        
        Args:
            hosts: List of hosts to scan
            port_list: List of ports to scan
            
        Returns:
            Dictionary of discovered hosts with port information
        """
        discovered_hosts = {}
        completed = 0
        total = len(hosts)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_host = {
                executor.submit(self.scan_ports, host, port_list): host 
                for host in hosts
            }
            
            for future in concurrent.futures.as_completed(future_to_host):
                if self._shutdown:
                    break
                    
                host = future_to_host[future]
                completed += 1
                
                try:
                    open_ports = future.result()
                    if open_ports:
                        discovered_hosts[host] = {
                            'ports': open_ports,
                            'services': {}
                        }
                        
                        # Try to identify services
                        for port in open_ports:
                            service = self.get_service_name(port)
                            discovered_hosts[host]['services'][str(port)] = service
                            
                        logging.info(f"Host {host}: Found {len(open_ports)} open ports: {', '.join(map(str, open_ports[:10]))}{'...' if len(open_ports) > 10 else ''}")
                except Exception as e:
                    logging.debug(f"Error scanning {host}: {e}")
                
                # Progress logging
                if completed % 10 == 0 or completed == total:
                    percent = (completed / total) * 100
                    logging.info(f"Fallback scan progress: {completed}/{total} hosts ({percent:.1f}%)")
        
        return discovered_hosts