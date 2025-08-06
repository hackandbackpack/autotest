"""
DNSRecon enumeration plugin for AutoTest.
"""

import logging
import subprocess
import shutil
import time
import json
from typing import Dict, Any, List, Tuple
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="dns_recon")
class DNSReconPlugin(Plugin):
    """Plugin for DNS reconnaissance using DNSRecon."""
    
    def __init__(self):
        """Initialize the DNSRecon plugin."""
        super().__init__()
        self.name = "DNSRecon DNS Enumeration"
        self.version = "1.0.0"
        self.description = "DNS reconnaissance and enumeration using DNSRecon"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        self.required_tools = ["dnsrecon"]
        
        # DNS port
        self.dns_ports = [53]
    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port."""
        return (
            port == 53 or
            'dns' in service.lower()
        )
    
    def get_required_params(self) -> List[str]:
        """Get required parameters."""
        return ["target"]
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with defaults."""
        return {
            "port": 53,
            "timeout": 300,
            "output_dir": "output/dns",
            "record_types": "A,AAAA,CNAME,MX,NS,PTR,SOA,TXT",
            "wordlist": "/usr/share/dnsrecon/namelist.txt"
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate parameters."""
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        return True
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """Check if dnsrecon is available."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        if shutil.which("dnsrecon"):
            return True, {"dnsrecon": {"available": True, "path": shutil.which("dnsrecon")}}
        else:
            return False, {"dnsrecon": {
                "available": False, 
                "install_command": "apt install dnsrecon",
                "path": None
            }}
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute DNSRecon enumeration."""
        logger.info(f"DNSRecon plugin execute() called for {target} with kwargs: {kwargs}")
        
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Check if dnsrecon is available
        tool_available, tool_status = self.check_required_tools()
        if not tool_available:
            error_msg = "dnsrecon not found. Please install it first with: apt install dnsrecon"
            logger.error(error_msg)
            
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="dnsrecon",
                    target=target,
                    command="dnsrecon (NOT FOUND)",
                    output=error_msg,
                    service="DNS",
                    execution_time=0
                )
            
            return {
                "success": False,
                "error": error_msg,
                "install_command": "apt install dnsrecon"
            }
        
        results = {
            "success": True,
            "target": target,
            "service": "DNS",
            "findings": [],
            "errors": []
        }
        
        try:
            timeout = kwargs.get("timeout", 300)
            record_types = kwargs.get("record_types", "A,AAAA,CNAME,MX,NS,PTR,SOA,TXT")
            wordlist = kwargs.get("wordlist", "/usr/share/dnsrecon/namelist.txt")
            output_dir = Path(kwargs.get("output_dir", "output/dns"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting DNSRecon enumeration on {target}")
            
            # Prepare output files
            json_output = output_dir / f"dnsrecon_{target}.json"
            csv_output = output_dir / f"dnsrecon_{target}.csv"
            
            # Build DNSRecon command for standard enumeration
            cmd = [
                "dnsrecon",
                "-d", target,
                "-t", "std",  # Standard enumeration
                "-j", str(json_output),
                "-c", str(csv_output)
            ]
            
            # Run standard enumeration
            logger.info(f"Running command: {' '.join(cmd)}")
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            execution_time = time.time() - start_time
            
            # Combine output
            full_output = f"=== STANDARD DNS ENUMERATION ===\n"
            if result.stdout:
                full_output += result.stdout
            if result.stderr:
                full_output += f"\n\nSTDERR:\n{result.stderr}"
            full_output += f"\n\nReturn code: {result.returncode}\n\n"
            
            # Try zone transfer
            zt_cmd = [
                "dnsrecon",
                "-d", target,
                "-t", "axfr"  # Zone transfer
            ]
            
            try:
                logger.info("Attempting zone transfer...")
                zt_result = subprocess.run(
                    zt_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                full_output += f"=== ZONE TRANSFER ATTEMPT ===\n"
                if zt_result.stdout:
                    full_output += zt_result.stdout
                if zt_result.stderr:
                    full_output += f"\nSTDERR:\n{zt_result.stderr}"
                full_output += f"\nReturn code: {zt_result.returncode}\n\n"
                
            except subprocess.TimeoutExpired:
                full_output += "Zone transfer attempt timed out\n\n"
            except Exception as e:
                full_output += f"Zone transfer failed: {e}\n\n"
            
            # Try subdomain brute force if wordlist exists
            if Path(wordlist).exists():
                bf_cmd = [
                    "dnsrecon",
                    "-d", target,
                    "-t", "brt",  # Brute force
                    "-D", wordlist
                ]
                
                try:
                    logger.info("Starting subdomain brute force...")
                    bf_result = subprocess.run(
                        bf_cmd,
                        capture_output=True,
                        text=True,
                        timeout=min(timeout - execution_time, 180) if timeout > execution_time else 180
                    )
                    
                    full_output += f"=== SUBDOMAIN BRUTE FORCE ===\n"
                    if bf_result.stdout:
                        full_output += bf_result.stdout
                    if bf_result.stderr:
                        full_output += f"\nSTDERR:\n{bf_result.stderr}"
                    full_output += f"\nReturn code: {bf_result.returncode}\n\n"
                    
                except subprocess.TimeoutExpired:
                    full_output += "Subdomain brute force timed out\n\n"
                except Exception as e:
                    full_output += f"Subdomain brute force failed: {e}\n\n"
            
            # Always log to output manager
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="dnsrecon",
                    target=target,
                    command=' '.join(cmd) + " + zone transfer + brute force",
                    output=full_output,
                    service="DNS",
                    execution_time=time.time() - start_time
                )
            
            # Parse findings from JSON output
            if json_output.exists():
                findings = self._parse_dnsrecon_json(json_output, target)
                results["findings"].extend(findings)
                results["json_output"] = str(json_output)
            
            # Parse findings from stdout
            stdout_findings = self._parse_dnsrecon_stdout(full_output, target)
            results["findings"].extend(stdout_findings)
            
            results["command"] = ' '.join(cmd)
            results["execution_time"] = time.time() - start_time
            results["csv_output"] = str(csv_output)
            
        except subprocess.TimeoutExpired:
            error_msg = f"DNSRecon scan timed out after {timeout} seconds"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
            
        except Exception as e:
            error_msg = f"DNSRecon scan failed: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
        
        return results
    
    def _parse_dnsrecon_json(self, json_file: Path, target: str) -> List[Dict[str, Any]]:
        """Parse DNSRecon JSON output for findings."""
        findings = []
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                return findings
            
            for record in data:
                if not isinstance(record, dict):
                    continue
                
                record_type = record.get('type', '')
                name = record.get('name', '')
                address = record.get('address', '')
                
                # Check for interesting findings
                if record_type and name:
                    finding = {
                        'type': 'dns_record',
                        'severity': 'info',
                        'target': target,
                        'port': 53,
                        'title': f'DNS Record Found: {record_type}',
                        'description': f"{record_type} record: {name} -> {address}",
                        'service': 'DNS',
                        'details': {
                            'record_type': record_type,
                            'name': name,
                            'address': address
                        }
                    }
                    
                    # Adjust severity for sensitive records
                    if record_type in ['MX', 'NS', 'SOA']:
                        finding['severity'] = 'medium'
                    elif record_type == 'TXT':
                        finding['severity'] = 'medium'
                        # Check for sensitive TXT records
                        if any(sensitive in address.lower() for sensitive in [
                            'v=spf1', 'dmarc', 'dkim', 'google-site-verification'
                        ]):
                            finding['severity'] = 'high'
                    
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Failed to parse DNSRecon JSON: {e}")
        
        return findings
    
    def _parse_dnsrecon_stdout(self, output: str, target: str) -> List[Dict[str, Any]]:
        """Parse DNSRecon stdout for additional findings."""
        findings = []
        
        if not output:
            return findings
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Check for zone transfer success
                if 'zone transfer' in line.lower() and 'successful' in line.lower():
                    findings.append({
                        'type': 'zone_transfer',
                        'severity': 'critical',
                        'target': target,
                        'port': 53,
                        'title': 'DNS Zone Transfer Allowed',
                        'description': 'DNS server allows zone transfers (AXFR)',
                        'service': 'DNS',
                        'details': {
                            'vulnerability': 'zone_transfer_enabled',
                            'impact': 'Information disclosure of all DNS records'
                        }
                    })
                
                # Check for wildcard DNS
                if 'wildcard' in line.lower() and 'found' in line.lower():
                    findings.append({
                        'type': 'dns_wildcard',
                        'severity': 'medium',
                        'target': target,
                        'port': 53,
                        'title': 'DNS Wildcard Record Found',
                        'description': line,
                        'service': 'DNS',
                        'details': {
                            'finding': 'wildcard_dns',
                            'details': line
                        }
                    })
                
                # Check for subdomain discoveries
                if any(indicator in line for indicator in ['A ', 'AAAA ', 'CNAME ']):
                    # Extract subdomain from line
                    parts = line.split()
                    if len(parts) >= 3:
                        record_type = parts[0]
                        domain = parts[1] if len(parts) > 1 else ''
                        
                        if domain and domain != target and target in domain:
                            findings.append({
                                'type': 'subdomain_found',
                                'severity': 'info',
                                'target': target,
                                'port': 53,
                                'title': f'Subdomain Found: {domain}',
                                'description': line,
                                'service': 'DNS',
                                'details': {
                                    'subdomain': domain,
                                    'record_type': record_type,
                                    'parent_domain': target
                                }
                            })
        
        except Exception as e:
            logger.error(f"Failed to parse DNSRecon stdout: {e}")
        
        return findings