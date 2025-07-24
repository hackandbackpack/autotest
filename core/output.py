"""
Output management for AutoTest framework.
"""

import os
import logging
import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
import gzip
import zipfile
from .utils import sanitize_filename, create_directory, get_timestamp
from .exceptions import OutputError


class OutputManager:
    """
    Manages output generation and formatting for AutoTest.
    """
    
    def __init__(self, output_dir: str = "output", default_format: str = "json"):
        """
        Initialize OutputManager.
        
        Args:
            output_dir: Directory for output files
            default_format: Default output format
        """
        self.output_dir = output_dir
        self.default_format = default_format
        self.session_id = get_timestamp()
        
        # Create output directory
        create_directory(self.output_dir)
        
        # Use the output_dir directly as session_dir (no duplicate timestamp directory)
        self.session_dir = self.output_dir
        
        # Create subdirectories for better organization
        self.logs_dir = os.path.join(self.session_dir, "logs")
        self.services_dir = os.path.join(self.session_dir, "services")
        self.raw_dir = os.path.join(self.session_dir, "raw")
        self.reports_dir = os.path.join(self.session_dir, "reports")
        
        for directory in [self.logs_dir, self.services_dir, self.raw_dir, self.reports_dir]:
            create_directory(directory)
        
        # Initialize consolidated logs
        self.consolidated_log_path = os.path.join(self.logs_dir, "consolidated_tools.log")
        self.security_findings_path = os.path.join(self.reports_dir, "security_findings.txt")
        
        # Initialize consolidated log with header
        with open(self.consolidated_log_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("AutoTest Consolidated Tool Output Log\n")
            f.write(f"Session: {self.session_id}\n")
            f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
    
    def save_results(self, results: Dict[str, Any], filename: str,
                    format: Optional[str] = None, compress: bool = False) -> str:
        """
        Save results to a file.
        
        Args:
            results: Results dictionary to save
            filename: Output filename (without extension)
            format: Output format (json, xml, csv, txt)
            compress: Whether to compress the output
            
        Returns:
            Path to saved file
            
        Raises:
            OutputError: If save fails
        """
        format = format or self.default_format
        
        # Sanitize filename
        filename = sanitize_filename(filename)
        
        # Determine file extension
        ext = format
        if compress:
            ext += ".gz"
        
        # Save reports in the reports directory for better organization
        if format in ["txt", "json", "xml", "csv"] and ("report" in filename or "scan_results" in filename):
            filepath = os.path.join(self.reports_dir, f"{filename}.{ext}")
        else:
            filepath = os.path.join(self.raw_dir, f"{filename}.{ext}")
        
        try:
            # Format results
            if format == "json":
                content = self._format_json(results)
            elif format == "txt":
                content = self._format_txt(results)
            else:
                raise OutputError(f"Unsupported output format: {format}")
            
            # Save to file
            if compress:
                self._save_compressed(filepath, content)
            else:
                self._save_plain(filepath, content)
            
            return filepath
            
        except Exception as e:
            raise OutputError(f"Failed to save results: {e}")
    
    def save_raw_output(self, tool_name: str, output: str, 
                       target: Optional[str] = None) -> str:
        """
        Save raw tool output.
        
        Args:
            tool_name: Name of the tool
            output: Raw output text
            target: Optional target identifier
            
        Returns:
            Path to saved file
        """
        # Generate filename
        timestamp = get_timestamp("%Y%m%d_%H%M%S")
        if target:
            filename = f"{tool_name}_{sanitize_filename(target)}_{timestamp}.txt"
        else:
            filename = f"{tool_name}_{timestamp}.txt"
        
        filepath = os.path.join(self.raw_dir, filename)
        
        # Save output
        self._save_plain(filepath, output)
        
        return filepath
    
    def generate_report(self, results: Dict[str, Any], 
                       report_type: str = "summary") -> str:
        """
        Generate a formatted report.
        
        Args:
            results: Results to report on
            report_type: Type of report (summary, detailed, executive)
            
        Returns:
            Path to report file
        """
        if report_type == "summary":
            content = self._generate_summary_report(results)
        elif report_type == "detailed":
            content = self._generate_detailed_report(results)
        elif report_type == "executive":
            content = self._generate_executive_report(results)
        else:
            raise OutputError(f"Unknown report type: {report_type}")
        
        # Save report
        filename = f"report_{report_type}_{self.session_id}"
        filepath = self.save_results({"report": content}, filename, format="txt")
        
        return filepath
    
    def create_archive(self, archive_name: Optional[str] = None) -> str:
        """
        Create an archive of the session output.
        
        Args:
            archive_name: Name for the archive (uses session ID if not provided)
            
        Returns:
            Path to archive file
        """
        archive_name = archive_name or f"autotest_{self.session_id}"
        archive_path = os.path.join(self.output_dir, f"{archive_name}.zip")
        
        try:
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add all files from session directory
                for root, dirs, files in os.walk(self.session_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.output_dir)
                        zipf.write(file_path, arcname)
            
            return archive_path
            
        except Exception as e:
            raise OutputError(f"Failed to create archive: {e}")
    
    def _format_json(self, data: Dict[str, Any]) -> str:
        """Format data as JSON."""
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
    
    
    def _format_txt(self, data: Dict[str, Any]) -> str:
        """Format data as human-readable text."""
        lines = []
        lines.append("=" * 80)
        lines.append("AutoTest Results")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        self._format_txt_recursive(data, lines)
        
        return "\n".join(lines)
    
    def _format_txt_recursive(self, data: Any, lines: List[str], 
                            indent: int = 0) -> None:
        """Recursively format data as text."""
        prefix = "  " * indent
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    lines.append(f"{prefix}{key}:")
                    self._format_txt_recursive(value, lines, indent + 1)
                else:
                    lines.append(f"{prefix}{key}: {value}")
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    lines.append(f"{prefix}[{i}]:")
                    self._format_txt_recursive(item, lines, indent + 1)
                else:
                    lines.append(f"{prefix}- {item}")
        else:
            lines.append(f"{prefix}{data}")
    
    def _save_plain(self, filepath: str, content: str) -> None:
        """Save content to a plain text file."""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def _save_compressed(self, filepath: str, content: str) -> None:
        """Save content to a compressed file."""
        with gzip.open(filepath, 'wt', encoding='utf-8') as f:
            f.write(content)
    
    def _generate_summary_report(self, results: Dict[str, Any]) -> str:
        """Generate a summary report."""
        lines = []
        lines.append("SUMMARY REPORT")
        lines.append("=" * 50)
        
        # Extract key statistics
        if "discovery" in results:
            disc = results["discovery"]
            lines.append(f"Hosts scanned: {disc.get('total_hosts', 0)}")
            lines.append(f"Live hosts: {disc.get('live_hosts', 0)}")
            lines.append(f"Total ports scanned: {disc.get('total_ports', 0)}")
            lines.append(f"Open ports found: {disc.get('open_ports', 0)}")
        
        if "vulnerabilities" in results:
            vulns = results["vulnerabilities"]
            lines.append(f"\nVulnerabilities found: {len(vulns)}")
            
            # Count by severity
            severity_count = {}
            for vuln in vulns:
                severity = vuln.get("severity", "unknown")
                severity_count[severity] = severity_count.get(severity, 0) + 1
            
            for severity, count in sorted(severity_count.items()):
                lines.append(f"  {severity}: {count}")
        
        lines.append(f"\nScan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return "\n".join(lines)
    
    def _generate_detailed_report(self, results: Dict[str, Any]) -> str:
        """Generate a detailed report."""
        lines = []
        lines.append("DETAILED REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Host details
        if "hosts" in results:
            lines.append("HOST DETAILS")
            lines.append("-" * 40)
            
            for host, info in results["hosts"].items():
                lines.append(f"\nHost: {host}")
                
                if isinstance(info, dict):
                    if "ports" in info:
                        lines.append(f"  Open ports: {', '.join(map(str, info['ports']))}")
                    
                    if "os" in info:
                        lines.append(f"  OS: {info['os']}")
                    
                    if "services" in info:
                        lines.append("  Services:")
                        # services is a list of service names, not a dict
                        for service in info["services"]:
                            lines.append(f"    - {service}")
        
        # Vulnerability details
        if "vulnerabilities" in results:
            lines.append("\n\nVULNERABILITY DETAILS")
            lines.append("-" * 40)
            
            for vuln in results["vulnerabilities"]:
                lines.append(f"\n{vuln.get('title', 'Unknown vulnerability')}")
                lines.append(f"  Host: {vuln.get('host', 'N/A')}")
                lines.append(f"  Port: {vuln.get('port', 'N/A')}")
                lines.append(f"  Severity: {vuln.get('severity', 'N/A')}")
                
                if "description" in vuln:
                    lines.append(f"  Description: {vuln['description']}")
                
                if "recommendation" in vuln:
                    lines.append(f"  Recommendation: {vuln['recommendation']}")
        
        return "\n".join(lines)
    
    def _generate_executive_report(self, results: Dict[str, Any]) -> str:
        """Generate an executive summary report."""
        lines = []
        lines.append("EXECUTIVE SUMMARY")
        lines.append("=" * 50)
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
        lines.append("")
        
        lines.append("OVERVIEW")
        lines.append("-" * 30)
        lines.append("An automated security assessment was performed on the target network.")
        lines.append("")
        
        # Risk summary
        if "vulnerabilities" in results:
            vulns = results["vulnerabilities"]
            critical = sum(1 for v in vulns if v.get("severity") == "critical")
            high = sum(1 for v in vulns if v.get("severity") == "high")
            
            lines.append("RISK SUMMARY")
            lines.append("-" * 30)
            
            if critical > 0:
                lines.append(f"CRITICAL: {critical} critical vulnerabilities require immediate attention")
            if high > 0:
                lines.append(f"HIGH: {high} high-risk vulnerabilities should be addressed promptly")
            
            if critical == 0 and high == 0:
                lines.append("No critical or high-risk vulnerabilities were identified.")
        
        lines.append("")
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 30)
        lines.append("1. Review detailed report for specific vulnerability information")
        lines.append("2. Prioritize remediation based on risk severity")
        lines.append("3. Implement recommended security controls")
        lines.append("4. Schedule regular security assessments")
        
        return "\n".join(lines)
    
    def create_summary_log(self) -> str:
        """
        Create a summary log of the scanning session.
        
        Returns:
            Path to the summary log file
        """
        summary_lines = []
        summary_lines.append("AutoTest Session Summary")
        summary_lines.append("=" * 50)
        summary_lines.append(f"Session ID: {self.session_id}")
        summary_lines.append(f"Output Directory: {self.session_dir}")
        summary_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary_lines.append("")
        
        # List all generated files
        summary_lines.append("Generated Files:")
        summary_lines.append("-" * 30)
        
        for root, dirs, files in os.walk(self.session_dir):
            for file in sorted(files):
                rel_path = os.path.relpath(os.path.join(root, file), self.session_dir)
                file_size = os.path.getsize(os.path.join(root, file))
                summary_lines.append(f"  {rel_path} ({file_size} bytes)")
        
        summary_lines.append("")
        summary_lines.append("Session completed successfully.")
        
        # Save summary
        summary_content = "\n".join(summary_lines)
        summary_path = os.path.join(self.session_dir, "session_summary.txt")
        self._save_plain(summary_path, summary_content)
        
        return summary_path
    
    def generate_reports(self, results: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate essential reports only: JSON for programmatic access
        and security findings for human consumption.
        
        Args:
            results: Results dictionary to generate reports from
            
        Returns:
            Dictionary mapping format type to file path
        """
        generated = {}
        
        # Save raw JSON results for programmatic access
        try:
            json_path = self.save_results(results, "scan_results", format="json")
            generated['json'] = json_path
            logging.info(f"Generated json report: {json_path}")
        except Exception as e:
            logging.error(f"Failed to save JSON results: {e}")
        
        # Security findings are generated separately by the main application
        # No need for summary, detailed, or executive reports
        
        return generated
    
    def log_tool_execution(self, tool_name: str, target: str, command: str, 
                          output: str, service: Optional[str] = None,
                          execution_time: Optional[float] = None) -> None:
        """
        Log tool execution to consolidated log and service-specific log.
        
        Args:
            tool_name: Name of the tool executed
            target: Target host/port
            command: Command that was executed
            output: Tool output
            service: Service name (for service-specific logs)
            execution_time: Execution time in seconds
        """
        # Create log entry
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        separator = "-" * 80
        
        log_entry = f"\n{separator}\n"
        log_entry += f"Tool: {tool_name}\n"
        log_entry += f"Target: {target}\n"
        log_entry += f"Service: {service or 'Unknown'}\n"
        log_entry += f"Timestamp: {timestamp}\n"
        if execution_time:
            log_entry += f"Execution Time: {execution_time:.2f} seconds\n"
        log_entry += f"Command: {command}\n"
        log_entry += f"{separator}\n"
        log_entry += f"Output:\n{output}\n"
        log_entry += f"{separator}\n\n"
        
        # Append to consolidated log
        with open(self.consolidated_log_path, 'a', encoding='utf-8') as f:
            f.write(log_entry)
        
        # Also save to service-specific log if service is provided
        if service:
            service_log_path = os.path.join(self.services_dir, f"{sanitize_filename(service.lower())}_scan.log")
            
            # Initialize service log if it doesn't exist
            if not os.path.exists(service_log_path):
                with open(service_log_path, 'w', encoding='utf-8') as f:
                    f.write(f"{'=' * 80}\n")
                    f.write(f"{service} Service Scan Log\n")
                    f.write(f"Session: {self.session_id}\n")
                    f.write(f"{'=' * 80}\n\n")
            
            # Append to service log
            with open(service_log_path, 'a', encoding='utf-8') as f:
                f.write(log_entry)
    
    def save_security_findings(self, findings: List[Dict[str, Any]], 
                              update: bool = True) -> str:
        """
        Save security findings in a clean, copy-paste friendly format.
        Groups findings by severity and type, with intelligent deduplication.
        
        Args:
            findings: List of security findings
            update: Whether to append to existing findings or overwrite
            
        Returns:
            Path to security findings file
        """
        # Define severity order and colors for potential future use
        severity_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        
        # Group findings by severity and type
        findings_by_severity = {
            'critical': {},
            'high': {},
            'medium': {},
            'low': {},
            'info': {}
        }
        
        # Map finding types to cleaner titles
        type_title_map = {
            'self_signed_cert': 'Self-signed Certificate',
            'cert_expired': 'Expired Certificate',
            'cert_expiring': 'Certificate Expiring Soon',
            'cert_validation': 'Certificate Validation Failed',
            'weak_signature': 'Weak Certificate Signature',
            'weak_rsa': 'Weak RSA Key',
            'weak_ec': 'Weak EC Key',
            'weak_protocol': 'Weak TLS/SSL Protocol',
            'weak_cipher': 'Weak Cipher Suite',
            'medium_cipher': 'Medium Strength Cipher',
            'heartbleed': 'Heartbleed Vulnerability',
            'compression': 'TLS Compression Enabled',
            'ssl_vulnerability': 'SSL/TLS Vulnerability',
            'ssl_weakness': 'SSL/TLS Weakness',
            # SMB findings
            'smb_v1_enabled': 'SMB Version 1 Enabled',
            'smb_signing_not_enforced': 'SMB Signing Not Enforced',
            'smb_null_session': 'SMB Null Session',
            'smb_dangerous_shares': 'Administrative Shares Accessible',
            'ms17_010': 'MS17-010 (EternalBlue)',
            'smb_guest_access': 'SMB Guest Access Enabled',
            # RDP findings
            'rdp_critical_vulnerability': 'RDP Critical Vulnerability',
            'rdp_weak_configuration': 'Weak RDP Configuration',
            'rdp_admin_access': 'RDP Administrative Access',
            'rdp_service_detected': 'RDP Service Detected',
            # SNMP findings
            'snmp_community': 'SNMP Community String Found',
            'snmp_default_community': 'Default SNMP Community String',
            'snmp_weak_community': 'Weak SNMP Community String',
            # SSH findings
            'ssh_weak_kex': 'Weak SSH Key Exchange',
            'ssh_weak_cipher': 'Weak SSH Cipher',
            'ssh_weak_mac': 'Weak SSH MAC Algorithm',
            'ssh_vulnerability': 'SSH Vulnerability',
            'ssh_compression': 'SSH Compression Enabled'
        }
        
        # Special handling for certificate validation - deduplicate across trust stores
        cert_validation_findings = {}
        
        for finding in findings:
            finding_type = finding.get('type', 'unknown')
            severity = finding.get('severity', 'info').lower()
            
            # Ensure valid severity
            if severity not in findings_by_severity:
                severity = 'info'
            
            # Special handling for certificate validation to deduplicate
            if finding_type == 'cert_validation':
                target = finding.get('target', 'Unknown')
                port = finding.get('port', '')
                key = f"{target}:{port}" if port else target
                
                # Only keep one certificate validation finding per host:port
                if key not in cert_validation_findings:
                    cert_validation_findings[key] = finding
                continue
            
            # Get clean title
            clean_title = type_title_map.get(finding_type, finding.get('title', 'Unknown Issue'))
            
            # Initialize category if needed
            if clean_title not in findings_by_severity[severity]:
                findings_by_severity[severity][clean_title] = []
            
            # Create host entry
            target = finding.get('target', 'Unknown')
            port = finding.get('port', '')
            details = finding.get('details', {})
            
            host_entry = f"{target}"
            if port:
                host_entry += f":{port}"
            
            # Add additional context for certain finding types
            additional_info = ""
            
            # For SNMP community strings, use the community string as additional info
            if finding_type == 'snmp_community' and isinstance(details, dict):
                community = details.get('community', '')
                if community:
                    additional_info = community
            
            # For weak protocols, show which protocols
            elif finding_type == 'weak_protocol' and isinstance(details, dict):
                protocol = details.get('protocol', '')
                if protocol:
                    # Convert tls_1_0 to TLSv1.0 format
                    protocol_str = protocol.replace('_', '.').replace('tls.', 'TLSv').replace('ssl.', 'SSLv')
                    additional_info = protocol_str
            
            # For weak ciphers, show cipher names
            elif finding_type in ['weak_cipher', 'medium_cipher'] and isinstance(details, dict):
                cipher_info = details.get('cipher_suite', {})
                if isinstance(cipher_info, dict):
                    cipher_name = cipher_info.get('name', '')
                    if cipher_name:
                        additional_info = cipher_name
                elif isinstance(details, dict) and 'name' in details:
                    additional_info = details['name']
            
            # For weak signatures, show type
            elif finding_type == 'weak_signature' and isinstance(details, dict):
                sig_algorithm = details.get('signature_algorithm', '')
                if sig_algorithm:
                    additional_info = f"{sig_algorithm} Certificate Signature"
            
            # For weak RSA, show key size
            elif finding_type == 'weak_rsa' and isinstance(details, dict):
                key_size = details.get('key_size', '')
                if key_size:
                    additional_info = f"{key_size} bits RSA"
            
            # For weak EC, show curve info
            elif finding_type == 'weak_ec' and isinstance(details, dict):
                curve = details.get('curve', '')
                bits = details.get('bits', '')
                if bits:
                    additional_info = f"{bits} bits EC"
                elif curve:
                    additional_info = curve
            
            # Build the entry for this host
            entry = {'host': host_entry, 'info': additional_info}
            
            # Check if this exact host+info combo already exists
            exists = False
            for existing in findings_by_severity[severity][clean_title]:
                if existing['host'] == entry['host'] and existing['info'] == entry['info']:
                    exists = True
                    break
            
            if not exists:
                findings_by_severity[severity][clean_title].append(entry)
        
        # Now add the deduplicated certificate validation findings
        for cert_finding in cert_validation_findings.values():
            severity = cert_finding.get('severity', 'medium').lower()
            clean_title = 'Certificate Validation Failed'
            
            if clean_title not in findings_by_severity[severity]:
                findings_by_severity[severity][clean_title] = []
            
            target = cert_finding.get('target', 'Unknown')
            port = cert_finding.get('port', '')
            host_entry = f"{target}:{port}" if port else target
            
            findings_by_severity[severity][clean_title].append({
                'host': host_entry,
                'info': ''
            })
        
        # Create findings report
        report_lines = []
        
        if not update:
            report_lines.append("SECURITY FINDINGS REPORT")
            report_lines.append("=" * 60)
            report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report_lines.append("")
        
        # Output findings by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings_in_severity = findings_by_severity[severity]
            
            if not findings_in_severity:
                continue
            
            # Add severity header
            severity_headers = {
                'critical': 'CRITICAL FINDINGS',
                'high': 'HIGH RISK FINDINGS', 
                'medium': 'MEDIUM RISK FINDINGS',
                'low': 'LOW RISK FINDINGS',
                'info': 'INFORMATIONAL FINDINGS'
            }
            
            report_lines.append(severity_headers[severity])
            report_lines.append("-" * len(severity_headers[severity]))
            report_lines.append("")
            
            # Output each finding type within this severity
            for finding_title, hosts in sorted(findings_in_severity.items()):
                if hosts:
                    report_lines.append(f"  {finding_title}")
                    
                    # Group hosts by additional info
                    hosts_by_info = {}
                    for host_data in hosts:
                        info = host_data['info']
                        if info not in hosts_by_info:
                            hosts_by_info[info] = []
                        hosts_by_info[info].append(host_data['host'])
                    
                    # Output hosts
                    if len(hosts_by_info) == 1 and '' in hosts_by_info:
                        # No additional info - just list hosts
                        for host in sorted(hosts_by_info['']):
                            report_lines.append(f"    {host}")
                    else:
                        # Special handling for SNMP community strings
                        if finding_title == "SNMP Community String Found":
                            # Show community string first, then hosts
                            for info, host_list in sorted(hosts_by_info.items()):
                                if info:  # info contains the community string
                                    report_lines.append(f"    Community: {info}")
                                    for host in sorted(host_list):
                                        report_lines.append(f"      {host}")
                        else:
                            # Default: Group by additional info
                            for info, host_list in sorted(hosts_by_info.items()):
                                if info:
                                    # Show hosts with their additional info
                                    for host in sorted(host_list):
                                        report_lines.append(f"    {host} ({info})")
                                else:
                                    # Just the host
                                    for host in sorted(host_list):
                                        report_lines.append(f"    {host}")
                    
                    report_lines.append("")  # Empty line between finding types
            
            report_lines.append("")  # Empty line between severities
        
        # Save report
        mode = 'a' if update and os.path.exists(self.security_findings_path) else 'w'
        with open(self.security_findings_path, mode, encoding='utf-8') as f:
            f.write('\n'.join(report_lines) + '\n')
        
        return self.security_findings_path