"""
Output management for AutoTest framework.
"""

import os
import logging
import json
import csv
import xml.etree.ElementTree as ET
from xml.dom import minidom
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
            elif format == "xml":
                content = self._format_xml(results)
            elif format == "csv":
                content = self._format_csv(results)
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
    
    def _format_xml(self, data: Dict[str, Any]) -> str:
        """Format data as XML."""
        root = ET.Element("autotest_results")
        root.set("timestamp", datetime.now().isoformat())
        
        self._dict_to_xml(data, root)
        
        # Pretty print XML
        rough_string = ET.tostring(root, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")
    
    def _dict_to_xml(self, data: Dict[str, Any], parent: ET.Element) -> None:
        """Convert dictionary to XML elements."""
        for key, value in data.items():
            # Sanitize key for XML
            key = key.replace(' ', '_').replace('-', '_')
            
            if isinstance(value, dict):
                elem = ET.SubElement(parent, key)
                self._dict_to_xml(value, elem)
            elif isinstance(value, list):
                list_elem = ET.SubElement(parent, key)
                for item in value:
                    if isinstance(item, dict):
                        item_elem = ET.SubElement(list_elem, "item")
                        self._dict_to_xml(item, item_elem)
                    else:
                        item_elem = ET.SubElement(list_elem, "item")
                        item_elem.text = str(item)
            else:
                elem = ET.SubElement(parent, key)
                elem.text = str(value)
    
    def _format_csv(self, data: Dict[str, Any]) -> str:
        """Format data as CSV."""
        # For CSV, we need to flatten the data structure
        rows = []
        
        # Handle different data structures
        if "hosts" in data:
            # Network scan results
            for host, info in data["hosts"].items():
                if isinstance(info, dict) and "ports" in info:
                    for port in info["ports"]:
                        rows.append({
                            "host": host,
                            "port": port,
                            "service": info.get("services", {}).get(str(port), "unknown")
                        })
                else:
                    rows.append({"host": host, "info": str(info)})
        else:
            # Generic data - flatten it
            rows = [self._flatten_dict(data)]
        
        if not rows:
            return ""
        
        # Write CSV
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
        
        return output.getvalue()
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', 
                     sep: str = '.') -> Dict[str, Any]:
        """Flatten a nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, ', '.join(map(str, v))))
            else:
                items.append((new_key, v))
        return dict(items)
    
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
        Generate reports in multiple formats.
        
        Args:
            results: Results dictionary to generate reports from
            
        Returns:
            Dictionary mapping format type to file path
        """
        generated = {}
        
        # Generate different report types
        report_types = ['summary', 'detailed']
        
        for report_type in report_types:
            try:
                report_path = self.generate_report(results, report_type)
                generated[report_type] = report_path
            except Exception as e:
                logging.error(f"Failed to generate {report_type} report: {e}")
        
        # Also save raw JSON results
        try:
            json_path = self.save_results(results, "scan_results", format="json")
            generated['json'] = json_path
        except Exception as e:
            logging.error(f"Failed to save JSON results: {e}")
        
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
        Save security findings to a dedicated summary file.
        Groups findings by vulnerability type and shows all affected hosts.
        
        Args:
            findings: List of security findings
            update: Whether to append to existing findings or overwrite
            
        Returns:
            Path to security findings file
        """
        # Group findings by type and title
        findings_by_type = {}
        for finding in findings:
            # Create a key based on type and title
            finding_type = finding.get('type', 'unknown')
            finding_title = finding.get('title', 'Unknown Issue')
            severity = finding.get('severity', 'info')
            
            key = (finding_type, finding_title, severity)
            
            if key not in findings_by_type:
                findings_by_type[key] = {
                    'type': finding_type,
                    'title': finding_title,
                    'severity': severity,
                    'description': finding.get('description', ''),
                    'recommendation': finding.get('recommendation', ''),
                    'affected_hosts': []
                }
            
            # Add the affected host
            target = finding.get('target', 'Unknown')
            port = finding.get('port', '')
            service = finding.get('service', '')
            details = finding.get('details', {})
            
            host_info = {
                'host': target,
                'port': port,
                'service': service,
                'details': details
            }
            
            findings_by_type[key]['affected_hosts'].append(host_info)
        
        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(findings_by_type.items(), 
                               key=lambda x: (severity_order.get(x[0][2], 5), x[0][1]))
        
        # Create findings report
        report_lines = []
        
        if not update:
            report_lines.append("=" * 80)
            report_lines.append("SECURITY FINDINGS SUMMARY")
            report_lines.append(f"Session: {self.session_id}")
            report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report_lines.append("=" * 80)
            report_lines.append("")
        
        # Count findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for key, _ in sorted_findings:
            severity_counts[key[2]] = severity_counts.get(key[2], 0) + 1
        
        # Summary statistics
        report_lines.append("FINDINGS OVERVIEW:")
        report_lines.append(f"  Critical: {severity_counts['critical']} issues")
        report_lines.append(f"  High:     {severity_counts['high']} issues")
        report_lines.append(f"  Medium:   {severity_counts['medium']} issues")
        report_lines.append(f"  Low:      {severity_counts['low']} issues")
        report_lines.append(f"  Info:     {severity_counts['info']} issues")
        report_lines.append(f"  Total:    {len(sorted_findings)} unique issues")
        report_lines.append("")
        
        # Detailed findings grouped by type
        current_severity = None
        for (finding_type, finding_title, severity), finding_data in sorted_findings:
            # Add severity header if changed
            if severity != current_severity:
                report_lines.append("=" * 80)
                report_lines.append(f"{severity.upper()} SEVERITY FINDINGS")
                report_lines.append("=" * 80)
                report_lines.append("")
                current_severity = severity
            
            # Finding header
            report_lines.append(f"[{severity.upper()}] {finding_title}")
            report_lines.append(f"Type: {finding_type}")
            
            if finding_data['description']:
                report_lines.append(f"Description: {finding_data['description']}")
            
            if finding_data['recommendation']:
                report_lines.append(f"Recommendation: {finding_data['recommendation']}")
            
            # Affected hosts
            report_lines.append(f"\nAffected Hosts ({len(finding_data['affected_hosts'])} total):")
            
            # Group hosts by similar details for cleaner output
            for host_info in finding_data['affected_hosts']:
                host_str = f"  - {host_info['host']}"
                if host_info['port']:
                    host_str += f":{host_info['port']}"
                if host_info['service']:
                    host_str += f" ({host_info['service']})"
                report_lines.append(host_str)
                
                # Show relevant details (but keep it concise)
                if host_info['details'] and isinstance(host_info['details'], dict):
                    # Only show key details, not entire objects
                    important_keys = ['cipher_suite', 'protocol', 'algorithm', 'key_size', 
                                    'error_message', 'version', 'name']
                    for key in important_keys:
                        if key in host_info['details']:
                            report_lines.append(f"    • {key}: {host_info['details'][key]}")
            
            report_lines.append("")  # Empty line between findings
        
        report_lines.append("")
        report_lines.append("=" * 80)
        report_lines.append("END OF SECURITY FINDINGS SUMMARY")
        report_lines.append("=" * 80)
        
        # Save report
        mode = 'a' if update and os.path.exists(self.security_findings_path) else 'w'
        with open(self.security_findings_path, mode, encoding='utf-8') as f:
            f.write('\n'.join(report_lines) + '\n\n')
        
        return self.security_findings_path