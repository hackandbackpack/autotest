#!/usr/bin/env python3
"""
AutoTest - Automated Network Penetration Testing Framework

A modular tool for automating common network penetration testing tasks.
"""

import sys
import os
import logging
import signal
import threading
import time
from pathlib import Path
from typing import List, Optional, Dict, Any
import click
from rich.console import Console
from rich.logging import RichHandler

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__ if "__file__" in globals() else ".")))

from core.config import Config
from core.exceptions import AutoTestException
from core.input_parser import InputParser
from core.discovery import Discovery
from core.task_manager import TaskManager, Task, TaskStatus
from core.output import OutputManager
from core.utils import create_directory, get_timestamp, ToolChecker

# Import plugins
from plugins.services.smb import SMBPlugin
from plugins.services.rdp import RDPPlugin
from plugins.services.snmp import SNMPPlugin
from plugins.services.ssh import SSHPlugin
from plugins.services.ssl import SSLPlugin

# Import UI (optional - not available on Windows)
try:
    from ui.tui import AutoTestTUI
    TUI_AVAILABLE = True
except ImportError:
    TUI_AVAILABLE = False
    AutoTestTUI = None


# Setup logging
console = Console()


def setup_logging(log_level: str, log_file: Optional[Path] = None) -> None:
    """Setup logging configuration."""
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers to prevent duplicates
    root_logger.handlers.clear()
    
    # Console handler with rich formatting
    console_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False
    )
    console_handler.setLevel(numeric_level)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


class AutoTest:
    """Main AutoTest application class."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize AutoTest."""
        self.config = Config(config_path)
        self.config.validate()
        
        self.input_parser = InputParser()
        self.discovery = None
        self.task_manager = None
        self.output_manager = None
        self.plugins = []
        self.tui = None
        
        # Shutdown handling
        self.shutdown_event = threading.Event()
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logging.info("Shutdown signal received")
        self.shutdown()
    
    def load_plugins(self) -> None:
        """Load all available plugins."""
        logging.info("Loading plugins...")
        
        # Load service plugins
        try:
            # SMB plugin
            smb_plugin = SMBPlugin()
            self.plugins.append(smb_plugin)
            logging.info(f"Loaded plugin: SMB")
            
            # RDP plugin
            rdp_plugin = RDPPlugin()
            self.plugins.append(rdp_plugin)
            logging.info(f"Loaded plugin: RDP")
            
            # SNMP plugin
            snmp_plugin = SNMPPlugin()
            self.plugins.append(snmp_plugin)
            logging.info(f"Loaded plugin: SNMP")
            
            # SSH plugin
            ssh_plugin = SSHPlugin()
            self.plugins.append(ssh_plugin)
            logging.info(f"Loaded plugin: SSH")
            
            # SSL/TLS plugin
            ssl_plugin = SSLPlugin()
            self.plugins.append(ssl_plugin)
            logging.info(f"Loaded plugin: SSL/TLS")
            
        except Exception as e:
            logging.error(f"Failed to load plugins: {e}")
            raise
        
        logging.info(f"Loaded {len(self.plugins)} plugins")
    
    def execute_plugin_task(self, task: Task) -> Any:
        """Execute a task using the appropriate plugin."""
        # Find the plugin for this task
        plugin = None
        for p in self.plugins:
            if p.name == task.plugin_name:
                plugin = p
                break
        
        if not plugin:
            raise AutoTestException(f"No plugin found for task: {task.plugin_name}")
        
        # Check if plugin tools are available (unless skipped)
        if not getattr(plugin, 'skip_tool_check', False):
            tools_available, tool_status = plugin.check_required_tools()
            if not tools_available:
                missing_tools = plugin.get_missing_tools()
                error_msg = "Missing required tools:\n"
                for tool in missing_tools:
                    error_msg += f"  - {tool['name']}: {tool['install_command']}\n"
                raise AutoTestException(error_msg)
        
        # Execute the task using the plugin's execute method
        # Convert task parameters to kwargs format expected by plugin.execute()
        kwargs = {
            'port': task.port,
            'output_dir': self.output_manager.session_dir
        }
        # Add any additional task-specific parameters
        if hasattr(task, 'params') and task.params:
            kwargs.update(task.params)
        
        return plugin.execute(task.target, **kwargs)
    
    def _process_tasks(self) -> None:
        """Process tasks from the task manager queue."""
        import threading
        
        def worker():
            """Worker thread to process tasks."""
            while not self.shutdown_event.is_set():
                # Get pending tasks
                with self.task_manager.lock:
                    pending_tasks = [
                        t for t in self.task_manager.tasks.values()
                        if t.status == TaskStatus.PENDING and
                        self.task_manager._are_dependencies_met(t)
                    ]
                
                if not pending_tasks:
                    time.sleep(0.1)
                    continue
                
                # Process each pending task
                for task in pending_tasks:
                    if self.shutdown_event.is_set():
                        break
                    
                    try:
                        # Mark as running
                        with self.task_manager.lock:
                            task.status = TaskStatus.RUNNING
                            task.start_time = time.time()
                        
                        # Execute the task
                        result = self.execute_plugin_task(task)
                        
                        # Mark as completed
                        with self.task_manager.lock:
                            task.status = TaskStatus.COMPLETED
                            task.result = result
                            task.end_time = time.time()
                            self.task_manager.completed_tasks.append(task)
                    
                    except Exception as e:
                        # Mark as failed
                        with self.task_manager.lock:
                            task.status = TaskStatus.FAILED
                            task.error = e
                            task.end_time = time.time()
                            self.task_manager.failed_tasks.append(task)
                        logging.error(f"Task {task.name} failed: {e}")
        
        # Start worker threads
        num_workers = self.config.get('max_threads', 10)
        workers = []
        for _ in range(num_workers):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            workers.append(t)
    
    def run_scan(
        self,
        targets: List[str],
        ports: Optional[str] = None,
        no_tui: bool = False
    ) -> None:
        """Run the main scanning workflow."""
        start_time = get_timestamp()
        logging.info(f"Starting AutoTest scan at {start_time}")
        
        # Create output directory
        timestamp = get_timestamp()
        output_dir_name = f"autotest_scan_{timestamp}"
        output_base = self.config.get('general.output_dir', 'output')
        output_dir = Path(output_base) / output_dir_name
        create_directory(str(output_dir))
        logging.info(f"Output directory: {output_dir}")
        
        # Initialize output manager
        self.output_manager = OutputManager(str(output_dir))
        
        # Save configuration
        if hasattr(self.config, 'save_runtime_config'):
            self.config.save_runtime_config(str(output_dir))
        else:
            logging.warning("Config.save_runtime_config not available, skipping runtime config save")
        
        # Setup log file in output directory
        log_file = output_dir / "autotest.log"
        setup_logging(self.config.get('general.log_level', 'INFO'), log_file)
        
        try:
            # Phase 1: Discovery
            logging.info("Phase 1: Host and port discovery")
            self.discovery = Discovery(
                max_threads=self.config.get('max_threads', 10),
                timeout=self.config.get('discovery.ping_timeout', 1.0)
            )
            discovered_hosts = self.discovery.discover_hosts(targets, ports)
            
            if not discovered_hosts:
                logging.warning("No live hosts found")
                return
            
            # Export discovery results
            discovery_file = output_dir / "discovery_results.json"
            self.discovery.export_discovery_results(discovery_file)
            
            # Phase 2: Service Enumeration
            logging.info(f"Phase 2: Service enumeration on {len(discovered_hosts)} hosts")
            
            # Initialize task manager
            self.task_manager = TaskManager(max_workers=self.config.get('max_threads', 10))
            
            # Create tasks from discovery results
            self.task_manager.create_tasks_from_discovery(discovered_hosts, self.plugins)
            
            # Setup TUI if not disabled and available
            if not no_tui and TUI_AVAILABLE:
                try:
                    self.tui = AutoTestTUI()
                    tui_thread = threading.Thread(target=self.tui.run)
                    tui_thread.daemon = True
                    tui_thread.start()
                except Exception as e:
                    logging.warning(f"Failed to start TUI: {e}")
                    self.tui = None
            elif not no_tui and not TUI_AVAILABLE:
                logging.info("Terminal UI not available on this platform")
            
            # Start task execution
            self.task_manager.start()
            
            # Process tasks using the execute_plugin_task callback
            self._process_tasks()
            
            # Wait for completion
            logging.info("Waiting for tasks to complete...")
            completed = self.task_manager.wait_for_completion()
            
            if not completed:
                logging.warning("Scan timed out or was interrupted")
            
            # Phase 3: Reporting
            logging.info("Phase 3: Generating reports")
            self._generate_reports(output_dir)
            
        except KeyboardInterrupt:
            logging.info("Scan interrupted by user")
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            raise
        finally:
            # Cleanup
            self.shutdown()
            
            # Create summary
            if self.output_manager:
                summary_file = self.output_manager.create_summary_log()
                logging.info(f"Output summary: {summary_file}")
            
            end_time = get_timestamp()
            logging.info(f"Scan completed at {end_time}")
    
    def _generate_reports(self, output_dir: Path) -> None:
        """Generate final reports."""
        # Collect all results
        results = {
            'scan_info': {
                'start_time': self.task_manager.stats.get('start_time'),
                'end_time': self.task_manager.stats.get('end_time'),
                'output_directory': str(output_dir)
            },
            'summary': self.task_manager.get_progress(),
            'hosts': {}
        }
        
        # Organize results by host
        for task in self.task_manager.completed_tasks:
            host = task.target
            if host not in results['hosts']:
                results['hosts'][host] = {
                    'tasks': [],
                    'open_ports': set(),
                    'services': set()
                }
            
            task_result = {
                'port': task.port,
                'service': task.service,
                'tool': task.plugin_name,
                'status': task.status.value,
                'started_at': task.start_time,
                'completed_at': task.end_time,
                'result': task.result
            }
            
            results['hosts'][host]['tasks'].append(task_result)
            results['hosts'][host]['open_ports'].add(task.port)
            if task.service:
                results['hosts'][host]['services'].add(task.service)
        
        # Add failed tasks
        for task in self.task_manager.failed_tasks:
            host = task.target
            if host not in results['hosts']:
                results['hosts'][host] = {
                    'tasks': [],
                    'open_ports': set(),
                    'services': set()
                }
            
            task_result = {
                'port': task.port,
                'service': task.service,
                'tool': task.plugin_name,
                'status': task.status.value,
                'started_at': task.start_time,
                'completed_at': task.end_time,
                'error': task.error
            }
            
            results['hosts'][host]['tasks'].append(task_result)
        
        # Convert sets to lists for JSON serialization
        for host_data in results['hosts'].values():
            host_data['open_ports'] = sorted(list(host_data['open_ports']))
            host_data['services'] = sorted(list(host_data['services']))
        
        # Generate reports in configured formats
        generated_reports = self.output_manager.generate_reports(results)
        
        for format_type, report_path in generated_reports.items():
            logging.info(f"Generated {format_type} report: {report_path}")
    
    def shutdown(self) -> None:
        """Shutdown the application cleanly."""
        logging.info("Shutting down AutoTest...")
        
        if self.discovery:
            self.discovery.shutdown()
            
        if self.task_manager and self.task_manager.running:
            self.task_manager.stop()
        
        self.shutdown_event.set()


def _is_likely_file_path(target: str) -> bool:
    """
    Determine if a target string is likely a file path.
    
    Args:
        target: The target string to check
        
    Returns:
        True if the target appears to be a file path
    """
    # Check for absolute paths
    if target.startswith('/') or (len(target) > 2 and target[1:3] == ':\\'):
        return True
    
    # Check for relative paths
    if target.startswith('./') or target.startswith('../'):
        return True
    
    # Exclude URLs
    if target.startswith(('http://', 'https://', 'ftp://', 'file://')):
        return False
    
    # Check for path separators (but not in hostnames like example.com/path)
    if '/' in target or '\\' in target:
        # Additional check: if it contains path separators and ends with common file extensions
        lower_target = target.lower()
        file_extensions = ['.txt', '.lst', '.list', '.targets', '.hosts', '.ips']
        if any(lower_target.endswith(ext) for ext in file_extensions):
            return True
        # Or if it has multiple path components
        if target.count('/') > 1 or target.count('\\') > 1:
            return True
    
    # Check for common target file extensions even without path separators
    lower_target = target.lower()
    common_extensions = ['.txt', '.lst', '.list', '.targets', '.hosts', '.ips', '.scope']
    if any(lower_target.endswith(ext) for ext in common_extensions):
        return True
    
    return False


@click.command()
@click.argument('targets', nargs=-1, required=False)
@click.option('-c', '--config', help='Path to configuration file')
@click.option('-p', '--ports', help='Port specification (default: from config)')
@click.option('-o', '--output', help='Output directory (default: from config)')
@click.option('--tui', is_flag=True, help='Enable TUI progress display (experimental)')
@click.option('--log-level', default='INFO', 
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
              help='Logging level')
@click.option('-f', '--file', help='Read targets from file')
@click.option('--nmap-xml', help='Import targets from Nmap XML file')
@click.option('--masscan-json', help='Import targets from Masscan JSON file')
@click.option('--skip-tool-check', is_flag=True, help='Skip checking for required tools')
@click.option('--check-tools', is_flag=True, help='Check all required tools and exit')
def main(
    targets: tuple,
    config: Optional[str],
    ports: Optional[str],
    output: Optional[str],
    tui: bool,
    log_level: str,
    file: Optional[str],
    nmap_xml: Optional[str],
    masscan_json: Optional[str],
    skip_tool_check: bool,
    check_tools: bool
):
    """
    AutoTest - Automated Network Penetration Testing Framework
    
    Targets can be specified as:
    - IP addresses (192.168.1.1)
    - CIDR ranges (192.168.1.0/24)
    - Domains (example.com)
    - Multiple targets separated by spaces
    
    Examples:
        autotest 192.168.1.0/24
        autotest 10.0.0.1 10.0.0.2 10.0.0.3
        autotest -f targets.txt
        autotest --nmap-xml scan.xml
        autotest --masscan-json results.json
    
    Note: When using -f, --nmap-xml, or --masscan-json, command-line targets are optional.
    """
    # Setup initial logging
    setup_logging(log_level)
    
    try:
        # Initialize AutoTest
        app = AutoTest(config)
        
        # Override output directory if specified
        if output:
            app.config.config['general']['output_dir'] = output
        
        # Load plugins
        app.load_plugins()
        
        # Handle tool checking
        if check_tools:
            console.print("[bold]Checking required tools...[/bold]\n")
            all_tools = set()
            
            # Collect tools from all plugins
            for plugin in app.plugins:
                if hasattr(plugin, 'required_tools'):
                    all_tools.update(plugin.required_tools)
            
            # Add discovery tools
            all_tools.update(['nmap', 'masscan'])
            
            # Check all tools
            tool_status = ToolChecker.check_required_tools(list(all_tools))
            
            # Display results
            for tool_name, status in tool_status.items():
                if status['available']:
                    console.print(f"[+] {tool_name}: [green]Available[/green] at {status['path']}")
                else:
                    console.print(f"[-] {tool_name}: [red]Not found[/red]")
                    console.print(f"  Install with: [yellow]{status['install_command']}[/yellow]")
            
            # Summary
            available_count = sum(1 for s in tool_status.values() if s['available'])
            total_count = len(tool_status)
            console.print(f"\n[bold]Summary:[/bold] {available_count}/{total_count} tools available")
            
            # Exit after checking
            sys.exit(0 if available_count == total_count else 1)
        
        # Set skip tool check flag for plugins if needed
        if skip_tool_check:
            for plugin in app.plugins:
                if hasattr(plugin, 'skip_tool_check'):
                    plugin.skip_tool_check = True
        else:
            # Check for critical tools (masscan and nmap) unless skipping
            critical_tools = ['masscan', 'nmap']
            critical_status = ToolChecker.check_required_tools(critical_tools)
            missing_critical = []
            
            for tool, status in critical_status.items():
                if not status['available']:
                    missing_critical.append((tool, status['install_command']))
            
            if missing_critical:
                console.print("[red]Error:[/red] Critical tools missing for discovery phase:")
                for tool, install_cmd in missing_critical:
                    console.print(f"  [-] {tool}: [yellow]{install_cmd}[/yellow]")
                console.print("\nThese tools are required for network discovery.")
                console.print("Use --skip-tool-check to bypass this check (discovery may fail).")
                sys.exit(1)
        
        # Parse targets
        input_parser = InputParser()
        all_targets = []
        
        # Add command line targets with smart file detection
        if targets:
            for target in targets:
                # Check if this looks like a file path
                if _is_likely_file_path(target):
                    # Check if file exists
                    if os.path.isfile(target):
                        console.print(f"[yellow]Auto-detected file:[/yellow] {target}")
                        console.print("[dim]Tip: You can also use -f flag or @filename syntax[/dim]")
                        # Convert to @filename format for InputParser
                        file_targets = input_parser.parse_targets(f"@{target}")
                        all_targets.extend(file_targets)
                    else:
                        # File-like path but doesn't exist
                        console.print(f"[red]Error:[/red] '{target}' looks like a file path but doesn't exist")
                        console.print("[yellow]Tip:[/yellow] Use -f flag for files, or check the path")
                        sys.exit(1)
                else:
                    # Regular target (IP, CIDR, hostname)
                    all_targets.append(target)
        
        # Add targets from file
        if file:
            # parse_targets expects '@filename' format for files
            file_targets = input_parser.parse_targets(f"@{file}")
            all_targets.extend(file_targets)
        
        # Add targets from Nmap XML
        if nmap_xml:
            nmap_results = input_parser.parse_nmap_xml(Path(nmap_xml))
            all_targets.extend(nmap_results['hosts'].keys())
        
        # Add targets from Masscan JSON
        if masscan_json:
            masscan_results = input_parser.parse_masscan_json(Path(masscan_json))
            all_targets.extend(masscan_results['hosts'].keys())
        
        if not all_targets:
            console.print("[red]Error:[/red] No targets specified")
            sys.exit(1)
        
        # Process and validate targets
        processed_targets = []
        for target in all_targets:
            try:
                parsed = input_parser.parse_targets(target)
                processed_targets.extend(parsed)
            except Exception as e:
                error_msg = str(e)
                # Provide helpful error message for file-like paths
                if ("Invalid target specification" in error_msg or "Cannot resolve hostname" in error_msg) and _is_likely_file_path(target):
                    console.print(f"[red]Error:[/red] Failed to parse '{target}'")
                    console.print(f"[yellow]This looks like a file path.[/yellow] Did you mean to use:")
                    console.print(f"  - [green]python3 autotest.py -f {target}[/green]")
                    if os.path.isfile(target):
                        console.print(f"[dim]The file exists. Autotest will now try to read it.[/dim]")
                        # Try to parse as file
                        try:
                            file_targets = input_parser.parse_targets(f"@{target}")
                            processed_targets.extend(file_targets)
                            console.print(f"[green]Successfully loaded {len(file_targets)} targets from {target}[/green]")
                            continue
                        except Exception as file_e:
                            console.print(f"[red]Failed to read file: {file_e}[/red]")
                    else:
                        console.print(f"[dim]Note: File '{target}' does not exist[/dim]")
                    sys.exit(1)
                else:
                    logging.warning(f"Failed to parse target '{target}': {e}")
                    continue
        
        # Remove duplicates while preserving order
        seen = set()
        unique_targets = []
        for target in processed_targets:
            if target not in seen:
                seen.add(target)
                unique_targets.append(target)
        processed_targets = unique_targets
        
        console.print(f"[green]Starting scan of {len(processed_targets)} targets[/green]")
        
        # Run the scan (TUI is disabled by default unless --tui flag is used)
        app.run_scan(processed_targets, ports, no_tui=not tui)
        
    except AutoTestException as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
        logging.exception("Unexpected error")
        sys.exit(1)


if __name__ == '__main__':
    main()