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
import subprocess

# Dynamic plugin loading support
import importlib
import pkgutil

# TUI support removed for simplification


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
        
        # Shutdown handling
        self.shutdown_event = threading.Event()
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logging.info("Shutdown signal received")
        self.shutdown()
    
    def load_plugins(self) -> None:
        """Dynamically load all available plugins from the plugins directory."""
        logging.info("Loading plugins...")
        
        plugins_loaded = 0
        plugins_failed = []
        
        # Define plugin directories to search
        plugin_dirs = ['plugins.services', 'plugins.tools', 'plugins.exploits']
        
        for plugin_dir in plugin_dirs:
            try:
                # Import the package
                package = importlib.import_module(plugin_dir)
                package_path = Path(package.__file__).parent
                
                # Iterate through all modules in the package
                for _, module_name, is_pkg in pkgutil.iter_modules([str(package_path)]):
                    if is_pkg:
                        continue  # Skip sub-packages
                    
                    module_path = f"{plugin_dir}.{module_name}"
                    
                    try:
                        # Import the module
                        module = importlib.import_module(module_path)
                        
                        # Look for classes that inherit from Plugin base class
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            
                            # Check if it's a class and inherits from Plugin
                            if (hasattr(attr, '__bases__') and 
                                any('Plugin' in str(base) for base in attr.__bases__) and
                                attr_name.endswith('Plugin') and
                                attr_name not in ['Plugin', 'NetExecPlugin']):  # Exclude base classes
                                
                                try:
                                    # Instantiate the plugin
                                    plugin_instance = attr()
                                    plugin_instance.output_manager = self.output_manager
                                    self.plugins.append(plugin_instance)
                                    logging.info(f"Loaded plugin: {attr_name} from {module_path}")
                                    plugins_loaded += 1
                                except Exception as e:
                                    logging.warning(f"Failed to instantiate {attr_name}: {e}")
                                    plugins_failed.append(f"{attr_name}: {str(e)}")
                    
                    except ImportError as e:
                        logging.debug(f"Failed to import {module_path}: {e}")
                        # This is normal for modules that have unmet dependencies
                    except Exception as e:
                        logging.warning(f"Error loading plugin from {module_path}: {e}")
                        plugins_failed.append(f"{module_path}: {str(e)}")
            
            except ImportError:
                logging.debug(f"Plugin directory {plugin_dir} not found")
            except Exception as e:
                logging.error(f"Error scanning plugin directory {plugin_dir}: {e}")
        
        if plugins_failed:
            logging.warning(f"Failed to load {len(plugins_failed)} plugin(s): {', '.join(plugins_failed)}")
        
        if plugins_loaded == 0:
            logging.error("No plugins loaded!")
            raise AutoTestException("No plugins could be loaded")
        
        logging.info(f"Successfully loaded {plugins_loaded} plugin(s)")
    
    # Note: Plugin task execution is now handled within TaskManager
    # by providing a closure function when creating tasks
    
    def run_scan(
        self,
        targets: List[str],
        ports: Optional[str] = None
    ) -> None:
        """Run the main scanning workflow."""
        start_time = get_timestamp()
        logging.info(f"Starting AutoTest scan at {start_time}")
        
        # Create output directory
        timestamp = get_timestamp()
        output_dir_name = f"scan_{timestamp}"
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
            
            # Create tasks from discovery results with plugin executor
            # Pass the AutoTest instance so tasks can access execute_plugin_task
            self.task_manager.autotest_instance = self
            self.task_manager.auth_test_enabled = auth_test
            self.task_manager.create_tasks_from_discovery(discovered_hosts, self.plugins, ports)
            
            # TUI support removed for simplification
            
            # Start task execution
            self.task_manager.start()
            
            # Note: Task execution is handled by TaskManager's scheduler
            # which calls the function provided in each task
            
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
        
        # Collect all security findings from plugin results
        all_findings = []
        for host, host_data in results['hosts'].items():
            for task in host_data['tasks']:
                if task.get('result') and isinstance(task['result'], dict):
                    findings = task['result'].get('findings', [])
                    # Add host and port info to each finding
                    for finding in findings:
                        finding['target'] = host
                        finding['port'] = task.get('port', '')
                        finding['service'] = task.get('service', '')
                        all_findings.append(finding)
        
        # Generate security findings report if there are any findings
        if all_findings:
            findings_report_path = self.output_manager.save_security_findings(all_findings, update=False)
            logging.info(f"Generated security findings report: {findings_report_path}")
        
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
@click.option('--log-level', default='INFO', 
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
              help='Logging level')
@click.option('-f', '--file', help='Read targets from file')
@click.option('--nmap-xml', help='Import targets from Nmap XML file')
@click.option('--masscan-json', help='Import targets from Masscan JSON file')
@click.option('--skip-tool-check', is_flag=True, help='Skip checking for required tools')
@click.option('--check-tools', is_flag=True, help='Check all required tools and exit')
@click.option('--setup', is_flag=True, help='Run interactive setup to install missing tools')
@click.option('--auth-test', is_flag=True, help='Enable authentication testing (hydra, ncrack) - REQUIRES PROPER AUTHORIZATION')
def main(
    targets: tuple,
    config: Optional[str],
    ports: Optional[str],
    output: Optional[str],
    log_level: str,
    file: Optional[str],
    nmap_xml: Optional[str],
    masscan_json: Optional[str],
    skip_tool_check: bool,
    check_tools: bool,
    setup: bool,
    auth_test: bool
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
        autotest --auth-test 192.168.1.0/24  # Enable authentication testing
    
    WARNING: --auth-test enables brute force authentication attacks.
    Only use with explicit written authorization from system owners.
    
    Note: When using -f, --nmap-xml, or --masscan-json, command-line targets are optional.
    """
    # Setup initial logging
    setup_logging(log_level)
    
    try:
        # Initialize AutoTest
        app = AutoTest(config)
        
        # Override output directory if specified
        if output:
            app.config.set('output_dir', output)
        
        # Load plugins
        app.load_plugins()
        
        # Handle setup mode
        if setup:
            console.print("[bold]AutoTest Setup - Installing Required Tools[/bold]\n")
            
            # Load plugins to get their required tools
            app.load_plugins()
            
            all_tools = set()
            # Collect tools from all plugins
            for plugin in app.plugins:
                if hasattr(plugin, 'required_tools'):
                    all_tools.update(plugin.required_tools)
            
            # Add discovery tools
            all_tools.update(['nmap', 'masscan'])
            
            # Check all tools
            tool_status = ToolChecker.check_required_tools(list(all_tools))
            
            missing_tools = []
            for tool_name, status in tool_status.items():
                if not status['available']:
                    missing_tools.append((tool_name, status['install_command']))
                else:
                    console.print(f"[green]✓[/green] {tool_name} already installed")
            
            if not missing_tools:
                console.print("\n[green]All tools are already installed![/green]")
                sys.exit(0)
            
            console.print(f"\n[yellow]Found {len(missing_tools)} missing tool(s)[/yellow]")
            
            # Ask user if they want to install
            for tool_name, install_cmd in missing_tools:
                console.print(f"\nMissing: [red]{tool_name}[/red]")
                console.print(f"Install command: [cyan]{install_cmd}[/cyan]")
                
                if click.confirm(f"Install {tool_name}?"):
                    console.print(f"Installing {tool_name}...")
                    try:
                        # Run install command
                        result = subprocess.run(
                            install_cmd.split(),
                            capture_output=True,
                            text=True
                        )
                        
                        if result.returncode == 0:
                            console.print(f"[green]✓ Successfully installed {tool_name}[/green]")
                        else:
                            console.print(f"[red]✗ Failed to install {tool_name}[/red]")
                            if result.stderr:
                                console.print(f"Error: {result.stderr}")
                    except Exception as e:
                        console.print(f"[red]✗ Error installing {tool_name}: {e}[/red]")
                else:
                    console.print(f"[yellow]Skipped {tool_name}[/yellow]")
            
            # Final check
            console.print("\n[bold]Setup complete. Checking final status...[/bold]")
            tool_status = ToolChecker.check_required_tools(list(all_tools))
            
            still_missing = [tool for tool, status in tool_status.items() if not status['available']]
            if still_missing:
                console.print(f"\n[yellow]Warning: Some tools are still missing: {', '.join(still_missing)}[/yellow]")
                console.print("[dim]You may need to install these manually or add them to your PATH[/dim]")
            else:
                console.print("\n[green]All tools successfully installed![/green]")
            
            sys.exit(0)
        
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
        
        # Check for required tools unless skipping
        if not skip_tool_check:
            # Import and check tools
            try:
                from installation import check_tools
                all_tools_available, missing_tools = check_tools()
                
                if not all_tools_available:
                    console.print("[red]Error:[/red] Required tools are missing:")
                    for tool in missing_tools:
                        console.print(f"  [-] {tool}")
                    console.print("\n[yellow]Please run:[/yellow] python installation.py")
                    console.print("[dim]Or use --skip-tool-check to bypass this check (some features may not work)[/dim]")
                    sys.exit(1)
            except ImportError:
                console.print("[yellow]Warning:[/yellow] Could not import installation module for tool checking")
                console.print("[dim]Some tools may be missing. Run 'python installation.py' to set up tools.[/dim]")
        else:
            # Set skip tool check flag for plugins
            for plugin in app.plugins:
                if hasattr(plugin, 'skip_tool_check'):
                    plugin.skip_tool_check = True
        
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
        
        # Display port filter information prominently
        if ports:
            console.print(f"[yellow]Port filter active: Only scanning port(s) {ports}[/yellow]")
        
        # Run the scan
        app.run_scan(processed_targets, ports)
        
    except AutoTestException as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
        logging.exception("Unexpected error")
        sys.exit(1)


if __name__ == '__main__':
    main()