#!/usr/bin/env python3
"""
AutoTest Security Tools Installation & Setup
Linux-only security testing framework installation.

NOTE: AutoTest is designed for Linux penetration testing environments only.

This comprehensive installer:
1. Verifies Linux system compatibility 
2. Checks for required tools and prerequisites
3. Installs missing tools via multiple methods:
   - Linux package managers (apt, yum, dnf)
   - Python packages with externally-managed environment handling
   - Source compilation with fallback options
4. Handles modern Python environment restrictions (PEP 668)
5. Provides interactive and automated installation modes
6. Configures tool paths and system integration

Usage:
  python3 installation.py              # Interactive installation
  python3 installation.py --auto      # Automatic installation (no prompts)
  python3 installation.py --check     # Check tools only (no installation)
"""

import os
import sys
import subprocess
import json
import shutil
import time
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Comprehensive tool definitions with priorities and descriptions
TOOLS = {
    # Discovery tools (High Priority)
    "nmap": {
        "description": "Network discovery and security auditing",
        "install": "sudo apt-get update && sudo apt-get install -y nmap || sudo yum install -y nmap || sudo dnf install -y nmap",
        "check_command": ["nmap", "--version"],
        "type": "binary",
        "priority": "high",
        "category": "discovery"
    },
    "masscan": {
        "description": "Fast port scanner",
        "install": "sudo apt-get update && sudo apt-get install -y masscan || (git clone https://github.com/robertdavidgraham/masscan.git /tmp/masscan && cd /tmp/masscan && make && sudo make install)",
        "check_command": ["masscan", "--version"],
        "type": "binary", 
        "priority": "high",
        "category": "discovery"
    },
    
    # Web security tools (Medium Priority)
    "nikto": {
        "description": "Web server vulnerability scanner",
        "install": "sudo apt-get update && sudo apt-get install -y nikto || (git clone https://github.com/sullo/nikto.git /opt/nikto && sudo ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto)",
        "check_command": ["nikto", "-Version"],
        "type": "binary",
        "priority": "medium",
        "category": "web"
    },
    "gobuster": {
        "description": "Directory and file brute-forcer",
        "install": "sudo apt-get update && sudo apt-get install -y gobuster || go install github.com/OJ/gobuster/v3@latest",
        "check_command": ["gobuster", "version"],
        "type": "binary",
        "priority": "medium",
        "category": "web"
    },
    "whatweb": {
        "description": "Web application fingerprinter",
        "install": "sudo apt-get update && sudo apt-get install -y whatweb || (sudo apt-get install -y ruby-dev && gem install whatweb)",
        "check_command": ["whatweb", "--version"],
        "type": "binary",
        "priority": "medium",
        "category": "web"
    },
    
    # DNS tools (Medium Priority)
    "dnsrecon": {
        "description": "DNS enumeration and reconnaissance",
        "install": "sudo apt-get update && sudo apt-get install -y dnsrecon || pip3 install dnsrecon",
        "check_command": ["dnsrecon", "--help"],
        "python_module": "dnsrecon",
        "type": "python",
        "priority": "medium",
        "category": "dns"
    },
    "dig": {
        "description": "DNS lookup utility",
        "install": "sudo apt-get update && sudo apt-get install -y dnsutils || sudo yum install -y bind-utils || sudo dnf install -y bind-utils",
        "check_command": ["dig", "-v"],
        "type": "binary",
        "priority": "high",
        "category": "dns"
    },
    
    # SSH tools (Medium Priority)
    "ssh-audit": {
        "description": "SSH server security auditing tool",
        "install": "pip3 install ssh-audit",
        "check_command": ["ssh-audit", "--help"],
        "python_module": "ssh_audit",
        "type": "python",
        "priority": "medium",
        "category": "ssh"
    },
    
    # SSL/TLS tools (Medium/Low Priority)
    "testssl.sh": {
        "description": "Comprehensive SSL/TLS testing suite",
        "install": "sudo git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh || (git clone https://github.com/drwetter/testssl.sh.git ~/testssl.sh && mkdir -p ~/.local/bin && ln -sf ~/testssl.sh/testssl.sh ~/.local/bin/testssl.sh)",
        "check_command": ["testssl.sh", "--version"],
        "type": "script",
        "priority": "medium",
        "category": "ssl"
    },
    "sslyze": {
        "description": "SSL/TLS configuration analyzer",
        "install": "pip3 install sslyze",
        "check_command": ["sslyze", "--help"],
        "python_module": "sslyze",
        "type": "python",
        "priority": "low",
        "category": "ssl"
    },
    
    # RPC tools (Low Priority)
    "rpcinfo": {
        "description": "RPC service enumeration tool",
        "install": "sudo apt-get update && sudo apt-get install -y rpcbind nfs-common || sudo yum install -y rpcbind || sudo dnf install -y rpcbind",
        "check_command": ["rpcinfo"],
        "type": "binary",
        "priority": "low",
        "category": "rpc"
    },
    
    # SMB/NetBIOS tools (Medium Priority)
    "netexec": {
        "description": "Network execution and credential testing tool",
        "install": "pip3 install netexec",
        "check_command": ["netexec", "--help"],
        "python_module": "netexec",
        "type": "python",
        "priority": "medium",
        "category": "smb",
        "requires_auth": True
    },
    
    # Authentication testing tools (High Priority)
    "hydra": {
        "description": "Network authentication brute-forcer",
        "install": "sudo apt-get update && sudo apt-get install -y hydra || sudo yum install -y hydra || sudo dnf install -y hydra",
        "check_command": ["hydra"],  # hydra shows help without any flags
        "type": "binary",
        "priority": "high",
        "category": "auth",
        "requires_auth": True
    },
    "onesixtyone": {
        "description": "Fast SNMP scanner",
        "install": "sudo apt-get update && sudo apt-get install -y onesixtyone || (git clone https://github.com/trailofbits/onesixtyone.git /tmp/onesixtyone && cd /tmp/onesixtyone && make && sudo make install)",
        "check_command": ["onesixtyone"],
        "type": "binary",
        "priority": "low",
        "category": "snmp"
    }
}


def get_python_scripts_dir() -> Optional[Path]:
    """Get the bin directory where pip installs executables on Linux."""
    try:
        import site
        user_base = site.USER_BASE
        scripts_dir = Path(user_base) / "bin"
        
        if scripts_dir.exists():
            return scripts_dir
    except:
        pass
    
    # Check common locations
    common_paths = [
        Path.home() / ".local" / "bin",
        Path("/usr/local/bin"),
        Path("/usr/bin")
    ]
    
    for path in common_paths:
        if path.exists():
            return path
    
    return None


def check_linux_system():
    """Verify we're running on a Linux system."""
    if os.name != 'posix':
        print("[-] ERROR: AutoTest requires a Linux system.")
        print("    Windows and macOS are not supported.")
        sys.exit(1)


def check_tool(tool_name: str, tool_info: Dict) -> Tuple[bool, Optional[str]]:
    """Check if a tool is available and return its path."""
    # Check if it's a Python module first
    if tool_info.get("type") == "python" and "python_module" in tool_info:
        try:
            result = subprocess.run(
                [sys.executable, "-m", tool_info["python_module"], "--help"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return True, f"{sys.executable} -m {tool_info['python_module']}"
        except:
            pass
    
    # Check normal command
    check_cmd = tool_info.get("check_command", [tool_name])
    
    # Try regular command
    try:
        result = subprocess.run(
            check_cmd,
            capture_output=True,
            timeout=5
        )
        # Accept any exit code - some tools return non-zero for help
        path = shutil.which(check_cmd[0])
        if path:
            return True, path
    except:
        pass
    
    # Check common Linux binary locations
    common_paths = [
        f"/usr/bin/{tool_name}",
        f"/usr/local/bin/{tool_name}",
        f"/opt/{tool_name}/bin/{tool_name}",
        f"/opt/{tool_name}/{tool_name}",
        f"/usr/sbin/{tool_name}"
    ]
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return True, path
    
    return False, None


def install_tool(tool_name: str, tool_info: Dict) -> bool:
    """Install a tool on Linux with fallback options for Python packages."""
    print(f"\n[*] Installing {tool_name}...")
    
    install_cmd = tool_info.get("install")
    
    if not install_cmd:
        print(f"[-] No install command available for {tool_name}")
        return False
    
    # Replace pip with pip3 for better compatibility
    if "pip install" in install_cmd:
        install_cmd = install_cmd.replace("pip install", "pip3 install")
    
    print(f"    Running: {install_cmd}")
    
    try:
        # Use shell execution for complex commands with && and ||
        result = subprocess.run(install_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] Successfully installed {tool_name}")
            return True
        else:
            # Handle externally-managed Python environment
            if "externally-managed-environment" in result.stderr and "pip3 install" in install_cmd:
                return _handle_python_package_install(tool_name, tool_info)
            
            # Handle permission denied for git clone to /opt
            elif "Permission denied" in result.stderr and "/opt/" in install_cmd:
                return _handle_opt_install(tool_name, install_cmd)
            
            else:
                print(f"[-] Failed to install {tool_name}")
                if result.stderr:
                    print(f"    Error: {result.stderr}")
                return False
            
    except Exception as e:
        print(f"[-] Error installing {tool_name}: {e}")
        return False


def _handle_python_package_install(tool_name: str, tool_info: Dict) -> bool:
    """Handle Python package installation with externally-managed environment."""
    print(f"[!] System Python is externally managed. Trying alternatives...")
    
    # Try system package first
    system_package = f"python3-{tool_name.replace('_', '-')}"
    print(f"    Trying system package: {system_package}")
    
    try:
        result = subprocess.run(
            f"sudo apt-get update && sudo apt-get install -y {system_package}",
            shell=True, capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[+] Successfully installed {tool_name} via system package")
            return True
    except:
        pass
    
    # Try pipx
    print(f"    Trying pipx...")
    try:
        # First ensure pipx is installed
        pipx_check = subprocess.run(["pipx", "--version"], capture_output=True)
        if pipx_check.returncode != 0:
            print(f"    Installing pipx...")
            subprocess.run("sudo apt-get install -y pipx", shell=True, capture_output=True)
        
        result = subprocess.run(f"pipx install {tool_name}", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] Successfully installed {tool_name} via pipx")
            return True
    except:
        pass
    
    # Try --user installation with --break-system-packages
    print(f"    Trying user installation with --break-system-packages...")
    try:
        result = subprocess.run(
            f"pip3 install --user --break-system-packages {tool_name}",
            shell=True, capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[+] Successfully installed {tool_name} with --user --break-system-packages")
            return True
    except:
        pass
    
    print(f"[-] All installation methods failed for {tool_name}")
    print(f"    Manual options:")
    print(f"    1. sudo apt install python3-{tool_name.replace('_', '-')}")
    print(f"    2. pipx install {tool_name}")
    print(f"    3. python3 -m venv venv && source venv/bin/activate && pip install {tool_name}")
    return False


def _handle_opt_install(tool_name: str, install_cmd: str) -> bool:
    """Handle installations that need /opt access by using user directory."""
    print(f"[!] Permission denied to /opt. Installing to user directory...")
    
    if "testssl.sh" in tool_name:
        # Install testssl.sh to user's home directory
        user_install_cmd = install_cmd.replace("/opt/testssl.sh", f"{Path.home()}/testssl.sh")
        user_install_cmd = user_install_cmd.replace("/usr/local/bin/testssl.sh", f"{Path.home()}/.local/bin/testssl.sh")
        
        # Ensure .local/bin exists
        local_bin = Path.home() / ".local" / "bin"
        local_bin.mkdir(parents=True, exist_ok=True)
        
        try:
            result = subprocess.run(user_install_cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Successfully installed {tool_name} to user directory")
                print(f"    Location: {Path.home()}/testssl.sh")
                print(f"    Symlink: {local_bin}/testssl.sh")
                return True
        except:
            pass
    
    print(f"[-] Failed to install {tool_name} to user directory")
    print(f"    Try running with sudo for system-wide installation")
    return False


def check_prerequisites():
    """Check for Linux prerequisites."""
    print("[*] Checking Linux prerequisites...")
    
    prerequisites = {
        "python3": [sys.executable, "--version"],
        "pip3": [sys.executable, "-m", "pip", "--version"],
        "git": ["git", "--version"],
        "make": ["make", "--version"],
        "gcc": ["gcc", "--version"]
    }
    
    missing = []
    optional_missing = []
    
    for name, cmd in prerequisites.items():
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode == 0:
                print(f"[+] {name}: Available")
            else:
                if name in ["make", "gcc"]:
                    optional_missing.append(name)
                    print(f"[!] {name}: Not working (optional for compiling)")
                else:
                    missing.append(name)
                    print(f"[-] {name}: Not working")
        except:
            if name in ["make", "gcc"]:
                optional_missing.append(name)
                print(f"[!] {name}: Not found (optional for compiling)")
            else:
                missing.append(name)
                print(f"[-] {name}: Not found")
    
    if missing:
        print(f"\n[!] Missing critical prerequisites: {', '.join(missing)}")
        print("    Install with: sudo apt-get install python3 python3-pip git")
        return False
    
    if optional_missing:
        print(f"\n[!] Missing build tools: {', '.join(optional_missing)}")
        print("    Install with: sudo apt-get install build-essential")
        print("    (Required for compiling some tools from source)")
    
    return True


def check_tools() -> Tuple[bool, List[str]]:
    """Check if all required tools are available.
    
    Returns:
        Tuple of (all_available, missing_tools)
    """
    missing_tools = []
    
    for tool_name, tool_info in TOOLS.items():
        available, _ = check_tool(tool_name, tool_info)
        if not available:
            missing_tools.append(tool_name)
    
    return len(missing_tools) == 0, missing_tools


def display_header():
    """Display the installer header."""
    print("=" * 70)
    print("AutoTest Security Tools Installation & Setup (Linux Only)")
    print("=" * 70)

def show_tool_categories():
    """Display tools organized by category and priority."""
    categories = {}
    for tool_name, tool_info in TOOLS.items():
        category = tool_info.get("category", "other")
        priority = tool_info.get("priority", "medium")
        if category not in categories:
            categories[category] = {"high": [], "medium": [], "low": []}
        categories[category][priority].append((tool_name, tool_info))
    
    print("\n📋 AutoTest Security Tool Categories:")
    print("-" * 50)
    
    for category, priorities in categories.items():
        category_name = category.upper().replace("_", " ")
        print(f"\n🔧 {category_name} TOOLS:")
        
        for priority in ["high", "medium", "low"]:
            if priorities[priority]:
                priority_label = f"{priority.upper()} PRIORITY"
                if priority == "high":
                    priority_label += " (Essential)"
                elif priority == "medium": 
                    priority_label += " (Recommended)"
                else:
                    priority_label += " (Optional)"
                
                print(f"  {priority_label}:")
                for tool_name, tool_info in priorities[priority]:
                    description = tool_info.get("description", "")
                    auth_note = " (REQUIRES --auth-test)" if tool_info.get("requires_auth") else ""
                    print(f"    • {tool_name:<15} {description}{auth_note}")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AutoTest Security Tools Installation & Setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 installation.py                    # Interactive installation
  python3 installation.py --auto            # Automatic installation (all tools)
  python3 installation.py --auto --high     # Install only high priority tools
  python3 installation.py --check           # Check tools only (no installation)
  python3 installation.py --categories      # Show tool categories and exit
        """
    )
    
    parser.add_argument("--auto", action="store_true",
                        help="Automatic installation without prompts")
    parser.add_argument("--check", action="store_true", 
                        help="Check tools only, do not install")
    parser.add_argument("--categories", action="store_true",
                        help="Show tool categories and exit")
    parser.add_argument("--high", action="store_true",
                        help="Install only high priority tools")
    parser.add_argument("--medium", action="store_true", 
                        help="Install high and medium priority tools")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    
    return parser.parse_args()

def main():
    """Main installation routine for Linux systems."""
    args = parse_arguments()
    
    if args.categories:
        display_header()
        show_tool_categories()
        return
        
    display_header()
    
    # Verify Linux system
    check_linux_system()
    
    print(f"System: {os.uname().sysname} {os.uname().release}")
    print(f"Python: {sys.version}")
    print()
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n[!] Please install missing prerequisites first.")
        print("    Install with: sudo apt-get install python3 python3-pip git build-essential")
        return
    
    # Check if running as root (discouraged for user tools)
    if os.geteuid() == 0 and not args.auto:
        print("\n[!] Warning: Running as root is not recommended for user tools")
        print("    Tool paths will be saved for root user, not your regular user")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    # Determine which tools to check based on arguments
    tools_to_check = {}
    if args.high:
        tools_to_check = {name: info for name, info in TOOLS.items() 
                         if info.get("priority") == "high"}
        print("Checking HIGH PRIORITY tools only...")
    elif args.medium:
        tools_to_check = {name: info for name, info in TOOLS.items() 
                         if info.get("priority") in ["high", "medium"]}
        print("Checking HIGH and MEDIUM PRIORITY tools...")
    else:
        tools_to_check = TOOLS
        print("Checking all security tools...")
    
    print("-" * 50)
    
    missing_tools = []
    available_tools = []
    
    for tool_name, tool_info in tools_to_check.items():
        available, path = check_tool(tool_name, tool_info)
        
        if available:
            priority = tool_info.get("priority", "medium").upper()
            category = tool_info.get("category", "other").upper()
            print(f"[+] {tool_name:<15} Available at: {path} ({priority} {category})")
            available_tools.append(tool_name)
        else:
            priority = tool_info.get("priority", "medium").upper() 
            category = tool_info.get("category", "other").upper()
            print(f"[-] {tool_name:<15} Not found ({priority} {category})")
            missing_tools.append(tool_name)
    
    # Show summary
    total_tools = len(tools_to_check)
    print(f"\n📊 Summary: {len(available_tools)}/{total_tools} tools available, {len(missing_tools)} missing")
    
    # Exit if just checking
    if args.check:
        print("\n[*] Tool check complete. Use --auto to install missing tools.")
        return
    
    # Install missing tools
    if missing_tools:
        print(f"\n📦 Missing tools by priority:")
        missing_by_priority = {"high": [], "medium": [], "low": []}
        for tool_name in missing_tools:
            priority = TOOLS[tool_name].get("priority", "medium")
            missing_by_priority[priority].append(tool_name)
        
        for priority in ["high", "medium", "low"]:
            if missing_by_priority[priority]:
                priority_label = priority.upper()
                if priority == "high":
                    priority_label += " PRIORITY (Essential)"
                elif priority == "medium":
                    priority_label += " PRIORITY (Recommended)" 
                else:
                    priority_label += " PRIORITY (Optional)"
                
                print(f"  {priority_label}: {', '.join(missing_by_priority[priority])}")
        
        if args.auto:
            install_missing = True
        else:
            response = input(f"\nInstall {len(missing_tools)} missing tools? (y/n): ")
            install_missing = response.lower() == 'y'
        
        if install_missing:
            successful_installs = 0
            print(f"\n🔧 Installing {len(missing_tools)} tools...")
            
            for tool_name in missing_tools:
                tool_info = tools_to_check[tool_name]
                
                if install_tool(tool_name, tool_info):
                    successful_installs += 1
                    # Wait a moment for system to update
                    time.sleep(1)
                    
                    # Verify installation
                    available, path = check_tool(tool_name, tool_info)
                    if available:
                        print(f"[+] {tool_name} is now available at: {path}")
                    else:
                        # Refresh PATH and try again
                        subprocess.run(["hash", "-r"], capture_output=True)
                        
                        # Get fresh PATH from shell
                        try:
                            fresh_path = subprocess.check_output(
                                ["bash", "-c", "echo $PATH"],
                                text=True
                            ).strip()
                            os.environ["PATH"] = fresh_path
                        except:
                            pass
                        
                        # Check again
                        available, path = check_tool(tool_name, tool_info)
                        if available:
                            print(f"[+] {tool_name} is now available at: {path}")
                        else:
                            print(f"[!] {tool_name} installed but not found in PATH")
                            print("    You may need to restart your terminal")
            
            print(f"\n📈 Installation Results: {successful_installs}/{len(missing_tools)} tools successfully installed")
    
    # Final summary
    print("\n\nFinal Summary")
    print("=" * 50)
    
    for tool_name, tool_info in TOOLS.items():
        available, path = check_tool(tool_name, tool_info)
        status = "[OK] Available" if available else "[FAIL] Missing"
        print(f"{tool_name:<15} {status}")
    
    print("\n[*] Installation complete!")
    
    # Save tool paths for AutoTest
    tool_paths = {}
    for tool_name, tool_info in TOOLS.items():
        available, path = check_tool(tool_name, tool_info)
        if available and path:
            tool_paths[tool_name] = path
    
    # Try to save in current directory, fallback to user directory
    config_paths = [
        "tool_paths.json",
        str(Path.home() / ".autotest_tool_paths.json"),
        "/tmp/autotest_tool_paths.json"
    ]
    
    saved = False
    for config_path in config_paths:
        try:
            with open(config_path, 'w') as f:
                json.dump(tool_paths, f, indent=2)
            print(f"\n[+] Tool paths saved to {config_path}")
            saved = True
            break
        except PermissionError:
            continue
        except Exception as e:
            print(f"[-] Failed to save to {config_path}: {e}")
            continue
    
    if not saved:
        print(f"\n[!] Could not save tool paths configuration")
        print("    Tool detection will run each time autotest starts")
    
    print("\n[*] AutoTest is ready for Linux security testing!")


if __name__ == "__main__":
    main()