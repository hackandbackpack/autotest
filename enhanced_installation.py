#!/usr/bin/env python3
"""
Linux-only installation script for AutoTest security tools.
Supports comprehensive installation of all security testing tools on Linux systems.

NOTE: AutoTest is designed for Linux penetration testing environments only.
"""

import os
import sys
import subprocess
import json
import shutil
import time
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Linux-only security tools definitions
SECURITY_TOOLS = {
    # Discovery tools
    "nmap": {
        "description": "Network discovery and security auditing",
        "install": "sudo apt-get update && sudo apt-get install -y nmap || sudo yum install -y nmap || sudo dnf install -y nmap",
        "check_command": ["nmap", "--version"],
        "type": "binary",
        "priority": "high"
    },
    "masscan": {
        "description": "Fast port scanner",
        "install": "sudo apt-get update && sudo apt-get install -y masscan || (git clone https://github.com/robertdavidgraham/masscan.git /tmp/masscan && cd /tmp/masscan && make && sudo make install)",
        "check_command": ["masscan", "--version"],
        "type": "binary",
        "priority": "high"
    },
    
    # Web security tools
    "nikto": {
        "description": "Web server vulnerability scanner",
        "install": "sudo apt-get update && sudo apt-get install -y nikto || git clone https://github.com/sullo/nikto.git /opt/nikto && sudo ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto",
        "check_command": ["nikto", "-Version"],
        "type": "binary",
        "priority": "medium"
    },
    "gobuster": {
        "description": "Directory and file brute-forcer",
        "install": "sudo apt-get update && sudo apt-get install -y gobuster || go install github.com/OJ/gobuster/v3@latest",
        "check_command": ["gobuster", "version"],
        "type": "binary",
        "priority": "medium"
    },
    "whatweb": {
        "description": "Web application fingerprinter",
        "install": "sudo apt-get update && sudo apt-get install -y whatweb || (sudo apt-get install -y ruby-dev && gem install whatweb)",
        "check_command": ["whatweb", "--version"],
        "type": "binary", 
        "priority": "medium"
    },
    
    # DNS tools
    "dnsrecon": {
        "description": "DNS enumeration and reconnaissance",
        "install": "sudo apt-get update && sudo apt-get install -y dnsrecon || pip3 install dnsrecon",
        "check_command": ["dnsrecon", "--help"],
        "type": "python",
        "priority": "medium"
    },
    "dig": {
        "description": "DNS lookup utility",
        "install": "sudo apt-get update && sudo apt-get install -y dnsutils || sudo yum install -y bind-utils || sudo dnf install -y bind-utils",
        "check_command": ["dig", "-v"],
        "type": "binary",
        "priority": "high"
    },
    
    # SSH tools
    "ssh-audit": {
        "description": "SSH server security auditing tool",
        "install": "pip3 install ssh-audit",
        "check_command": ["ssh-audit", "--help"],
        "python_module": "ssh_audit",
        "type": "python",
        "priority": "medium"
    },
    
    # SSL/TLS tools
    "testssl.sh": {
        "description": "Comprehensive SSL/TLS testing suite",
        "install": "sudo git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh || (git clone https://github.com/drwetter/testssl.sh.git ~/testssl.sh && mkdir -p ~/.local/bin && ln -sf ~/testssl.sh/testssl.sh ~/.local/bin/testssl.sh)",
        "check_command": ["testssl.sh", "--version"],
        "type": "script",
        "priority": "medium"
    },
    "sslyze": {
        "description": "SSL/TLS configuration analyzer",
        "install": "pip3 install sslyze",
        "check_command": ["sslyze", "--help"],
        "python_module": "sslyze",
        "type": "python",
        "priority": "low"
    },
    
    # RPC tools
    "rpcinfo": {
        "description": "RPC service enumeration tool",
        "install": "sudo apt-get update && sudo apt-get install -y rpcbind nfs-common || sudo yum install -y rpcbind || sudo dnf install -y rpcbind",
        "check_command": ["rpcinfo"],
        "type": "binary",
        "priority": "low"
    },
    
    # Authentication testing tools
    "hydra": {
        "description": "Network authentication brute-forcer",
        "install": "sudo apt-get update && sudo apt-get install -y hydra || sudo yum install -y hydra || sudo dnf install -y hydra",
        "check_command": ["hydra"],
        "type": "binary",
        "priority": "high",
        "requires_auth": True
    },
    
    # SNMP tools
    "onesixtyone": {
        "description": "Fast SNMP scanner",
        "install": "sudo apt-get update && sudo apt-get install -y onesixtyone || (git clone https://github.com/trailofbits/onesixtyone.git /tmp/onesixtyone && cd /tmp/onesixtyone && make && sudo make install)",
        "check_command": ["onesixtyone"],
        "type": "binary",
        "priority": "low"
    },
    
    # SMB/NetBIOS tools
    "netexec": {
        "description": "Network execution and credential testing tool",
        "install": "pip3 install netexec",
        "check_command": ["netexec", "--help"],
        "python_module": "netexec",
        "type": "python",
        "priority": "medium",
        "requires_auth": True
    }
}

def check_linux_system():
    """Verify we're running on a Linux system."""
    if os.name != 'posix':
        print("[-] ERROR: AutoTest requires a Linux system.")
        print("    Windows and macOS are not supported.")
        sys.exit(1)
    
    # Check if we have basic Linux tools
    required_system_tools = ["bash", "grep", "awk"]
    for tool in required_system_tools:
        if not shutil.which(tool):
            print(f"[-] ERROR: Required system tool '{tool}' not found.")
            print("    Ensure you're running on a proper Linux distribution.")
            sys.exit(1)

def check_tool_installed(tool_name: str, tool_info: Dict) -> Tuple[bool, Optional[str]]:
    """Check if a tool is installed and return its path."""
    # Check if it's a Python module first
    if tool_info.get("type") == "python" and "python_module" in tool_info:
        try:
            result = subprocess.run(
                [sys.executable, "-m", tool_info["python_module"], "--help"],
                capture_output=True,
                timeout=5,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                return True, f"{sys.executable} -m {tool_info['python_module']}"
        except:
            pass
    
    # Check normal command
    check_cmd = tool_info.get("check_command", [tool_name])
    
    try:
        # First check if it's in PATH
        path = shutil.which(check_cmd[0])
        if path:
            # Try to run it to confirm it works
            try:
                result = subprocess.run(
                    check_cmd,
                    capture_output=True,
                    timeout=5,
                    stderr=subprocess.DEVNULL
                )
                return True, path
            except:
                # Command exists but might not work, still consider it found
                return True, path
    except:
        pass
    
    # Check common Linux installation locations
    common_paths = [
        f"/usr/bin/{tool_name}",
        f"/usr/local/bin/{tool_name}",
        f"/opt/{tool_name}/{tool_name}",
        f"/opt/{tool_name}/bin/{tool_name}",
        f"/usr/sbin/{tool_name}"
    ]
    
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return True, path
    
    return False, None

def install_tool(tool_name: str, tool_info: Dict, interactive: bool = True) -> bool:
    """Install a tool using Linux package managers or source compilation."""
    install_cmd = tool_info.get("install")
    
    if not install_cmd:
        print(f"[-] No installation command available for {tool_name}")
        return False
    
    print(f"\n[*] Installing {tool_name}...")
    print(f"    Description: {tool_info.get('description', 'No description')}")
    print(f"    Command: {install_cmd}")
    
    if interactive:
        response = input("    Continue? (y/N): ")
        if response.lower() != 'y':
            print("    Skipped.")
            return False
    
    try:
        # Use shell execution for complex commands with && and ||
        result = subprocess.run(install_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] Successfully installed {tool_name}")
            
            # Wait a moment for PATH updates
            time.sleep(2)
            
            # Verify installation
            installed, path = check_tool_installed(tool_name, tool_info)
            if installed:
                print(f"[+] Verified: {tool_name} is available at {path}")
                return True
            else:
                print(f"[!] {tool_name} installed but not found in PATH. May need to restart terminal.")
                return False
        else:
            # Handle externally-managed Python environment
            if "externally-managed-environment" in result.stderr and "pip3 install" in install_cmd:
                return _handle_python_package(tool_name, tool_info, interactive)
            else:
                print(f"[-] Failed to install {tool_name}")
                if result.stderr:
                    print(f"    Error: {result.stderr}")
                return False
            
    except Exception as e:
        print(f"[-] Error installing {tool_name}: {e}")
        return False


def _handle_python_package(tool_name: str, tool_info: Dict, interactive: bool) -> bool:
    """Handle Python package installation with externally-managed environment."""
    print(f"[!] System Python is externally managed. Trying alternatives...")
    
    alternatives = [
        ("system package", f"sudo apt-get update && sudo apt-get install -y python3-{tool_name.replace('_', '-')}"),
        ("pipx", f"pipx install {tool_name}"),
        ("user install", f"pip3 install --user --break-system-packages {tool_name}")
    ]
    
    for method, cmd in alternatives:
        if interactive:
            response = input(f"    Try {method}? (y/N): ")
            if response.lower() != 'y':
                continue
        
        print(f"    Trying {method}...")
        try:
            # Install pipx if needed
            if "pipx install" in cmd:
                pipx_check = subprocess.run(["pipx", "--version"], capture_output=True)
                if pipx_check.returncode != 0:
                    print("    Installing pipx first...")
                    subprocess.run("sudo apt-get install -y pipx", shell=True, capture_output=True)
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Successfully installed {tool_name} via {method}")
                return True
            else:
                print(f"    {method} failed: {result.stderr}")
        except Exception as e:
            print(f"    {method} error: {e}")
    
    print(f"[-] All installation methods failed for {tool_name}")
    return False

def check_prerequisites():
    """Check for installation prerequisites."""
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
                    print(f"[!] {name}: Not working (optional for some tools)")
                else:
                    missing.append(name)
                    print(f"[-] {name}: Not working")
        except:
            if name in ["make", "gcc"]:
                optional_missing.append(name)
                print(f"[!] {name}: Not found (optional for some tools)")
            else:
                missing.append(name)
                print(f"[-] {name}: Not found")
    
    if missing:
        print(f"\n[!] Missing critical prerequisites: {', '.join(missing)}")
        print("    Install with: sudo apt-get install python3 python3-pip git")
        return False
    
    if optional_missing:
        print(f"\n[!] Missing optional build tools: {', '.join(optional_missing)}")
        print("    Install with: sudo apt-get install build-essential")
        print("    (Required for compiling some tools from source)")
    
    return True

def generate_install_script(tools_to_install: List[str]) -> str:
    """Generate a shell script for installing multiple tools."""
    script_content = """#!/bin/bash
# AutoTest Security Tools Installation Script
# Generated for Linux systems only

echo 'Installing AutoTest security tools...'
set -e

"""
    
    for tool_name in tools_to_install:
        if tool_name in SECURITY_TOOLS:
            tool_info = SECURITY_TOOLS[tool_name]
            install_cmd = tool_info["install"]
            
            if install_cmd:
                script_content += f"echo 'Installing {tool_name}...'\n"
                script_content += f"{install_cmd}\n"
                script_content += f"echo '{tool_name} installation complete'\n\n"
    
    script_content += "echo 'All installations complete. You may need to restart your terminal.'\n"
    
    script_name = "install_autotest_tools.sh"
    
    try:
        with open(script_name, 'w') as f:
            f.write(script_content)
        
        os.chmod(script_name, 0o755)
        
        print(f"[+] Installation script created: {script_name}")
        return script_name
    except Exception as e:
        print(f"[-] Failed to create installation script: {e}")
        return ""

def main():
    """Main installation interface."""
    print("=" * 60)
    print("AutoTest Security Tools Installation (Linux Only)")
    print("=" * 60)
    
    # Verify Linux system
    check_linux_system()
    
    print(f"System: {os.uname().sysname} {os.uname().release}")
    print(f"Python: {sys.version}")
    print()
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n[!] Please install missing prerequisites first.")
        return
    
    print(f"\n[*] Checking {len(SECURITY_TOOLS)} security tools...")
    
    installed_tools = []
    missing_tools = []
    
    # Sort tools by priority
    tools_by_priority = {
        "high": [],
        "medium": [], 
        "low": []
    }
    
    for tool_name, tool_info in SECURITY_TOOLS.items():
        priority = tool_info.get("priority", "medium")
        installed, path = check_tool_installed(tool_name, tool_info)
        
        if installed:
            print(f"[+] {tool_name:<15} Available at: {path}")
            installed_tools.append(tool_name)
        else:
            print(f"[-] {tool_name:<15} Not found")
            missing_tools.append(tool_name)
            tools_by_priority[priority].append(tool_name)
    
    print(f"\n[*] Summary: {len(installed_tools)} installed, {len(missing_tools)} missing")
    
    if not missing_tools:
        print("[+] All tools are already installed!")
        return
    
    # Show missing tools by priority
    for priority in ["high", "medium", "low"]:
        if tools_by_priority[priority]:
            priority_name = priority.upper()
            if priority == "high":
                priority_name += " PRIORITY (Essential)"
            elif priority == "medium":
                priority_name += " PRIORITY (Recommended)"
            else:
                priority_name += " PRIORITY (Optional)"
                
            print(f"\n{priority_name}:")
            for tool in tools_by_priority[priority]:
                description = SECURITY_TOOLS[tool].get("description", "")
                auth_note = " (REQUIRES --auth-test)" if SECURITY_TOOLS[tool].get("requires_auth") else ""
                print(f"  • {tool}: {description}{auth_note}")
    
    print("\n" + "=" * 60)
    print("Installation Options:")
    print("1. Install all missing tools")
    print("2. Install high-priority tools only")
    print("3. Install selected tools interactively")
    print("4. Generate installation script")
    print("5. Exit")
    
    try:
        choice = input("\nSelect option (1-5): ").strip()
        
        tools_to_install = []
        if choice == "1":
            tools_to_install = missing_tools
        elif choice == "2":
            tools_to_install = tools_by_priority["high"]
        elif choice == "3":
            # Interactive selection
            print("\nSelect tools to install (y/n for each):")
            for tool in missing_tools:
                response = input(f"Install {tool}? (y/N): ").lower()
                if response == 'y':
                    tools_to_install.append(tool)
        elif choice == "4":
            # Generate script
            script_tools = missing_tools
            script_name = generate_install_script(script_tools)
            if script_name:
                print(f"\n[+] Run the script with: ./{script_name}")
            return
        elif choice == "5":
            return
        else:
            print("Invalid choice.")
            return
        
        # Install selected tools
        if tools_to_install:
            print(f"\n[*] Installing {len(tools_to_install)} tools...")
            
            successful_installs = 0
            for tool_name in tools_to_install:
                if tool_name in SECURITY_TOOLS:
                    if install_tool(tool_name, SECURITY_TOOLS[tool_name], interactive=False):
                        successful_installs += 1
            
            print(f"\n[*] Installation complete: {successful_installs}/{len(tools_to_install)} successful")
            
            # Final verification
            print("\n[*] Final verification:")
            for tool_name in tools_to_install:
                installed, path = check_tool_installed(tool_name, SECURITY_TOOLS[tool_name])
                status = "[OK]" if installed else "[FAIL]"
                print(f"  {status} {tool_name}")
            
            print("\n[*] You may need to restart your terminal for PATH changes to take effect.")
        
    except KeyboardInterrupt:
        print("\n\n[!] Installation cancelled by user.")
    except Exception as e:
        print(f"\n[-] Installation error: {e}")

if __name__ == "__main__":
    main()