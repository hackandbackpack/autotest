#!/usr/bin/env python3
"""
Install and configure required tools for AutoTest.
Linux-only security testing framework installation.

NOTE: AutoTest is designed for Linux penetration testing environments only.

This script:
1. Checks for required tools on Linux systems
2. Installs missing tools via package managers and pip
3. Handles Linux PATH configuration
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

# Tool definitions with install commands
TOOLS = {
    # Discovery tools
    "nmap": {
        "install": "sudo apt-get update && sudo apt-get install -y nmap || sudo yum install -y nmap || sudo dnf install -y nmap",
        "check_command": ["nmap", "--version"],
        "type": "binary"
    },
    "masscan": {
        "install": "sudo apt-get update && sudo apt-get install -y masscan || (git clone https://github.com/robertdavidgraham/masscan.git /tmp/masscan && cd /tmp/masscan && make && sudo make install)",
        "check_command": ["masscan", "--version"],
        "type": "binary"
    },
    
    # Web security tools
    "nikto": {
        "install": "sudo apt-get update && sudo apt-get install -y nikto || (git clone https://github.com/sullo/nikto.git /opt/nikto && sudo ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto)",
        "check_command": ["nikto", "-Version"],
        "type": "binary"
    },
    "gobuster": {
        "install": "sudo apt-get update && sudo apt-get install -y gobuster || go install github.com/OJ/gobuster/v3@latest",
        "check_command": ["gobuster", "version"],
        "type": "binary"
    },
    "whatweb": {
        "install": "sudo apt-get update && sudo apt-get install -y whatweb || (sudo apt-get install -y ruby-dev && gem install whatweb)",
        "check_command": ["whatweb", "--version"],
        "type": "binary"
    },
    
    # DNS tools
    "dnsrecon": {
        "install": "sudo apt-get update && sudo apt-get install -y dnsrecon || pip3 install dnsrecon",
        "check_command": ["dnsrecon", "--help"],
        "python_module": "dnsrecon",
        "type": "python"
    },
    "dig": {
        "install": "sudo apt-get update && sudo apt-get install -y dnsutils || sudo yum install -y bind-utils || sudo dnf install -y bind-utils",
        "check_command": ["dig", "-v"],
        "type": "binary"
    },
    
    # SSH tools
    "ssh-audit": {
        "install": "pip3 install ssh-audit",
        "check_command": ["ssh-audit", "--help"],
        "python_module": "ssh_audit",
        "type": "python"
    },
    
    # SSL/TLS tools
    "testssl.sh": {
        "install": "git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh",
        "check_command": ["testssl.sh", "--version"],
        "type": "script"
    },
    "sslyze": {
        "install": "pip3 install sslyze",
        "check_command": ["sslyze", "--help"],
        "python_module": "sslyze",
        "type": "python"
    },
    
    # RPC tools
    "rpcinfo": {
        "install": "sudo apt-get update && sudo apt-get install -y rpcbind nfs-common || sudo yum install -y rpcbind || sudo dnf install -y rpcbind",
        "check_command": ["rpcinfo"],
        "type": "binary"
    },
    
    # SMB/NetBIOS tools
    "netexec": {
        "install": "pip3 install netexec",
        "check_command": ["netexec", "--help"],
        "python_module": "netexec",
        "type": "python"
    },
    
    # Authentication testing tools
    "hydra": {
        "install": "sudo apt-get update && sudo apt-get install -y hydra || sudo yum install -y hydra || sudo dnf install -y hydra",
        "check_command": ["hydra"],  # hydra shows help without any flags
        "type": "binary"
    },
    "onesixtyone": {
        "install": "sudo apt-get update && sudo apt-get install -y onesixtyone || (git clone https://github.com/trailofbits/onesixtyone.git /tmp/onesixtyone && cd /tmp/onesixtyone && make && sudo make install)",
        "check_command": ["onesixtyone"],
        "type": "binary"
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
                timeout=5,
                stderr=subprocess.DEVNULL
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
            timeout=5,
            stderr=subprocess.DEVNULL
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
    """Install a tool on Linux."""
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
            print(f"[-] Failed to install {tool_name}")
            if result.stderr:
                print(f"    Error: {result.stderr}")
            
            # For Python packages, suggest alternatives
            if "pip3 install" in install_cmd:
                print(f"    Try: sudo apt install python3-{tool_name}")
                print(f"    Or: pip3 install --user {tool_name}")
            
            return False
            
    except Exception as e:
        print(f"[-] Error installing {tool_name}: {e}")
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


def main():
    """Main installation routine for Linux systems."""
    print("AutoTest Installation & Setup (Linux Only)")
    print("=" * 50)
    
    # Verify Linux system
    check_linux_system()
    
    print(f"System: {os.uname().sysname} {os.uname().release}")
    print(f"Python: {sys.version}")
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n[!] Please install missing prerequisites first.")
        return
    
    # Check if running as root (discouraged for user tools)
    if os.geteuid() == 0:
        print("\n[!] Warning: Running as root is not recommended for user tools")
        print("    Tool paths will be saved for root user, not your regular user")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    # Check all tools
    print("\n\nChecking required tools...")
    print("-" * 50)
    
    missing_tools = []
    available_tools = []
    
    for tool_name, tool_info in TOOLS.items():
        available, path = check_tool(tool_name, tool_info)
        
        if available:
            print(f"[+] {tool_name:<15} Available at: {path}")
            available_tools.append(tool_name)
        else:
            print(f"[-] {tool_name:<15} Not found")
            missing_tools.append(tool_name)
    
    # Install missing tools
    if missing_tools:
        print(f"\n\nMissing tools: {', '.join(missing_tools)}")
        response = input("\nInstall missing tools? (y/n): ")
        
        if response.lower() == 'y':
            for tool_name in missing_tools:
                tool_info = TOOLS[tool_name]
                
                if install_tool(tool_name, tool_info):
                    # Wait a moment for system to update
                    time.sleep(1)
                    
                    # Verify installation
                    available, path = check_tool(tool_name, tool_info)
                    if available:
                        print(f"[+] {tool_name} is now available at: {path}")
                    else:
                        # Refresh PATH and try again
                        subprocess.run(["hash", "-r"], capture_output=True, stderr=subprocess.DEVNULL)
                        
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
    
    with open("tool_paths.json", 'w') as f:
        json.dump(tool_paths, f, indent=2)
    print(f"\n[+] Tool paths saved to tool_paths.json")
    print("\n[*] AutoTest is ready for Linux security testing!")


if __name__ == "__main__":
    main()