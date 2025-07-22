#!/usr/bin/env python3
"""Test script to verify all fixes are working."""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath((__file__ if "__file__" in globals() else "."))))

def test_imports():
    """Test all imports work without errors."""
    print("Testing imports...")
    
    try:
        from core.config import Config
        from core.discovery import Discovery
        from core.task_manager import TaskManager
        from core.output import OutputManager
        from autotest import AutoTest
        print("[+] All imports successful")
        return True
    except ImportError as e:
        print(f"[-] Import error: {e}")
        return False

def test_discovery_init():
    """Test Discovery can be initialized correctly."""
    print("\nTesting Discovery initialization...")
    
    try:
        from core.discovery import Discovery
        discovery = Discovery(max_threads=10, timeout=1.0)
        print("[+] Discovery initialized correctly")
        return True
    except Exception as e:
        print(f"[-] Discovery init error: {e}")
        return False

def test_output_manager():
    """Test OutputManager has create_summary_log method."""
    print("\nTesting OutputManager...")
    
    try:
        from core.output import OutputManager
        om = OutputManager("test_output")
        
        if hasattr(om, 'create_summary_log'):
            print("[+] OutputManager has create_summary_log method")
            
            # Clean up
            import shutil
            if os.path.exists("test_output"):
                shutil.rmtree("test_output")
            return True
        else:
            print("[-] OutputManager missing create_summary_log method")
            return False
    except Exception as e:
        print(f"[-] OutputManager error: {e}")
        return False

def test_task_manager():
    """Test TaskManager has required attributes."""
    print("\nTesting TaskManager...")
    
    try:
        from core.task_manager import TaskManager
        tm = TaskManager(max_workers=5)
        
        required_attrs = ['completed_tasks', 'failed_tasks', 'running', 'create_tasks_from_discovery']
        missing = []
        
        for attr in required_attrs:
            if not hasattr(tm, attr):
                missing.append(attr)
        
        if not missing:
            print("[+] TaskManager has all required attributes")
            return True
        else:
            print(f"[-] TaskManager missing: {', '.join(missing)}")
            return False
    except Exception as e:
        print(f"[-] TaskManager error: {e}")
        return False

def test_config():
    """Test Config class."""
    print("\nTesting Config...")
    
    try:
        from core.config import Config
        config = Config()
        
        if hasattr(config, 'save_runtime_config'):
            print("[+] Config has save_runtime_config method")
            return True
        else:
            print("[-] Config missing save_runtime_config method")
            return False
    except Exception as e:
        print(f"[-] Config error: {e}")
        return False

def main():
    """Run all tests."""
    print("AutoTest Fix Verification")
    print("=" * 40)
    
    all_passed = True
    
    # Run tests
    all_passed &= test_imports()
    all_passed &= test_discovery_init()
    all_passed &= test_output_manager()
    all_passed &= test_task_manager()
    all_passed &= test_config()
    
    print("\n" + "=" * 40)
    if all_passed:
        print("[+] All tests passed!")
        print("\nThe fixes should resolve the AttributeErrors.")
    else:
        print("[-] Some tests failed")
        print("\nThere may still be issues to fix.")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())