#!/usr/bin/env python3
"""
Test all class attributes to ensure no AttributeErrors.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath((__file__ if "__file__" in globals() else "."))))

from core.task_manager import Task, TaskManager, TaskStatus, TaskPriority
from core.discovery import Discovery
from core.output import OutputManager
from core.config import Config
from plugins.services.ssl import SSLPlugin


def test_task_attributes():
    """Test all Task attributes."""
    print("Testing Task attributes...")
    
    # Create a task with all attributes
    task = Task(
        id="test-1",
        name="Test Task",
        function=lambda: None,
        args=("arg1",),
        kwargs={"key": "value"},
        priority=TaskPriority.HIGH,
        dependencies=["dep1"],
        status=TaskStatus.PENDING,
        result=None,
        error=None,
        start_time=1234567890.0,
        end_time=1234567900.0,
        target="192.168.1.1",
        port=443,
        service="https",
        plugin_name="ssl",
        params={"timeout": 30}
    )
    
    # Test all attributes exist
    attributes = [
        'id', 'name', 'function', 'args', 'kwargs', 'priority', 
        'dependencies', 'status', 'result', 'error', 'start_time', 
        'end_time', 'target', 'port', 'service', 'plugin_name', 'params'
    ]
    
    missing = []
    for attr in attributes:
        if not hasattr(task, attr):
            missing.append(attr)
    
    if missing:
        print(f"  [FAIL] Missing attributes: {missing}")
        return False
    else:
        print("  [OK] All Task attributes present")
        return True


def test_discovery_attributes():
    """Test Discovery attributes."""
    print("\nTesting Discovery attributes...")
    
    discovery = Discovery(max_threads=10, timeout=1.0)
    
    attributes = ['max_threads', 'timeout', 'is_windows', '_shutdown', 'shutdown']
    
    missing = []
    for attr in attributes:
        if not hasattr(discovery, attr):
            missing.append(attr)
    
    if missing:
        print(f"  [FAIL] Missing attributes: {missing}")
        return False
    else:
        print("  [OK] All Discovery attributes present")
        return True


def test_task_manager_attributes():
    """Test TaskManager attributes."""
    print("\nTesting TaskManager attributes...")
    
    tm = TaskManager(max_workers=5)
    
    attributes = [
        'max_workers', 'tasks', 'task_queue', 'results', 'lock',
        'stop_event', 'executor', 'futures', 'stats', 'completed_tasks',
        'failed_tasks', 'running', 'create_tasks_from_discovery'
    ]
    
    missing = []
    for attr in attributes:
        if not hasattr(tm, attr):
            missing.append(attr)
    
    if missing:
        print(f"  [FAIL] Missing attributes: {missing}")
        return False
    else:
        print("  [OK] All TaskManager attributes present")
        return True


def test_output_manager_attributes():
    """Test OutputManager attributes."""
    print("\nTesting OutputManager attributes...")
    
    # Create temp output dir
    os.makedirs("test_output", exist_ok=True)
    
    try:
        om = OutputManager("test_output")
        
        attributes = [
            'output_dir', 'default_format', 'session_id', 'session_dir',
            'create_summary_log', 'generate_reports', 'generate_report',
            'save_results'
        ]
        
        missing = []
        for attr in attributes:
            if not hasattr(om, attr):
                missing.append(attr)
        
        if missing:
            print(f"  [FAIL] Missing attributes: {missing}")
            return False
        else:
            print("  [OK] All OutputManager attributes present")
            return True
    finally:
        # Cleanup
        import shutil
        if os.path.exists("test_output"):
            shutil.rmtree("test_output")


def test_plugin_attributes():
    """Test Plugin attributes."""
    print("\nTesting Plugin attributes...")
    
    plugin = SSLPlugin()
    
    attributes = [
        'name', 'version', 'description', 'type', 'author',
        'required_tools', 'ssl_ports', 'can_handle', 'execute',
        'get_required_params', 'get_optional_params'
    ]
    
    missing = []
    for attr in attributes:
        if not hasattr(plugin, attr):
            missing.append(attr)
    
    if missing:
        print(f"  [FAIL] Missing attributes: {missing}")
        return False
    else:
        print("  [OK] All Plugin attributes present")
        return True


def test_config_attributes():
    """Test Config attributes."""
    print("\nTesting Config attributes...")
    
    config = Config()
    
    attributes = [
        '_config', '_config_file', 'get', 'set', 'save',
        'save_runtime_config', 'validate', 'get_tool_config',
        'is_tool_enabled', 'get_output_path'
    ]
    
    missing = []
    for attr in attributes:
        if not hasattr(config, attr):
            missing.append(attr)
    
    if missing:
        print(f"  [FAIL] Missing attributes: {missing}")
        return False
    else:
        print("  [OK] All Config attributes present")
        return True


def test_attribute_access_patterns():
    """Test specific attribute access patterns that caused errors."""
    print("\nTesting specific attribute access patterns...")
    
    issues = []
    
    # Test Task attribute access as in _generate_reports
    task = Task(
        id="test-1",
        name="Test Task",
        function=lambda: None,
        target="192.168.1.1",
        port=443,
        service="https",
        plugin_name="ssl"
    )
    
    try:
        # These are the actual accesses from _generate_reports
        _ = task.port
        _ = task.service  
        _ = task.plugin_name
        _ = task.status.value
        _ = task.start_time  # This was the bug - was accessing started_at
        _ = task.end_time    # This was the bug - was accessing completed_at
        _ = task.result
        _ = task.error
        print("  [OK] Task attribute access patterns work correctly")
    except AttributeError as e:
        issues.append(f"Task attribute error: {e}")
        print(f"  [FAIL] Task attribute error: {e}")
    
    return len(issues) == 0


def main():
    """Run all tests."""
    print("AutoTest Attribute Validation")
    print("=" * 50)
    
    all_passed = True
    
    # Run all tests
    all_passed &= test_task_attributes()
    all_passed &= test_discovery_attributes()
    all_passed &= test_task_manager_attributes()
    all_passed &= test_output_manager_attributes()
    all_passed &= test_plugin_attributes()
    all_passed &= test_config_attributes()
    all_passed &= test_attribute_access_patterns()
    
    print("\n" + "=" * 50)
    if all_passed:
        print("[OK] All attribute tests passed!")
        print("\nThe attribute issues should be resolved.")
    else:
        print("[FAIL] Some attribute tests failed")
        print("\nThere are still attribute issues to fix.")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())