#!/usr/bin/env python3
"""Test plugin execution flow."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__ if "__file__" in globals() else ".")))

from core.task_manager import TaskManager, Task, TaskPriority
from plugins.services.ssl import SSLPlugin

def test_task_function_creation():
    """Test that tasks are created with proper functions."""
    print("Testing task function creation...")
    
    # Create task manager
    tm = TaskManager(max_workers=1)
    
    # Simulate discovery results
    discovered_hosts = {
        "example.com": {
            "ports": [443],
            "services": {"443": "HTTPS"}
        }
    }
    
    # Create SSL plugin
    ssl_plugin = SSLPlugin()
    plugins = [ssl_plugin]
    
    # Create tasks
    tm.create_tasks_from_discovery(discovered_hosts, plugins)
    
    # Check tasks were created
    print(f"Created {len(tm.tasks)} tasks")
    
    # Check task has a function
    for task_id, task in tm.tasks.items():
        print(f"\nTask: {task.name}")
        print(f"  ID: {task.id}")
        print(f"  Function: {task.function}")
        print(f"  Target: {task.target}")
        print(f"  Port: {task.port}")
        print(f"  Plugin: {task.plugin_name}")
        
        # Verify function is not None
        assert task.function is not None, "Task function should not be None"
        print("  [OK] Task has valid function")
        
        # Test we can call it (without actually executing)
        assert callable(task.function), "Task function should be callable"
        print("  [OK] Task function is callable")

def test_plugin_execute():
    """Test that plugin execute method works."""
    print("\n\nTesting plugin execute method...")
    
    ssl_plugin = SSLPlugin()
    
    # Test the execute method signature
    import inspect
    sig = inspect.signature(ssl_plugin.execute)
    print(f"Plugin execute signature: {sig}")
    
    # Verify it accepts the right parameters
    params = list(sig.parameters.keys())
    assert 'target' in params, "Plugin should accept 'target' parameter"
    print("[OK] Plugin accepts target parameter")
    
    # Check it accepts kwargs
    assert any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()), \
        "Plugin should accept **kwargs"
    print("[OK] Plugin accepts **kwargs")

def main():
    """Run tests."""
    print("Plugin Execution Tests")
    print("=" * 50)
    
    try:
        test_task_function_creation()
        test_plugin_execute()
        
        print("\n" + "=" * 50)
        print("[OK] All tests passed!")
        return 0
        
    except Exception as e:
        print(f"\n[FAIL] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())