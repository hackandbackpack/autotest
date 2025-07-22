#!/usr/bin/env python3
"""
Comprehensive attribute audit for AutoTest to find all potential AttributeErrors.
"""

import ast
import os
import sys
from pathlib import Path
from typing import Set, Dict, List, Tuple

class AttributeAuditor(ast.NodeVisitor):
    """AST visitor to find all attribute accesses."""
    
    def __init__(self):
        self.attribute_accesses: Dict[str, Set[str]] = {}
        self.current_file = ""
        self.issues: List[Tuple[str, int, str, str]] = []
        
    def visit_Attribute(self, node):
        """Visit attribute access nodes."""
        if isinstance(node.value, ast.Name):
            obj_name = node.value.id
            attr_name = node.attr
            
            # Track attribute access
            if obj_name not in self.attribute_accesses:
                self.attribute_accesses[obj_name] = set()
            self.attribute_accesses[obj_name].add(attr_name)
            
            # Check for potential issues with known objects
            if self._is_potential_issue(obj_name, attr_name):
                line_no = node.lineno
                self.issues.append((self.current_file, line_no, obj_name, attr_name))
                
        self.generic_visit(node)
    
    def _is_potential_issue(self, obj_name: str, attr_name: str) -> bool:
        """Check if this attribute access might cause an issue."""
        # Known problematic patterns
        problem_patterns = {
            'task': ['started_at', 'completed_at', 'plugin_name', 'target', 'port', 'service'],
            'self.discovery': ['shutdown'],
            'self.task_manager': ['completed_tasks', 'failed_tasks', 'running', 'stats'],
            'self.output_manager': ['generate_reports', 'create_summary_log'],
            'plugin': ['can_handle', 'execute'],
        }
        
        for pattern, attrs in problem_patterns.items():
            if obj_name.endswith(pattern.split('.')[-1]):
                if attr_name in attrs:
                    return True
        return False

def audit_file(filepath: Path) -> AttributeAuditor:
    """Audit a single Python file."""
    auditor = AttributeAuditor()
    auditor.current_file = str(filepath)
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
            auditor.visit(tree)
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        
    return auditor

def find_class_definitions() -> Dict[str, Dict[str, Set[str]]]:
    """Find all class definitions and their attributes."""
    classes = {}
    
    for root, dirs, files in os.walk('.'):
        # Skip irrelevant directories
        if any(skip in root for skip in ['__pycache__', '.git', 'test', 'venv']):
            continue
            
        for file in files:
            if file.endswith('.py'):
                filepath = Path(root) / file
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        tree = ast.parse(f.read())
                        
                    for node in ast.walk(tree):
                        if isinstance(node, ast.ClassDef):
                            class_name = node.name
                            if class_name not in classes:
                                classes[class_name] = {
                                    'file': str(filepath),
                                    'attributes': set(),
                                    'methods': set()
                                }
                            
                            # Find attributes and methods
                            for item in node.body:
                                if isinstance(item, ast.FunctionDef):
                                    if item.name == '__init__':
                                        # Look for self.attr assignments
                                        for stmt in ast.walk(item):
                                            if isinstance(stmt, ast.Assign):
                                                for target in stmt.targets:
                                                    if isinstance(target, ast.Attribute) and \
                                                       isinstance(target.value, ast.Name) and \
                                                       target.value.id == 'self':
                                                        classes[class_name]['attributes'].add(target.attr)
                                    else:
                                        classes[class_name]['methods'].add(item.name)
                                        
                                elif isinstance(item, ast.AnnAssign):
                                    # Handle dataclass-style annotations
                                    if isinstance(item.target, ast.Name):
                                        classes[class_name]['attributes'].add(item.target.id)
                                        
                except Exception as e:
                    pass
                    
    return classes

def main():
    """Run the attribute audit."""
    print("AutoTest Attribute Audit")
    print("=" * 60)
    
    # Find all class definitions
    print("\n1. Finding all class definitions...")
    classes = find_class_definitions()
    
    # Key classes to audit
    key_classes = ['Task', 'TaskManager', 'Discovery', 'AutoTest', 'OutputManager', 
                   'Config', 'Plugin', 'SSLPlugin', 'SMBPlugin', 'RDPPlugin', 
                   'SNMPPlugin', 'SSHPlugin']
    
    print("\n2. Class attributes found:")
    for class_name in key_classes:
        if class_name in classes:
            info = classes[class_name]
            print(f"\n{class_name} ({info['file']}):")
            print(f"  Attributes: {sorted(info['attributes'])}")
            print(f"  Methods: {sorted(list(info['methods'])[:10])}...")
    
    # Audit all Python files
    print("\n\n3. Auditing attribute accesses...")
    all_issues = []
    
    for root, dirs, files in os.walk('.'):
        if any(skip in root for skip in ['__pycache__', '.git', 'test', 'venv']):
            continue
            
        for file in files:
            if file.endswith('.py'):
                filepath = Path(root) / file
                auditor = audit_file(filepath)
                all_issues.extend(auditor.issues)
    
    # Report issues
    if all_issues:
        print(f"\n4. Potential attribute issues found: {len(all_issues)}")
        for filepath, line, obj, attr in sorted(all_issues):
            print(f"   {filepath}:{line} - {obj}.{attr}")
    else:
        print("\n4. No obvious attribute issues found!")
    
    # Specific checks
    print("\n5. Specific attribute checks:")
    
    # Check Task attributes
    task_attrs_used = set()
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.py'):
                filepath = Path(root) / file
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        # Find task.xxx patterns
                        import re
                        matches = re.findall(r'task\.(\w+)', content)
                        task_attrs_used.update(matches)
                except:
                    pass
    
    if 'Task' in classes:
        task_defined = classes['Task']['attributes']
        task_missing = task_attrs_used - task_defined - classes['Task']['methods']
        if task_missing:
            print(f"\n   Task attributes used but not defined: {task_missing}")
        else:
            print("\n   ✓ All Task attributes are properly defined")
    
    return all_issues

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    issues = main()
    sys.exit(0 if not issues else 1)