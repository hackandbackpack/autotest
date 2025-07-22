#!/usr/bin/env python3
"""
Comprehensive checker for undefined names and attribute issues in Python code.
Uses AST parsing to find all potential issues.
"""

import ast
import os
import sys
from pathlib import Path
from typing import Set, Dict, List, Tuple, Optional
import builtins

class UndefinedChecker(ast.NodeVisitor):
    """AST visitor to find undefined names and attribute issues."""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.current_scope = [set()]  # Stack of defined names per scope
        self.imported_modules = set()
        self.from_imports = {}  # module -> set of imported names
        self.issues = []
        self.builtins = set(dir(builtins))
        self.class_definitions = {}  # class_name -> set of attributes
        self.current_class = None
        
    def enter_scope(self):
        """Enter a new scope."""
        self.current_scope.append(set())
        
    def exit_scope(self):
        """Exit current scope."""
        if len(self.current_scope) > 1:
            self.current_scope.pop()
            
    def add_name(self, name: str):
        """Add a name to current scope."""
        self.current_scope[-1].add(name)
        
    def is_defined(self, name: str) -> bool:
        """Check if a name is defined in any scope."""
        # Check all scopes
        for scope in self.current_scope:
            if name in scope:
                return True
        
        # Check if it's a builtin
        if name in self.builtins:
            return True
            
        # Check imports
        if name in self.imported_modules:
            return True
            
        # Check from imports
        for module, names in self.from_imports.items():
            if name in names or '*' in names:
                return True
                
        return False
        
    def visit_Import(self, node):
        """Handle import statements."""
        for alias in node.names:
            # import foo -> defines 'foo'
            # import foo as bar -> defines 'bar'
            name = alias.asname if alias.asname else alias.name
            self.add_name(name)
            self.imported_modules.add(name)
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node):
        """Handle from ... import statements."""
        module = node.module or ''
        if module not in self.from_imports:
            self.from_imports[module] = set()
            
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.from_imports[module].add(name)
            if name != '*':
                self.add_name(name)
        self.generic_visit(node)
        
    def visit_FunctionDef(self, node):
        """Handle function definitions."""
        # Function name is defined in parent scope
        self.add_name(node.name)
        
        # Enter function scope
        self.enter_scope()
        
        # Add parameters to function scope
        for arg in node.args.args:
            self.add_name(arg.arg)
        if node.args.vararg:
            self.add_name(node.args.vararg.arg)
        if node.args.kwarg:
            self.add_name(node.args.kwarg.arg)
            
        # Visit function body
        self.generic_visit(node)
        
        # Exit function scope
        self.exit_scope()
        
    def visit_ClassDef(self, node):
        """Handle class definitions."""
        # Class name is defined in parent scope
        self.add_name(node.name)
        self.class_definitions[node.name] = set()
        
        # Enter class scope
        old_class = self.current_class
        self.current_class = node.name
        self.enter_scope()
        
        # Visit class body
        self.generic_visit(node)
        
        # Exit class scope
        self.exit_scope()
        self.current_class = old_class
        
    def visit_Name(self, node):
        """Check name usage."""
        if isinstance(node.ctx, ast.Store):
            # This is an assignment, add to current scope
            self.add_name(node.id)
        elif isinstance(node.ctx, ast.Load):
            # This is a usage, check if defined
            if not self.is_defined(node.id):
                self.issues.append({
                    'type': 'undefined_name',
                    'file': self.filename,
                    'line': node.lineno,
                    'col': node.col_offset,
                    'name': node.id,
                    'message': f"Name '{node.id}' is not defined"
                })
        self.generic_visit(node)
        
    def visit_Attribute(self, node):
        """Check attribute access."""
        # For now, just visit children
        # More sophisticated attribute checking would require type inference
        self.generic_visit(node)
        
    def visit_ExceptHandler(self, node):
        """Handle exception handlers."""
        if node.name:
            self.add_name(node.name)
        self.generic_visit(node)
        
    def visit_With(self, node):
        """Handle with statements."""
        for item in node.items:
            if item.optional_vars:
                # The 'as' variable
                if isinstance(item.optional_vars, ast.Name):
                    self.add_name(item.optional_vars.id)
        self.generic_visit(node)
        
    def visit_For(self, node):
        """Handle for loops."""
        # The loop variable
        if isinstance(node.target, ast.Name):
            self.add_name(node.target.id)
        elif isinstance(node.target, ast.Tuple):
            for elt in node.target.elts:
                if isinstance(elt, ast.Name):
                    self.add_name(elt.id)
        self.generic_visit(node)
        
    def visit_ListComp(self, node):
        """Handle list comprehensions."""
        self.enter_scope()
        self.generic_visit(node)
        self.exit_scope()
        
    def visit_DictComp(self, node):
        """Handle dict comprehensions."""
        self.enter_scope()
        self.generic_visit(node)
        self.exit_scope()
        
    def visit_SetComp(self, node):
        """Handle set comprehensions."""
        self.enter_scope()
        self.generic_visit(node)
        self.exit_scope()
        
    def visit_GeneratorExp(self, node):
        """Handle generator expressions."""
        self.enter_scope()
        self.generic_visit(node)
        self.exit_scope()
        
    def visit_Lambda(self, node):
        """Handle lambda expressions."""
        self.enter_scope()
        # Add lambda parameters
        for arg in node.args.args:
            self.add_name(arg.arg)
        self.generic_visit(node)
        self.exit_scope()


def check_file(filepath: Path) -> List[Dict]:
    """Check a single Python file for undefined names."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        tree = ast.parse(content)
        checker = UndefinedChecker(str(filepath))
        checker.visit(tree)
        
        return checker.issues
    except Exception as e:
        return [{
            'type': 'parse_error',
            'file': str(filepath),
            'message': f"Failed to parse: {e}"
        }]


def find_python_files(root_dir: Path) -> List[Path]:
    """Find all Python files in directory."""
    python_files = []
    
    for root, dirs, files in os.walk(root_dir):
        # Skip certain directories
        dirs[:] = [dir_name for dir_name in dirs if dir_name not in ['__pycache__', '.git', 'venv', 'env', '.venv']]
        
        for file in files:
            if file.endswith('.py'):
                python_files.append(Path(root) / file)
                
    return python_files


def main():
    """Run the undefined names checker."""
    print("AutoTest Undefined Names Checker")
    print("=" * 60)
    
    # Get all Python files
    root_dir = Path((__file__ if "__file__" in globals() else ".")).parent
    python_files = find_python_files(root_dir)
    
    print(f"\nChecking {len(python_files)} Python files...\n")
    
    all_issues = []
    
    # Check each file
    for filepath in sorted(python_files):
        issues = check_file(filepath)
        if issues:
            all_issues.extend(issues)
    
    # Group issues by type
    undefined_names = [issue for issue in all_issues if issue['type'] == 'undefined_name']
    parse_errors = [issue for issue in all_issues if issue['type'] == 'parse_error']
    
    # Report results
    if parse_errors:
        print(f"\nParse Errors ({len(parse_errors)}):")
        for issue in parse_errors:
            print(f"  {issue['file']}: {issue['message']}")
    
    if undefined_names:
        print(f"\nUndefined Names ({len(undefined_names)}):")
        
        # Group by file
        by_file = {}
        for issue in undefined_names:
            if issue['file'] not in by_file:
                by_file[issue['file']] = []
            by_file[issue['file']].append(issue)
        
        for filepath, issues in sorted(by_file.items()):
            print(f"\n  {filepath}:")
            for issue in sorted(issues, key=lambda x: x['line']):
                print(f"    Line {issue['line']}: {issue['message']}")
    
    # Summary
    print("\n" + "=" * 60)
    if all_issues:
        print(f"Found {len(all_issues)} issues!")
        print("\nCommon fixes:")
        print("  - Add missing imports")
        print("  - Check for typos in variable names")
        print("  - Ensure variables are defined before use")
    else:
        print("No undefined names found!")
    
    return len(all_issues)


if __name__ == "__main__":
    sys.exit(main())