#!/bin/bash
# Quick fix script for AutoTest sync issues

echo "AutoTest Quick Fix Script"
echo "========================"
echo ""

# Check if we're in the right directory
if [ ! -f "autotest.py" ]; then
    echo "Error: This script must be run from the AutoTest directory"
    echo "Please cd to the AutoTest directory and run again"
    exit 1
fi

echo "1. Checking current branch..."
BRANCH=$(git branch --show-current)
echo "   Current branch: $BRANCH"

echo ""
echo "2. Fetching latest changes from remote..."
git fetch origin

echo ""
echo "3. Checking for local modifications..."
if git diff --quiet && git diff --cached --quiet; then
    echo "   No local modifications found"
    
    echo ""
    echo "4. Pulling latest changes..."
    git pull origin main
    
    echo ""
    echo "5. Verifying save_runtime_config method..."
    if grep -q "def save_runtime_config" core/config.py; then
        echo "   ✓ save_runtime_config method found in core/config.py"
    else
        echo "   ✗ save_runtime_config method NOT found - please contact support"
    fi
else
    echo "   ⚠ Local modifications detected!"
    echo ""
    echo "   You have uncommitted changes. Options:"
    echo "   1. Stash your changes: git stash"
    echo "   2. Commit your changes: git add . && git commit -m 'Local changes'"
    echo "   3. Discard your changes: git reset --hard origin/main (WARNING: This will lose your changes)"
    echo ""
    echo "   After handling your changes, run this script again."
    exit 1
fi

echo ""
echo "6. Clearing Python cache..."
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

echo ""
echo "7. Running verification..."
python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from core.config import Config
    if hasattr(Config, 'save_runtime_config'):
        print('   ✓ Python verification: save_runtime_config is available')
    else:
        print('   ✗ Python verification: save_runtime_config NOT found')
except Exception as e:
    print(f'   ✗ Python verification failed: {e}')
"

echo ""
echo "8. Testing AutoTest..."
python3 autotest.py --check-tools > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "   ✓ AutoTest runs without import errors"
else
    echo "   ✗ AutoTest has errors - run 'python3 autotest.py --check-tools' for details"
fi

echo ""
echo "Fix complete! Try running AutoTest again:"
echo "  python3 autotest.py -f /opt/client/scope.txt"