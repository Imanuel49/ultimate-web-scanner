#!/usr/bin/env python3
"""
Test script for Ultimate Scanner v5.0
Verifies all components work correctly
"""

import sys
import os

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    try:
        import requests
        import bs4
        import urllib.parse
        print("✓ Core dependencies OK")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        print("Run: pip install -r requirements.txt")
        return False

def test_scanner_exists():
    """Test if scanner file exists"""
    print("\nTesting scanner file...")
    if os.path.exists('ultimate_scanner_v5.py'):
        print("✓ Scanner file exists")
        return True
    else:
        print("✗ Scanner file not found")
        return False

def test_scanner_syntax():
    """Test if scanner has valid Python syntax"""
    print("\nTesting scanner syntax...")
    try:
        with open('ultimate_scanner_v5.py', 'r') as f:
            compile(f.read(), 'ultimate_scanner_v5.py', 'exec')
        print("✓ Scanner syntax OK")
        return True
    except SyntaxError as e:
        print(f"✗ Syntax error: {e}")
        return False

def test_help_command():
    """Test if scanner help command works"""
    print("\nTesting help command...")
    try:
        import subprocess
        result = subprocess.run(
            [sys.executable, 'ultimate_scanner_v5.py', '--help'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print("✓ Help command works")
            return True
        else:
            print(f"✗ Help command failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error running help: {e}")
        return False

def test_docker_files():
    """Test if Docker files exist"""
    print("\nTesting Docker files...")
    docker_files = ['Dockerfile', 'docker-compose.yml']
    all_exist = True
    for f in docker_files:
        if os.path.exists(f):
            print(f"✓ {f} exists")
        else:
            print(f"✗ {f} missing")
            all_exist = False
    return all_exist

def test_documentation():
    """Test if documentation exists"""
    print("\nTesting documentation...")
    docs = ['README_v5.md', 'QUICKSTART.md']
    all_exist = True
    for d in docs:
        if os.path.exists(d):
            print(f"✓ {d} exists")
        else:
            print(f"✗ {d} missing")
            all_exist = False
    return all_exist

def main():
    """Run all tests"""
    print("="*60)
    print("Ultimate Scanner v5.0 - Test Suite")
    print("="*60)
    
    tests = [
        test_imports,
        test_scanner_exists,
        test_scanner_syntax,
        test_help_command,
        test_docker_files,
        test_documentation
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("\n✓ ALL TESTS PASSED!")
        print("Scanner is ready to use.")
        print("\nQuick start:")
        print("  python3 ultimate_scanner_v5.py --help")
        return 0
    else:
        print("\n✗ SOME TESTS FAILED")
        print("Please fix the issues above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
