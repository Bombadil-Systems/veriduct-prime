#!/usr/bin/env python3
"""
Veriduct Prime Test Suite
Tests all major functionality including the native loader
"""

import os
import sys
import subprocess
import tempfile
import hashlib
from pathlib import Path

# Colors for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

def print_test(name):
    print(f"\n{BLUE}[TEST]{RESET} {name}")

def print_pass(msg):
    print(f"{GREEN}  ✓{RESET} {msg}")

def print_fail(msg):
    print(f"{RED}  ✗{RESET} {msg}")

def print_warn(msg):
    print(f"{YELLOW}  ⚠{RESET} {msg}")

def run_command(cmd, capture=True):
    """Run a command and return output"""
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        return result.returncode, result.stdout, result.stderr
    else:
        return subprocess.run(cmd, shell=True).returncode, "", ""

def create_test_binary():
    """Create a simple test binary"""
    print_test("Creating test binary")
    
    test_code = '''
import sys
print("Hello from Veriduct test!")
print(f"Args: {sys.argv}")
sys.exit(42)
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_py = f.name
    
    # Compile to pyc
    import py_compile
    test_pyc = test_py + 'c'
    py_compile.compile(test_py, test_pyc)
    
    print_pass(f"Created test binary: {test_pyc}")
    return test_pyc, test_py

def test_annihilate(test_file):
    """Test annihilation"""
    print_test("Testing annihilation")
    
    tmpdir = tempfile.mkdtemp()  # Don't use context manager yet
    cmd = f"python veriduct_prime.py annihilate {test_file} {tmpdir} --verbose"
    code, stdout, stderr = run_command(cmd)
    
    if code != 0:
        print_fail(f"Annihilation failed with code {code}")
        print(stderr)
        return False
    
    # Check outputs exist
    keymap = Path(tmpdir) / "veriduct_key.zst"
    chunks_db = Path(tmpdir) / "veriduct_chunks.db"
    
    if not keymap.exists():
        print_fail("Keymap not created")
        return False
    
    if not chunks_db.exists():
        print_fail("Chunks DB not created")
        return False
    
    print_pass(f"Keymap created: {keymap.stat().st_size} bytes")
    print_pass(f"Chunks DB created: {chunks_db.stat().st_size} bytes")
    
    return str(tmpdir), str(keymap), str(chunks_db)

def test_reassemble(keymap_path, output_dir):
    """Test reassembly"""
    print_test("Testing reassembly")
    
    cmd = f"python veriduct_prime.py reassemble {keymap_path} {output_dir} --verbose"
    code, stdout, stderr = run_command(cmd)
    
    if code != 0:
        print_fail(f"Reassembly failed with code {code}")
        print(stderr)
        return False
    
    # Find reassembled file
    reassembled = None
    for f in Path(output_dir).iterdir():
        if f.is_file() and f.suffix in ['.pyc', '.py', '.exe', '.dll']:
            reassembled = f
            break
    
    if not reassembled:
        print_fail("No reassembled file found")
        return False
    
    print_pass(f"Reassembled: {reassembled.name} ({reassembled.stat().st_size} bytes)")
    return reassembled

def test_semantic_execution(keymap_path):
    """Test semantic execution"""
    print_test("Testing semantic execution (run)")
    
    cmd = f"python veriduct_prime.py run {keymap_path} --verbose"
    code, stdout, stderr = run_command(cmd)
    
    # Check if execution happened
    if "Hello from Veriduct test!" in stdout or "Hello from Veriduct test!" in stderr:
        print_pass("Semantic execution successful")
        print_pass("Test binary executed correctly")
        return True
    else:
        print_warn("Execution completed but output not found")
        print(f"stdout: {stdout[:200]}")
        print(f"stderr: {stderr[:200]}")
        return False

def test_integrity_verification(original_file, reassembled_file):
    """Test file integrity"""
    print_test("Testing integrity verification")
    
    def get_hash(filepath):
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    orig_hash = get_hash(original_file)
    reasm_hash = get_hash(reassembled_file)
    
    if orig_hash == reasm_hash:
        print_pass(f"File integrity verified (SHA256: {orig_hash[:16]}...)")
        return True
    else:
        print_fail("File hashes do not match")
        print(f"  Original:    {orig_hash}")
        print(f"  Reassembled: {reasm_hash}")
        return False

def test_advanced_features():
    """Test advanced Veriduct features"""
    print_test("Testing advanced features")
    
    test_pyc, test_py = create_test_binary()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Test with SSM
        print("\n  Testing SSM...")
        cmd = f"python veriduct_prime.py annihilate {test_pyc} {tmpdir} --ssm --verbose"
        code, _, _ = run_command(cmd)
        if code == 0:
            print_pass("SSM enabled")
        else:
            print_fail("SSM failed")
        
        # Test with entanglement
        print("\n  Testing XOR Entanglement...")
        cmd = f"python veriduct_prime.py annihilate {test_pyc} {tmpdir} --entanglement --verbose"
        code, _, _ = run_command(cmd)
        if code == 0:
            print_pass("Entanglement enabled")
        else:
            print_fail("Entanglement failed")
        
        # Test with fake chunks
        print("\n  Testing fake chunks...")
        cmd = f"python veriduct_prime.py annihilate {test_pyc} {tmpdir} --fake-chunks --verbose"
        code, _, _ = run_command(cmd)
        if code == 0:
            print_pass("Fake chunks enabled")
        else:
            print_fail("Fake chunks failed")
    
    os.unlink(test_pyc)
    os.unlink(test_py)

def test_native_loader_status():
    """Test that native loader components are present"""
    print_test("Testing native loader status")
    
    # Check if veriduct_prime.py has the loader
    with open('veriduct_prime.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = [
        ('TLS callbacks', '_execute_tls_callbacks'),
        ('SEH registration', '_setup_seh'),
        ('Delay-load imports', '_resolve_pe_delay_imports'),
        ('ELF dynamic linking', '_parse_elf_dynamic'),
        ('ELF relocations', '_resolve_elf_relocations'),
        ('Section parsing', '_parse_elf_sections'),
    ]
    
    for name, marker in checks:
        if marker in content:
            print_pass(f"{name}: Present")
        else:
            print_fail(f"{name}: Missing")

def main():
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}VERIDUCT PRIME TEST SUITE{RESET}")
    print(f"{BLUE}{'='*70}{RESET}")
    
    # Check veriduct_prime.py exists
    if not Path('veriduct_prime.py').exists():
        print_fail("veriduct_prime.py not found in current directory")
        return 1
    
    # Test 1: Native loader status
    test_native_loader_status()
    
    # Test 2: Create test binary
    test_pyc, test_py = create_test_binary()
    
    # Test 3: Annihilate
    result = test_annihilate(test_pyc)
    if not result:
        print_fail("Cannot continue without successful annihilation")
        return 1
    
    tmpdir, keymap, chunks_db = result
    
    # Test 4: Semantic execution
    test_semantic_execution(keymap)
    
    # Test 5: Reassemble
    with tempfile.TemporaryDirectory() as reassemble_dir:
        reassembled = test_reassemble(keymap, reassemble_dir)
        
        if reassembled:
            # Test 6: Integrity
            test_integrity_verification(test_pyc, reassembled)
    
    # Test 7: Advanced features
    test_advanced_features()
    
    # Cleanup
    try:
        os.unlink(test_pyc)
        os.unlink(test_py)
        # Clean up the annihilation temp dir
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    except:
        pass
    
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{GREEN}TEST SUITE COMPLETE{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
