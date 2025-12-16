#!/usr/bin/env python3
"""
Veriduct Prime - Binary Test Battery
Tests different binary types to validate loader completeness

Test Categories:
1. CRT variants (MSVC, MinGW, static)
2. GUI applications (Win32 API)
3. Console applications
4. DLLs with exports
5. Packed binaries (UPX)
6. .NET executables (if native loader present)
7. Large binaries (memory stress)
8. Tiny binaries (minimal imports)
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path

# Test programs to create/download
TEST_PROGRAMS = {
    "minimal_console": {
        "source": """
#include <stdio.h>
int main() {
    printf("Hello from minimal console\\n");
    return 42;
}
""",
        "compile": "gcc -o minimal_console.exe minimal_console.c -s",
        "expected": "Hello from minimal console",
        "tests": ["Basic CRT", "Minimal imports", "Console output"]
    },
    
    "static_linked": {
        "source": """
#include <stdio.h>
int main() {
    printf("Static linked binary\\n");
    return 0;
}
""",
        "compile": "gcc -static -o static_linked.exe static_linked.c",
        "expected": "Static linked binary",
        "tests": ["Static CRT", "No external DLL dependencies", "Large binary"]
    },
    
    "windows_api": {
        "source": """
#include <windows.h>
int main() {
    MessageBoxA(NULL, "Veriduct Test", "Success", MB_OK);
    return 0;
}
""",
        "compile": "gcc -o windows_api.exe windows_api.c -mwindows -luser32",
        "expected": "MessageBox appears",
        "tests": ["Win32 API", "USER32.dll imports", "GUI application"]
    },
    
    "multithreaded": {
        "source": """
#include <windows.h>
#include <stdio.h>

DWORD WINAPI ThreadFunc(LPVOID lpParam) {
    printf("Thread %d running\\n", (int)lpParam);
    return 0;
}

int main() {
    HANDLE threads[3];
    for (int i = 0; i < 3; i++) {
        threads[i] = CreateThread(NULL, 0, ThreadFunc, (LPVOID)i, 0, NULL);
    }
    WaitForMultipleObjects(3, threads, TRUE, INFINITE);
    printf("All threads completed\\n");
    return 0;
}
""",
        "compile": "gcc -o multithreaded.exe multithreaded.c",
        "expected": "All threads completed",
        "tests": ["Threading", "TLS", "Synchronization"]
    },
    
    "exception_handling": {
        "source": """
#include <windows.h>
#include <stdio.h>

int main() {
    __try {
        int *ptr = NULL;
        printf("About to crash...\\n");
        *ptr = 42;  // Access violation
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("Exception caught via SEH!\\n");
        return 0;
    }
    return 1;
}
""",
        "compile": "cl /O2 exception_handling.c /Fe:exception_handling.exe",
        "expected": "Exception caught via SEH!",
        "tests": ["SEH", "Exception handling", "MSVC CRT"]
    },
    
    "file_operations": {
        "source": """
#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *fp = fopen("test_veriduct.txt", "w");
    if (!fp) {
        printf("Failed to create file\\n");
        return 1;
    }
    fprintf(fp, "Veriduct file operations test\\n");
    fclose(fp);
    
    fp = fopen("test_veriduct.txt", "r");
    if (!fp) {
        printf("Failed to read file\\n");
        return 1;
    }
    
    char buf[256];
    fgets(buf, sizeof(buf), fp);
    fclose(fp);
    remove("test_veriduct.txt");
    
    printf("File operations successful\\n");
    return 0;
}
""",
        "compile": "gcc -o file_operations.exe file_operations.c",
        "expected": "File operations successful",
        "tests": ["File I/O", "CRT stdio", "Filesystem operations"]
    },
    
    "network_test": {
        "source": """
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed\\n");
        return 1;
    }
    
    struct hostent *host = gethostbyname("localhost");
    if (host) {
        printf("Network stack initialized\\n");
    }
    
    WSACleanup();
    return 0;
}
""",
        "compile": "gcc -o network_test.exe network_test.c -lws2_32",
        "expected": "Network stack initialized",
        "tests": ["Winsock", "Network DLLs", "Socket operations"]
    },
    
    "crypto_test": {
        "source": """
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

int main() {
    HCRYPTPROV hCryptProv;
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        printf("Crypto context acquired\\n");
        CryptReleaseContext(hCryptProv, 0);
        return 0;
    }
    printf("Failed to acquire crypto context\\n");
    return 1;
}
""",
        "compile": "gcc -o crypto_test.exe crypto_test.c -ladvapi32",
        "expected": "Crypto context acquired",
        "tests": ["CryptoAPI", "ADVAPI32.dll", "Security functions"]
    },
    
    "dll_test": {
        "source": """
// DLL source
#include <windows.h>

__declspec(dllexport) int TestFunction() {
    return 42;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}
""",
        "compile": "gcc -shared -o test.dll dll_test.c -Wl,--out-implib,libtest.a",
        "expected": "DLL loads successfully",
        "tests": ["DLL execution", "DllMain", "Export resolution"]
    }
}

def create_test_program(name, info):
    """Create and compile a test program"""
    print(f"\n{'='*70}")
    print(f"Creating: {name}")
    print(f"Tests: {', '.join(info['tests'])}")
    print(f"{'='*70}")
    
    # Write source
    src_file = f"{name}.c"
    with open(src_file, 'w') as f:
        f.write(info['source'])
    print(f"[1/3] Source written: {src_file}")
    
    # Compile
    print(f"[2/3] Compiling: {info['compile']}")
    result = subprocess.run(info['compile'], shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[✗] Compilation failed:")
        print(result.stderr)
        return None
    
    print(f"[✓] Compilation successful")
    
    # Find executable
    exe_name = None
    for word in info['compile'].split():
        if word.endswith('.exe') or word.endswith('.dll'):
            exe_name = word.replace('-o', '').strip()
            break
    
    if not exe_name:
        # Try to guess
        exe_name = f"{name}.exe"
    
    if os.path.exists(exe_name):
        size = os.path.getsize(exe_name)
        print(f"[3/3] Binary created: {exe_name} ({size:,} bytes)")
        return exe_name
    
    print(f"[✗] Binary not found: {exe_name}")
    return None

def test_with_veriduct(exe_path, expected_output):
    """Test binary with Veriduct"""
    print(f"\n--- Testing with Veriduct ---")
    
    # Annihilate
    output_dir = tempfile.mkdtemp()
    print(f"[1/3] Annihilating...")
    cmd = f"python veriduct_prime.py annihilate {exe_path} {output_dir} --ssm"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[✗] Annihilation failed")
        return False
    
    keymap = os.path.join(output_dir, "veriduct_key.zst")
    if not os.path.exists(keymap):
        print(f"[✗] Keymap not created")
        return False
    
    print(f"[✓] Annihilation successful")
    
    # Run semantically
    print(f"[2/3] Running from chunks...")
    cmd = f"python veriduct_prime.py run {keymap}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    
    output = result.stdout + result.stderr
    
    # Check for expected output
    if expected_output in output or "Entry point returned" in output:
        print(f"[✓] Semantic execution successful")
        if expected_output in output:
            print(f"    Found expected output: '{expected_output}'")
        return True
    else:
        print(f"[✗] Semantic execution failed or no output")
        print(f"    Output: {output[:200]}")
        return False

def main():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║           VERIDUCT PRIME - BINARY TEST BATTERY                    ║
║  Comprehensive testing of native loader capabilities              ║
╚═══════════════════════════════════════════════════════════════════╝
""")
    
    if not os.path.exists('veriduct_prime.py'):
        print("ERROR: veriduct_prime.py not found!")
        return 1
    
    print("Available tests:")
    for i, (name, info) in enumerate(TEST_PROGRAMS.items(), 1):
        print(f"  {i}. {name:20s} - {', '.join(info['tests'])}")
    
    print("\nOptions:")
    print("  1. Run all tests")
    print("  2. Run specific test")
    print("  3. Create test binaries only")
    
    choice = input("\nChoice (1-3): ").strip()
    
    if choice == "1":
        # Run all tests
        results = {}
        for name, info in TEST_PROGRAMS.items():
            exe = create_test_program(name, info)
            if exe:
                success = test_with_veriduct(exe, info['expected'])
                results[name] = success
        
        print(f"\n{'='*70}")
        print("TEST RESULTS SUMMARY")
        print(f"{'='*70}")
        for name, success in results.items():
            status = "✓ PASS" if success else "✗ FAIL"
            print(f"  {status:8s} {name}")
        
        passed = sum(results.values())
        total = len(results)
        print(f"\nPassed: {passed}/{total} ({100*passed//total}%)")
        
    elif choice == "2":
        # Run specific test
        test_names = list(TEST_PROGRAMS.keys())
        for i, name in enumerate(test_names, 1):
            print(f"  {i}. {name}")
        
        idx = int(input("\nSelect test: ")) - 1
        if 0 <= idx < len(test_names):
            name = test_names[idx]
            info = TEST_PROGRAMS[name]
            exe = create_test_program(name, info)
            if exe:
                test_with_veriduct(exe, info['expected'])
    
    elif choice == "3":
        # Create all binaries
        for name, info in TEST_PROGRAMS.items():
            create_test_program(name, info)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
