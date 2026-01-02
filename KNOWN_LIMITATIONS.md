# Veriduct Prime - Known Limitations

## Platform Support

### Windows PE — Production Ready

Fully functional for console applications, tools, and agents.

**What works:**
- Section mapping with memory protections
- Base relocation (ASLR)
- Import resolution via hash-based lookup
- Delay-load imports
- TLS callbacks
- SEH registration (64-bit)
- DLL dependency loading
- Multi-threaded applications
- Network applications (Winsock, WinINet)
- Cryptographic applications (CryptoAPI)
- Static-linked binaries

**Test results:** 100% pass rate on Windows test suite (StealthResolver, WINFUNCTYPE, PE execution, threading, network, crypto, file I/O).

### Linux ELF — Functional with Caveats

Works for many binaries, but some edge cases require reassemble mode.

**What works:**
- ELF header parsing
- Program header loading
- Section mapping
- Dynamic linking (GOT/PLT)
- Relocations (REL/RELA)

**Known issue:** Stack initialization doesn't fully match System V ABI expectations. The loader calls the entry point via ctypes rather than setting up the kernel-style stack layout (argc, argv, envp, auxiliary vector). This can cause issues with:
- Static binaries that read argc directly
- Binaries that depend on the auxiliary vector
- Some glibc initialization paths

**Workaround:** Use reassemble mode for problematic ELF binaries:
```bash
python veriduct_prime.py reassemble keymap.zst output/
./output/binary
```

---

## What Doesn't Work

### GUI Applications (Windows)

MessageBox and windowed applications have limited support. Missing activation context for Common Controls, no manifest parsing. Console applications are the primary use case.

### DLL Direct Execution

DLLs need a host process. Use reassemble mode, then load the DLL normally.

### 32-bit SEH (Windows)

32-bit exception handling uses the FS:[0] chain, which isn't implemented. 64-bit is the primary target.

### .NET / Managed Code

CLR executables are not supported. Native code only.

### macOS

Mach-O format not implemented.

---

## Edge Cases

### API Set DLLs (Windows 10/11)

Virtual API sets (api-ms-*.dll) generally work via LoadLibrary redirection. Tested successfully with api-ms-win-crt-* imports.

### Python Version Portability

Annihilate and run should use the same Python version. Marshal format changes between versions can cause issues.

---

## Recommendations

**Use semantic execution (run mode) for:**
- Windows PE console applications
- Tools and utilities
- Agents
- Network tools
- Static-linked binaries

**Use reassemble mode for:**
- Linux ELF binaries with stack issues
- Windows GUI applications
- DLLs
- Any binary that fails in run mode

---

## Future Work

- ELF stack initialization (assembly trampoline)
- 32-bit SEH support
- GUI activation context
- macOS Mach-O support

---

*Last updated: January 2026*
