# Veriduct Prime - Known Limitations

## Platform Support

### Windows PE — Production Ready

Fully functional for console applications, tools, and agents.

**What works:**
- Section mapping with memory protections
- Base relocation (ASLR)
- Import resolution via hash-based lookup
- Export forwarder resolution (recursive)
- Delay-load imports
- TLS callbacks
- SEH registration (64-bit)
- DLL dependency loading
- Multi-threaded applications
- Network applications (Winsock, WinINet)
- Cryptographic applications (CryptoAPI)
- Static-linked binaries
- Indirect syscalls with RBP-chain stack spoofing
- Annihilation sleep mask (Sleep/SleepEx IAT hook — PE destroyed during sleep, reconstructed on wake)
- Module stomping for thread creation (thread origin in signed disk-backed DLL)

**Test results:** 100% pass rate on Windows test suite (StealthResolver, WINFUNCTYPE, PE execution, threading, network, crypto, file I/O).

### Linux ELF — Production Ready (kernel 3.19+)

Primary path uses `memfd_create` + `fork`/`execveat`. The kernel handles stack initialization (argc, argv, envp, auxiliary vector), dynamic linking, PIE ASLR, TLS, and init/fini arrays. Stays fileless — memfd never touches disk.

**What works:**
- ELF header parsing
- Program header loading
- Section mapping
- Dynamic linking (GOT/PLT)
- Relocations (REL/RELA)
- Standard glibc-linked binaries
- PIE executables

**Known limitation:** Requires `memfd_create` (kernel 3.17+) and `execveat` (kernel 3.19+). On older kernels, falls back to direct mmap + ctypes call, which only works for static binaries compiled with `-nostdlib`. Standard glibc-linked binaries will segfault on the fallback path because `_start` expects the kernel's stack layout.

**Workaround for fallback path:** Use reassemble mode:
```bash
python veriduct_prime.py reassemble keymap.zst output/
./output/binary
```

---

## What Doesn't Work

### GUI Applications (Windows)
Basic windowed applications work (message loop, GDI). Applications that depend on Common Controls v6 or SxS activation contexts (themed UI, modern dialogs) may have issues.

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
Annihilate and run should use the same Python version. Marshal format changes between versions can cause issues. The `.pyc` header size is now detected dynamically (8/12/16 bytes depending on Python version), which improves cross-version tolerance but doesn't eliminate marshal incompatibility.

### CFG-Enabled Targets (Windows)
Indirect syscall trampolines use per-function gadgets sourced from each function's own ntdll stub for CFG safety. If a stub is hooked, the gadget is borrowed from a clean neighbor. Edge case: if all neighboring stubs are hooked, falls back to the global gadget, which may not be CFG-valid.

---

## Recommendations

**Use semantic execution (run mode) for:**
- Windows PE console applications
- Tools and utilities
- Agents
- Network tools
- Static-linked binaries
- Linux ELF binaries (kernel 3.19+)

**Use reassemble mode for:**
- Linux ELF on pre-3.19 kernels
- Windows GUI applications
- DLLs
- Any binary that fails in run mode

---

## Future Work
- 32-bit SEH support
- GUI activation context
- macOS Mach-O support
- ELF: WoW64 / cross-arch execution

---

*Last updated: April 2026*
