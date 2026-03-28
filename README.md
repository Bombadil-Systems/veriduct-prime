# Veriduct Prime

**Format Destruction Framework for Binary Manipulation**

Veriduct destroys executable file formats into unrecognizable chunks, then executes them directly from memory without ever writing a file to disk. Security tools can't detect what doesn't exist.

```
┌──────────────┐          ┌─────────────────┐          ┌──────────────┐
│              │          │                 │          │              │
│  EXECUTABLE  │  ─────►  │  1,674 CHUNKS   │  ─────►  │   EXECUTE    │
│   58/72 AV   │          │    0/72 AV      │          │  FROM MEMORY │
│              │          │                 │          │              │
└──────────────┘          └─────────────────┘          └──────────────┘
     Detected               Undetectable                 No file on disk
```

## What It Does

1. **Annihilate** — Split a binary into chunks that individually contain no recognizable signatures
2. **Execute** — Stream chunks into memory and run natively, without reconstructing the file
3. **Reassemble** — Optionally rebuild the original binary byte-for-byte (proves integrity)

The file format is destroyed, not encrypted or obfuscated. Each chunk is meaningless in isolation. Only the keymap knows how to interpret them.

## Why It Matters

| Approach | Detection Surface | Reversible? |
|----------|------------------|-------------|
| Encryption | Entropy patterns, headers | Yes (with key) |
| Packing | Unpacker stubs, signatures | Yes (at runtime) |
| Obfuscation | Heuristics, behavior | Partially |
| **Veriduct** | **Nothing exists to scan** | **Yes (byte-perfect)** |

Traditional evasion transforms the payload. Veriduct eliminates it until the moment of execution.

## Quick Start

```bash
# Clone and install
git clone https://github.com/bombadil-systems/veriduct-prime.git
cd veriduct-prime
pip install -r requirements.txt

# Destroy a binary
python src/veriduct_prime.py annihilate payload.exe output/ --ssm --verbose

# Execute from chunks (no file written)
python src/veriduct_prime.py run output/veriduct_key.zst --verbose

# Execute disguised as svchost
python src/veriduct_prime.py run output/veriduct_key.zst --cloak svchost --verbose

# Or verify reconstruction integrity
python src/veriduct_prime.py reassemble output/veriduct_key.zst rebuilt/
sha256sum payload.exe rebuilt/payload.exe  # Identical
```

## How It Works

### Annihilation

The binary is split into chunks (default 4KB). Optional transformations:

- **SSM (Semantic Shatter Mapping)** — Permutes bytes within chunks using a deterministic seed
- **XOR Entanglement** — Makes chunks mathematically dependent on each other
- **Substrate Poisoning** — Injects fake chunks to confuse analysis

Output: A chunk database (SQLite) and a keymap containing reconstruction metadata with HMAC integrity verification.

### Execution

The native loader streams chunks from the database and builds the executable in memory:

1. Parse PE headers from chunk stream
2. Allocate memory with correct section protections (RX, RW, etc.)
3. Apply base relocations for ASLR
4. Resolve imports via hash-based lookup (no string references in memory)
5. Process TLS callbacks
6. Register SEH handlers (x64)
7. Apply Identity Cloak (if enabled) — clone PEB markers from a live process
8. Jump to entry point

No file is written. The executable exists only in allocated memory pages.

### Identity Cloak

New in v2.2. At runtime, Veriduct can masquerade as another process by cloning PEB identity markers from a real running instance of the target.

Rather than hardcoding fake strings, the cloak enumerates live processes via Toolhelp32, opens a matching instance with `ReadProcessMemory`, and copies its actual PEB values onto the current process. The disguise is an exact replica of something already on the box.

**What it clones (user-mode, PEB-level — assumed by most tools, not kernel-verified):**
- `CommandLine`
- `ImagePathName`
- `CurrentDirectory`
- Environment variables (`USERNAME`, `USERDOMAIN`)

**What it cannot modify (kernel-enforced):**
- Token SID, Integrity Level, Session ID, `EPROCESS.ImageFileName`

All API resolution goes through `StealthResolver` — no `ctypes.windll` calls during cloak setup. Allocated buffers are tracked and freed on restore.

### Technical Implementation

**Import Resolution (StealthResolver)**

Instead of standard `GetProcAddress` with string names, Veriduct uses hash-based resolution:

```python
# No "CreateFileW" string anywhere
hash = 0x7c0017a5  # Pre-computed hash of "CreateFileW"
addr = resolve_by_hash("kernel32.dll", hash)
```

This eliminates string-based detection of suspicious API usage.

**Native Syscall Proxying**

Windows API calls are made through `ctypes` with proper `WINFUNCTYPE` declarations, ensuring correct calling conventions and type marshaling:

```python
CreateFileW = ctypes.WINFUNCTYPE(
    wintypes.HANDLE,           # Return
    wintypes.LPCWSTR,          # lpFileName
    wintypes.DWORD,            # dwDesiredAccess
    wintypes.DWORD,            # dwShareMode
    ctypes.c_void_p,           # lpSecurityAttributes
    wintypes.DWORD,            # dwCreationDisposition
    wintypes.DWORD,            # dwFlagsAndAttributes
    wintypes.HANDLE            # hTemplateFile
)(kernel32.CreateFileW)
```

## Validation

**Test Suite: 100% Pass Rate (Windows)**

| Test | Status | Coverage |
|------|--------|----------|
| StealthResolver | ✅ | Hash-based import resolution |
| WINFUNCTYPE | ✅ | Native API calling conventions |
| PE Execution | ✅ | Full loader pipeline |
| Multithreaded | ✅ | Threading, TLS, synchronization |
| Network | ✅ | Winsock, WinINet |
| Crypto | ✅ | CryptoAPI, ADVAPI32 |
| File I/O | ✅ | Filesystem operations |

**Real-World Validation**

Tested against a multi-function agent binary:
- 78 KB executable → 1,674 chunks
- 13 DLLs loaded dynamically
- 77 imports resolved via hash lookup
- Network beaconing, command execution, file operations
- Zero crashes across extended testing

**Detection Results**

```
Original binary:     58/72 detections (VirusTotal)
Chunked format:       0/72 detections
Reassembled:         58/72 detections (proves byte-perfect reconstruction)
```

## Platform Support

### Windows PE — Production Ready
- Section mapping with memory protections
- Base relocation (HIGHLOW, DIR64)
- Import resolution (hash-based, delay-load)
- TLS callbacks
- SEH registration (RtlAddFunctionTable)
- DLL dependency loading
- Identity Cloak (live PEB clone from running processes)

### Linux ELF — Functional
- Program header loading
- Dynamic linking (GOT/PLT)
- RELA/REL relocations
- Note: Some edge cases use `reassemble` mode for reliability

## Advanced Usage

```bash
# Maximum obfuscation
python src/veriduct_prime.py annihilate binary.exe out/ \
    --ssm \
    --entanglement \
    --fake-chunks \
    --variable-chunks \
    --chunk-jitter 0.3 \
    --disguise csv \
    --verbose

# Disguise keymap as common file types
--disguise csv    # Looks like spreadsheet data
--disguise log    # Looks like application logs
--disguise config # Looks like INI configuration
```

### Identity Cloak

```bash
# Clone identity from a live svchost instance
python src/veriduct_prime.py run keymap.zst --cloak svchost

# Clone from RuntimeBroker, dllhost, or any running process
python src/veriduct_prime.py run keymap.zst --cloak RuntimeBroker

# Explicit custom identity (no enumeration)
python src/veriduct_prime.py run keymap.zst --cloak custom \
    --cloak-cmd "C:\Windows\system32\svchost.exe -k netsvcs -p" \
    --cloak-image "C:\Windows\system32\svchost.exe" \
    --cloak-dir "C:\Windows\system32" \
    --cloak-user "SYSTEM" \
    --cloak-domain "NT AUTHORITY"
```

| Flag | Description |
|------|-------------|
| `--cloak <name>` | Clone PEB from a live process (e.g. `svchost`, `RuntimeBroker`). Use `custom` for explicit values. |
| `--cloak-cmd` | Custom CommandLine (requires `--cloak custom`) |
| `--cloak-image` | Custom ImagePathName (requires `--cloak custom`) |
| `--cloak-dir` | Custom CurrentDirectory (requires `--cloak custom`) |
| `--cloak-user` | Custom USERNAME env var (requires `--cloak custom`) |
| `--cloak-domain` | Custom USERDOMAIN env var (requires `--cloak custom`) |

## Included Demo

The repository includes a proof-of-concept C2 agent demonstrating practical application:

```bash
# Server
python c2/veriduct_c2_server.py

# Agent (compile, annihilate, execute)
python src/veriduct_prime.py annihilate agent.exe chunks/ --ssm
python src/veriduct_prime.py run chunks/veriduct_key.zst
```

Features HTTP beaconing, command execution, and file transfer. Intended as a demonstration of capability, not operational tooling.

## Limitations

- **GUI Applications**: MessageBox and windowed applications have limited support
- **DLL Standalone**: DLLs require a host process (by design)
- **Self-modifying Code**: Binaries that modify their own code sections may fail
- **.NET/Managed**: CLR executables not supported (native code only)
- **Identity Cloak**: Only modifies user-mode PEB markers; kernel-level identity (`EPROCESS.ImageFileName`, token SID, integrity level) is not affected — tools that query the kernel will still see the real process identity

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for details.

## Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](QUICKSTART.md) | Get running in 5 minutes |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Technical deep-dive |
| [docs/API.md](docs/API.md) | API reference |
| [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) | Current limitations |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

## Background

Veriduct emerged from ransomware defense research. While developing file blueprint reconstruction techniques to recover encrypted files, the inverse became apparent: if file formats can be perfectly reconstructed from fragments, they can also be perfectly destructed into fragments. Veriduct applies that insight offensively.

Presented at DEF CON DC862 and BSidesROC 2026.

## Requirements

- Python 3.8+
- Windows 10/11 (PE execution) or Linux (ELF)
- Dependencies: `zstandard` (optional, falls back to zlib)

## Legal

This tool is for authorized security testing, research, and education. Users must ensure compliance with applicable laws and obtain proper authorization before use.

MIT License — See [LICENSE](LICENSE)

## Author

**Chris @ Bombadil Systems LLC**

- Website: [bombadil.systems](https://bombadil.systems)
- Research: research@bombadil.systems
- GitHub: [github.com/bombadil-systems](https://github.com/bombadil-systems)
