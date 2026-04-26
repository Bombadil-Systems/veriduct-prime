# Veriduct Prime - Quick Start Guide

Get format destruction working in 5 minutes.

## Prerequisites

- Python 3.8 or higher
- Windows 10/11 (for PE semantic execution) or Linux kernel 3.19+ (for ELF)
- ~50MB disk space

## Installation

```bash
# Clone the repository
git clone https://github.com/bombadil-systems/veriduct-prime.git
cd veriduct-prime

# Install dependencies
pip install -r requirements.txt

# Verify installation
python src/veriduct_prime.py --help
```

Expected output:
```
usage: veriduct_prime.py [-h] {annihilate,reassemble,run} ...

Veriduct Prime - Format Destruction Framework

positional arguments:
  {annihilate,reassemble,run}
    annihilate          Destroy file format into chunks
    reassemble          Reconstruct files from chunks
    run                 Execute from chunks (semantic execution)
```

## Example 1: Annihilate a Binary

Destroy a binary's file format into unrecognizable chunks.

```bash
# Create test directory
mkdir -p output

# Annihilate any .exe (using calc.exe as example)
python src/veriduct_prime.py annihilate C:\Windows\System32\calc.exe output/ --verbose
```

Expected output:
```
2026-04-26 12:00:00 [INFO] ============================================================
2026-04-26 12:00:00 [INFO] VERIDUCT PRIME - FORMAT DESTRUCTION
2026-04-26 12:00:00 [INFO] ============================================================
2026-04-26 12:00:00 [INFO] Processing: C:\Windows\System32\calc.exe
2026-04-26 12:00:00 [INFO] File size: 27,648 bytes
2026-04-26 12:00:00 [INFO] Chunking with base size: 4096 bytes
2026-04-26 12:00:00 [INFO] Created 7 chunks
2026-04-26 12:00:00 [INFO] Stored 7 chunks to database
2026-04-26 12:00:00 [INFO] Keymap written to: output/veriduct_key.zst
2026-04-26 12:00:00 [INFO] Chunks DB written to: output/veriduct_chunks.db
2026-04-26 12:00:00 [INFO] ============================================================
2026-04-26 12:00:00 [INFO] ANNIHILATION COMPLETE
2026-04-26 12:00:00 [INFO] ============================================================
```

**What happened:**
- `veriduct_key.zst` — Compressed keymap with reconstruction metadata
- `veriduct_chunks.db` — SQLite database containing format-destroyed chunks

## Example 2: Reassemble and Verify

Prove deterministic reconstruction with hash verification.

```bash
# Create output directory
mkdir -p rebuilt

# Reassemble from chunks
python src/veriduct_prime.py reassemble output/veriduct_key.zst rebuilt/ --verbose

# Verify integrity (Windows)
certutil -hashfile C:\Windows\System32\calc.exe SHA256
certutil -hashfile rebuilt\calc.exe SHA256

# Verify integrity (Linux/WSL)
sha256sum /path/to/original rebuilt/calc.exe
```

Expected output:
```
2026-04-26 12:00:05 [INFO] ============================================================
2026-04-26 12:00:05 [INFO] VERIDUCT REASSEMBLY
2026-04-26 12:00:05 [INFO] ============================================================
2026-04-26 12:00:05 [INFO] Loading keymap: output/veriduct_key.zst
2026-04-26 12:00:05 [INFO] Reassembling: calc.exe
2026-04-26 12:00:05 [INFO] Retrieved 7 chunks
2026-04-26 12:00:05 [INFO] File reassembled: rebuilt/calc.exe (27,648 bytes)
2026-04-26 12:00:05 [INFO] Integrity check: PASSED ✓
2026-04-26 12:00:05 [INFO] ============================================================
2026-04-26 12:00:05 [INFO] REASSEMBLY COMPLETE
2026-04-26 12:00:05 [INFO] ============================================================
```

**The hashes will be identical.** This proves byte-perfect reconstruction.

## Example 3: Semantic Execution (Run from Chunks)

Execute a binary directly from format-destroyed chunks without writing to disk.

```bash
# First, annihilate your target binary
python src/veriduct_prime.py annihilate mytool.exe output/ --ssm --verbose

# Execute semantically (no file ever written to disk)
python src/veriduct_prime.py run output/veriduct_key.zst --verbose
```

Expected output:
```
2026-04-26 12:00:10 [INFO] ============================================================
2026-04-26 12:00:10 [INFO] VERIDUCT SEMANTIC EXECUTION MODE
2026-04-26 12:00:10 [INFO] Files execute from chunks without disk materialization
2026-04-26 12:00:10 [INFO] Supports: Python (.pyc/.py), PE (.exe/.dll), ELF
2026-04-26 12:00:10 [INFO] ============================================================
2026-04-26 12:00:10 [INFO] Loading keymap: output/veriduct_key.zst
2026-04-26 12:00:10 [INFO] Streaming chunks to memory...
2026-04-26 12:00:10 [INFO] Detected PE binary (Windows executable)
2026-04-26 12:00:10 [INFO] SyscallEngine: Ready — 9 SSNs, gadget @ 0x7FF..., spoof targets: 2
2026-04-26 12:00:10 [INFO] PE Loader: Using INDIRECT SYSCALLS with stack frame spoofing
2026-04-26 12:00:10 [INFO] Allocated 65536 bytes at 0x... [indirect syscall]
2026-04-26 12:00:10 [INFO] Mapping 4 sections...
2026-04-26 12:00:10 [INFO] Applying relocations (delta: 0x...)
2026-04-26 12:00:10 [INFO] Resolving imports...
2026-04-26 12:00:10 [INFO] IAT Hook: Redirecting Sleep -> SleepMask @ 0x...
2026-04-26 12:00:10 [INFO] Loaded 3 DLLs
2026-04-26 12:00:10 [INFO] Module stomp: thread @ 0x... (version.dll!DllMain+0) [indirect syscall]
2026-04-26 12:00:10 [INFO] Waiting for PE thread completion...
[Binary output appears here]
2026-04-26 12:00:11 [INFO] PE thread exited with code: 0
```

**What happened:**
- Binary was streamed from chunks into memory
- PE headers were parsed
- Imports were resolved dynamically, Sleep/SleepEx hooked for annihilation sleep masking
- Thread created via module stomping (start address in a signed disk-backed DLL)
- All memory operations routed through indirect syscalls with spoofed call stacks
- **No file was ever written to disk**

## Example 4: Advanced Options

### Semantic Shatter Mapping (SSM)
Permutes bytes within chunks for additional obfuscation:

```bash
python src/veriduct_prime.py annihilate target.exe output/ --ssm --verbose
```

### XOR Entanglement
Makes chunks interdependent (can't analyze single chunk):

```bash
python src/veriduct_prime.py annihilate target.exe output/ --entanglement --verbose
```

### Substrate Poisoning
Adds fake chunks to confuse forensic analysis:

```bash
python src/veriduct_prime.py annihilate target.exe output/ --fake-chunks --fake-ratio 0.5 --verbose
```

### Disguised Keymap
Hide keymap as innocent file type:

```bash
# As CSV
python src/veriduct_prime.py annihilate target.exe output/ --disguise csv

# As log file
python src/veriduct_prime.py annihilate target.exe output/ --disguise log

# As config file
python src/veriduct_prime.py annihilate target.exe output/ --disguise conf
```

### Identity Cloak
Clone PEB identity from a live process at runtime:

```bash
# Clone from a running svchost instance
python src/veriduct_prime.py run output/veriduct_key.zst --cloak svchost

# Clone from RuntimeBroker
python src/veriduct_prime.py run output/veriduct_key.zst --cloak RuntimeBroker

# Custom identity
python src/veriduct_prime.py run output/veriduct_key.zst --cloak custom \
    --cloak-cmd "C:\Windows\System32\svchost.exe -k netsvcs" \
    --cloak-image "C:\Windows\System32\svchost.exe" \
    --cloak-dir "C:\Windows\System32"
```

### Full Stealth Mode
Combine all anti-detection features:

```bash
python src/veriduct_prime.py annihilate target.exe output/ \
    --ssm \
    --entanglement \
    --fake-chunks \
    --fake-ratio 0.3 \
    --variable-chunks \
    --chunk-jitter 0.2 \
    --disguise log \
    --blob \
    --verbose
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'zstandard'"

```bash
pip install zstandard
# Or use without zstd (falls back to zlib)
```

### "Key file not found"

Ensure the path to the keymap is correct:
```bash
ls output/  # Should show veriduct_key.zst and veriduct_chunks.db
```

### "Integrity check failed"

The chunks database may be corrupted or modified. Re-annihilate the source file:
```bash
python src/veriduct_prime.py annihilate original.exe fresh_output/ --verbose
```

### PE execution crashes immediately

Check the binary type:
- **GUI apps** — basic windowed apps work, but apps needing Common Controls v6 or SxS activation contexts may fail. Use `reassemble` if needed.
- **DLLs** can't be executed standalone — use `reassemble`
- **.NET/managed binaries** are not supported

### ELF execution issues

The primary ELF path uses `memfd_create` + `fork`/`execveat` and handles standard glibc-linked binaries. Requires kernel 3.19+. On older kernels, falls back to direct mmap which only works for `-nostdlib` static binaries.

If the memfd path fails, use `reassemble`:
```bash
python src/veriduct_prime.py reassemble key.zst output/
./output/mybinary
```

### "Failed to resolve import: KERNEL32!SomeFunction"

The binary uses APIs not present on your Windows version. Try on Windows 10/11.

### "SyscallEngine: Init failed"

Indirect syscalls unavailable — execution falls back to standard stealth-resolved API calls automatically. No action needed. This is normal on non-Windows platforms or if ntdll is heavily instrumented.

## Verification Workflow

Prove the technique works with your target:

```bash
# 1. Get original hash
sha256sum target.exe
# Output: abc123... target.exe

# 2. Annihilate
python src/veriduct_prime.py annihilate target.exe chunks/

# 3. Scan chunks with AV (should find nothing)
# Upload chunks/*.db to VirusTotal — expect 0 detections

# 4. Reassemble
python src/veriduct_prime.py reassemble chunks/veriduct_key.zst rebuilt/

# 5. Verify identical hash
sha256sum rebuilt/target.exe
# Output: abc123... rebuilt/target.exe (IDENTICAL)

# 6. Scan rebuilt with AV (should find original detections)
# Upload rebuilt/target.exe to VirusTotal — original detection count
```

## Next Steps

- Read [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for edge cases
- Review [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details

## Getting Help

- Open an [issue](https://github.com/bombadil-systems/veriduct-prime/issues)
- Contact: research@bombadil.systems
