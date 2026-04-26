# Veriduct Prime Architecture

## Overview

Veriduct Prime implements **format destruction** — a technique that annihilates binary file formats into unrecognizable chunks that can be perfectly reconstructed or executed semantically from memory.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        VERIDUCT PRIME ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────┐    ┌───────────────┐    ┌────────────────┐               │
│  │  SOURCE  │───►│  ANNIHILATOR  │───►│  CHUNK STORE   │               │
│  │  BINARY  │    │               │    │  (SQLite DB)   │               │
│  └──────────┘    │  - Chunking   │    └────────────────┘               │
│                  │  - SSM        │              │                       │
│                  │  - Entangle   │              │                       │
│                  │  - Poison     │              ▼                       │
│                  └───────────────┘    ┌────────────────┐               │
│                         │             │    KEYMAP      │               │
│                         │             │  (Compressed)  │               │
│                         │             └────────────────┘               │
│                         │                      │                       │
│           ┌─────────────┴──────────────────────┴───────────┐          │
│           │                                                │          │
│           ▼                                                ▼          │
│  ┌────────────────┐                            ┌────────────────┐     │
│  │  REASSEMBLER   │                            │ NATIVE LOADER  │     │
│  │                │                            │                │     │
│  │  - Stream      │                            │  - PE Loader   │     │
│  │  - Unshatter   │                            │  - ELF Loader  │     │
│  │  - Disentangle │                            │  - Memory Exec │     │
│  │  - Write File  │                            │  - No Disk I/O │     │
│  └────────────────┘                            └────────────────┘     │
│           │                                            │              │
│           ▼                                            ▼              │
│  ┌────────────────┐                            ┌────────────────┐     │
│  │  RECONSTRUCTED │                            │   IN-MEMORY    │     │
│  │    BINARY      │                            │   EXECUTION    │     │
│  │  (Disk File)   │                            │   (No File)    │     │
│  └────────────────┘                            └────────────────┘     │
│                                                                       │
└─────────────────────────────────────────────────────────────────────────┘
```

## Core Concepts

### Format Destruction vs. Traditional Techniques

**Traditional evasion relies on transformation:**
- Encryption changes byte values but preserves structure
- Packing compresses and adds a decompression stub
- Obfuscation modifies code but maintains executability

**Veriduct destroys the format itself:**
- File headers become invalid
- Section tables become meaningless
- Import tables become noise
- The file is no longer a file — it's a substrate of chunks

### The Universal Substrate Format (USF)

Files exist as three components:

1. **Chunk Database** (`veriduct_chunks.db`)
   - SQLite database containing content fragments
   - Each chunk is content-addressed by salted SHA256
   - Optional fake chunks for substrate poisoning
   - No chunk is recognizable as part of a binary

2. **Keymap** (`veriduct_key.zst`)
   - Compressed JSON metadata
   - Contains reconstruction order
   - HMAC for tamper detection
   - File hashes for integrity verification
   - Optional: SSM seeds, entanglement info

3. **Memory Substrate** (runtime only)
   - In-memory filesystem for semantic execution
   - Binary exists only as Python bytes object
   - Never written to disk

## Data Flow

### Annihilation Pipeline

```
Input Binary
     │
     ▼
┌─────────────────────────────────────────────┐
│              READ FILE                       │
│  - Calculate SHA256 hash                     │
│  - Generate file salt                        │
│  - Detect binary type (PE/ELF/Python)        │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│              CHUNKING                        │
│  - Split into base_size chunks (4KB)         │
│  - Optional: variable sizing with jitter     │
│  - Calculate salted hash per chunk           │
└─────────────────────────────────────────────┘
     │
     ▼ (if --ssm)
┌─────────────────────────────────────────────┐
│       SEMANTIC SHATTER MAPPING              │
│  - Generate SSM seed                         │
│  - Permute bytes within each chunk           │
│  - Record null insertion positions           │
│  - Store seed in keymap                      │
└─────────────────────────────────────────────┘
     │
     ▼ (if --entanglement)
┌─────────────────────────────────────────────┐
│          XOR ENTANGLEMENT                   │
│  - Group chunks (default: 3)                 │
│  - XOR prefix accumulation                   │
│  - Seed-derived random padding               │
│  - Record group info in keymap               │
│  - Each chunk depends on predecessors        │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│           STORE CHUNKS                       │
│  - Batch insert to SQLite                    │
│  - Optional: generate fake chunks            │
│  - Compress with zstd                        │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│           BUILD KEYMAP                       │
│  - Ordered list of chunk hashes              │
│  - File metadata (name, size, hash)          │
│  - SSM/entanglement parameters               │
│  - HMAC signature                            │
│  - Compress with zstd                        │
└─────────────────────────────────────────────┘
     │
     ▼
Output: veriduct_key.zst + veriduct_chunks.db
```

### Reassembly Pipeline

```
Keymap + Chunks DB
     │
     ▼
┌─────────────────────────────────────────────┐
│            LOAD KEYMAP                       │
│  - Decompress zstd                           │
│  - Parse JSON                                │
│  - Verify HMAC                               │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│          STREAM CHUNKS                       │
│  - Query SQLite by hash                      │
│  - Maintain reconstruction order             │
│  - Skip fake chunks                          │
└─────────────────────────────────────────────┘
     │
     ▼ (if entangled)
┌─────────────────────────────────────────────┐
│          DISENTANGLE                         │
│  - Process XOR groups                        │
│  - Reverse prefix accumulation               │
│  - Restore original chunk contents           │
└─────────────────────────────────────────────┘
     │
     ▼ (if SSM)
┌─────────────────────────────────────────────┐
│           UNSHATTER                          │
│  - Load SSM seed                             │
│  - Remove null insertions                    │
│  - Reverse byte permutation                  │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│         WRITE + VERIFY                       │
│  - Concatenate chunks                        │
│  - Write to disk                             │
│  - Calculate SHA256                          │
│  - Compare with original hash                │
└─────────────────────────────────────────────┘
     │
     ▼
Reconstructed Binary (byte-perfect)
```

### Semantic Execution Pipeline

```
Keymap + Chunks DB
     │
     ▼
┌─────────────────────────────────────────────┐
│          STREAM TO MEMORY                    │
│  - Load keymap                               │
│  - Stream chunks (disentangle/unshatter)     │
│  - Assemble in MemorySubstrate               │
│  - NO DISK WRITE                             │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│         DETECT BINARY TYPE                   │
│  - Check magic bytes                         │
│  - MZ/PE → Windows executable                │
│  - ELF → Linux executable                    │
│  - .pyc magic → Python bytecode              │
└─────────────────────────────────────────────┘
     │
     ├─────────────────┬─────────────────┐
     ▼                 ▼                 ▼
┌──────────┐    ┌──────────┐    ┌──────────┐
│ PE Loader│    │ELF Loader│    │Python Exec│
└──────────┘    └──────────┘    └──────────┘
     │                 │                 │
     ▼                 ▼                 ▼
  Execute           Execute           exec()
```

## Native Loader Architecture

### PE Loader (Windows)

```
┌─────────────────────────────────────────────────────────────────┐
│                     PE LOADING SEQUENCE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. PARSE HEADERS                                               │
│     ├─ DOS Header (MZ signature)                                │
│     ├─ PE Signature                                             │
│     ├─ COFF Header (machine type, section count)                │
│     └─ Optional Header (image base, entry point, data dirs)     │
│                                                                 │
│  2. INITIALIZE STEALTH INFRASTRUCTURE                           │
│     ├─ StealthResolver: PEB walk → module list → export tables  │
│     ├─ SyscallEngine: SSN extraction, syscall;ret gadgets,      │
│     │   two-stage trampolines with RBP-chain stack spoofing     │
│     └─ Fallback: standard stealth-resolved Win32 API calls      │
│                                                                 │
│  3. ALLOCATE MEMORY                                             │
│     ├─ NtAllocateVirtualMemory (indirect syscall)               │
│     ├─ Fallback: VirtualAlloc (stealth-resolved)                │
│     └─ PAGE_READWRITE initially                                 │
│                                                                 │
│  4. MAP SECTIONS                                                │
│     ├─ .text → Code                                             │
│     ├─ .rdata → Read-only data                                  │
│     ├─ .data → Initialized data                                 │
│     └─ .bss → Uninitialized data (zero-fill)                   │
│                                                                 │
│  5. APPLY RELOCATIONS                                           │
│     ├─ Calculate delta (actual_base - preferred_base)           │
│     ├─ IMAGE_REL_BASED_HIGHLOW (32-bit)                        │
│     └─ IMAGE_REL_BASED_DIR64 (64-bit)                          │
│                                                                 │
│  6. RESOLVE IMPORTS                                             │
│     ├─ Walk Import Descriptor Table                             │
│     ├─ Hash-based resolution via StealthResolver                │
│     │   (PEB walk + PE export table parsing, no API strings)    │
│     ├─ Export forwarder resolution (recursive)                  │
│     ├─ Patch Import Address Table (IAT)                         │
│     └─ IAT hooks: Sleep/SleepEx → SleepMask callbacks           │
│                                                                 │
│  7. RESOLVE DELAY-LOAD IMPORTS                                  │
│     ├─ Walk Delay Import Descriptor                             │
│     └─ Eagerly resolve (same as normal imports)                 │
│                                                                 │
│  8. EXECUTE TLS CALLBACKS                                       │
│     ├─ Parse IMAGE_TLS_DIRECTORY                               │
│     ├─ Walk callback array                                      │
│     └─ Call each with DLL_PROCESS_ATTACH                        │
│                                                                 │
│  9. REGISTER SEH (64-bit)                                       │
│     ├─ Parse .pdata (Exception Directory)                       │
│     └─ RtlAddFunctionTable()                                   │
│                                                                 │
│  10. CRT INITIALIZATION                                        │
│      ├─ Security cookie (__security_init_cookie)                │
│      ├─ PEB.ImageBaseAddress patch                              │
│      └─ CommandLine patch (if specified)                        │
│                                                                 │
│  11. IDENTITY CLOAK (optional)                                  │
│      ├─ Enumerate target process via Toolhelp32                 │
│      ├─ ReadProcessMemory to clone PEB identity markers         │
│      │   (CommandLine, ImagePathName, CurrentDirectory, Env)    │
│      └─ Write cloned values to our own PEB                     │
│                                                                 │
│  12. APPLY SECTION PROTECTIONS                                  │
│      ├─ NtProtectVirtualMemory (indirect syscall)               │
│      ├─ Fallback: VirtualProtect (stealth-resolved)             │
│      ├─ .text → PAGE_EXECUTE_READ                               │
│      └─ .rdata → PAGE_READONLY                                  │
│                                                                 │
│  13. EXECUTE                                                    │
│      ├─ EXE: Isolated thread via module stomping                │
│      │   ├─ Priority 1: Stomp benign DLL DllMain, create thread │
│      │   │   from signed disk-backed address (NtCreateThreadEx)  │
│      │   ├─ Priority 2: NtCreateThreadEx (indirect syscall)     │
│      │   └─ Priority 3: CreateThread (fallback)                 │
│      ├─ DLL: DllMain(hInstance, DLL_PROCESS_ATTACH, NULL)      │
│      └─ Wait + cleanup (handle close, memory free)             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Indirect Syscall Engine

```
┌─────────────────────────────────────────────────────────────────┐
│                    SYSCALL ENGINE                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  INITIALIZATION                                                 │
│  ├─ Scan ntdll .text for syscall;ret (0F 05 C3) gadgets        │
│  ├─ Extract SSNs from ntdll stubs (mov eax, SSN pattern)       │
│  ├─ Hell's Gate: recover SSNs from hooked stubs via neighbors  │
│  ├─ Per-function CFG-safe gadgets from each stub               │
│  └─ Locate spoof targets (BaseThreadInitThunk, etc.)           │
│                                                                 │
│  TWO-STAGE TRAMPOLINE (per function)                            │
│  ┌──────────────────────────────────────────────┐              │
│  │ Stage 1: save rbp/r12 → spoof rbp →          │              │
│  │   [rsp]=stage2 → mov r10,rcx →               │              │
│  │   mov eax,SSN → jmp ntdll_gadget             │              │
│  ├──────────────────────────────────────────────┤              │
│  │ Stage 2: restore rbp → push r12 →             │              │
│  │   restore r12 → ret                           │              │
│  ├──────────────────────────────────────────────┤              │
│  │ Data: saved_rbp | saved_r12 |                 │              │
│  │   fake_frame_0 (→kernel32) |                  │              │
│  │   fake_frame_1 (→ntdll)                       │              │
│  └──────────────────────────────────────────────┘              │
│                                                                 │
│  RESULT                                                         │
│  ├─ Syscall executes from ntdll address space                  │
│  ├─ Call stack shows kernel32 → ntdll ancestry                 │
│  └─ Userland hooks bypassed entirely                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Annihilation Sleep Mask

```
┌─────────────────────────────────────────────────────────────────┐
│                    SLEEP MASK CYCLE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PE calls Sleep() → IAT hook fires                              │
│       │                                                         │
│       ▼                                                         │
│  1. CAPTURE — ctypes.string_at(pe_base, pe_size)               │
│       │                                                         │
│       ▼                                                         │
│  2. SCATTER — SSM shatter + XOR entangle + chunk                │
│     Chunks become Python bytearray objects in managed heap      │
│       │                                                         │
│       ▼                                                         │
│  3. FREE — VirtualFree(pe_base, MEM_DECOMMIT)                  │
│     PE region decommitted. Pages released. VA reserved.         │
│     Nothing for memory scanners to find.                        │
│       │                                                         │
│       ▼                                                         │
│  4. SLEEP — NtDelayExecution (indirect syscall + stack spoof)   │
│     PE does not exist in memory during this window.             │
│       │                                                         │
│       ▼                                                         │
│  5. RECONSTRUCT — VirtualAlloc(pe_base, MEM_COMMIT)            │
│     Disentangle → unshatter → memmove → re-apply protections   │
│     PE resumes as if Sleep() returned normally.                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### ELF Loader (Linux)

```
┌─────────────────────────────────────────────────────────────────┐
│                     ELF LOADING SEQUENCE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PRIMARY PATH: memfd_create + fork/execveat (kernel 3.19+)      │
│                                                                 │
│  1. CREATE MEMFD                                                │
│     ├─ memfd_create("veriduct", MFD_CLOEXEC)                   │
│     └─ Write ELF binary to anonymous fd                         │
│                                                                 │
│  2. FORK                                                        │
│     ├─ Child: execveat(fd, "", argv, envp, AT_EMPTY_PATH)      │
│     │   Kernel handles: stack layout (argc/argv/envp/auxv),     │
│     │   dynamic linking, PIE ASLR, TLS, init/fini arrays        │
│     └─ Parent: waitpid()                                       │
│                                                                 │
│  3. RESULT                                                      │
│     ├─ Standard glibc-linked binaries work correctly            │
│     ├─ Fileless — memfd never touches disk                      │
│     └─ Exit code propagated to caller                           │
│                                                                 │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
│                                                                 │
│  FALLBACK PATH: direct mmap (old kernels / -nostdlib only)      │
│                                                                 │
│  1. PARSE HEADERS                                               │
│     ├─ ELF Magic (0x7F 'E' 'L' 'F')                            │
│     ├─ ELF Header (class, machine, entry point)                 │
│     ├─ Program Headers (PT_LOAD segments)                       │
│     └─ Section Headers (for symbols)                            │
│                                                                 │
│  2. ALLOCATE + MAP                                              │
│     ├─ mmap(MAP_ANONYMOUS | MAP_PRIVATE)                       │
│     ├─ Copy PT_LOAD segments, zero BSS                          │
│     └─ Resolve dynamic section + apply relocations              │
│                                                                 │
│  3. EXECUTE                                                     │
│     ├─ CFUNCTYPE(c_int)(entry_point)                            │
│     └─ WARNING: glibc _start expects kernel stack layout —      │
│        only -nostdlib static binaries survive this path          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Storage Layer

### Chunk Database Schema

```sql
CREATE TABLE chunks (
    hash TEXT PRIMARY KEY,    -- Salted SHA256 of chunk data
    data BLOB,                -- Compressed chunk content
    is_fake INTEGER DEFAULT 0 -- 1 if substrate poisoning
);
```

### Keymap Structure (JSON)

```json
{
    "version": 7,
    "files": [
        {
            "name": "target.exe",
            "original_hash": "abc123...",
            "size": 78336,
            "chunks": [
                {"hash": "chunk_hash_1", "size": 4096},
                {"hash": "chunk_hash_2", "size": 4096}
            ],
            "ssm": {
                "enabled": true,
                "seed": "base64_encoded_seed",
                "null_positions": [[0, 15, 42], [7, 23]]
            },
            "entanglement": {
                "enabled": true,
                "groups": [
                    {
                        "idxs": [0,1,2],
                        "maxlen": 4096,
                        "original_lengths": [4096,4096,4096],
                        "padding_seed": "base64_encoded_seed"
                    }
                ]
            }
        }
    ],
    "salt": "base64_encoded_salt",
    "hmac": "signature_for_tamper_detection",
    "created": "2026-04-26T12:00:00Z",
    "chunks_db": "veriduct_chunks.db"
}
```

## Cryptographic Components

### Content Addressing

```python
def calculate_salted_chunk_hash(salt: bytes, chunk_data: bytes) -> str:
    return hashlib.sha256(salt + chunk_data).hexdigest()
```

- Salt is random per annihilation (prevents rainbow tables)
- Same content produces different hashes in different runs
- Prevents chunk correlation across operations

### Integrity Verification

```python
def calculate_hmac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()
```

- HMAC protects keymap from tampering
- Key derived from file salt
- Verification before reconstruction/execution

## Anti-Analysis Features

### Semantic Shatter Mapping (SSM)

```
Original chunk:    [A B C D E F G H]
                        │
                   Deterministic shuffle
                   (seeded by ssm_seed)
                        │
                        ▼
Shattered chunk:   [D H A F C B G E] + nulls inserted
```

- Bytes within each chunk are permuted
- Deterministic based on seed (reversible)
- Optional null byte insertion (configurable rate)
- Breaks byte-level pattern matching

### XOR Entanglement

```
Chunks:     C1        C2        C3
            │         │         │
            ▼         ▼         ▼
Entangled:  C1    C1⊕C2   C1⊕C2⊕C3

To recover C2, you need C1 and the entangled value.
To recover C3, you need C1, C2, and the entangled value.
```

- Chunks become interdependent
- Single chunk analysis reveals nothing
- Must have all chunks in group to recover any
- Padding uses seed-derived random bytes (no frequency artifacts)

### Substrate Poisoning

```
Real chunks:  [R1] [R2] [R3] [R4]
Fake chunks:  [F1] [F2]
Database:     [R1] [F1] [R2] [F2] [R3] [R4]
```

- Fake chunks added with random content
- Same hash algorithm (indistinguishable)
- Increases forensic analysis complexity
- Ratio configurable (default: 25%)

### Annihilation Sleep Mask

```
During execution:    PE image lives at 0x140000000
                          │
                     Sleep() called
                          │
                          ▼
During sleep:        PE image does not exist
                     Chunks are Python objects in managed heap
                     Memory scanners find nothing
                          │
                     NtDelayExecution returns
                          │
                          ▼
After sleep:         PE image reconstructed at 0x140000000
                     Execution resumes normally
```

- Not encrypted, not obfuscated — the PE is genuinely absent from memory
- Chunks are indistinguishable from normal Python application data
- Sleep performed via indirect syscall with spoofed call stack
- Uses MEM_DECOMMIT (VA reservation survives, re-commit guaranteed)

## Security Considerations

### What Veriduct Provides

1. **Format evasion** — Binary signatures don't match
2. **Fileless execution** — No artifact on disk
3. **Tamper detection** — HMAC verification
4. **Perfect reconstruction** — Byte-level integrity
5. **Runtime stealth** — Indirect syscalls, stack spoofing, sleep mask, identity cloak, module stomping

### What Veriduct Does NOT Provide

1. **Confidentiality** — Anyone with keymap can reconstruct
2. **Encryption** — Content is chunked, not encrypted
3. **Kernel-level evasion** — Token SID, integrity level, EPROCESS ImageFileName are kernel-enforced and cannot be modified
4. **Code signing bypass** — Reconstructed binary is unsigned

### Operational Security

For confidentiality, encrypt the keymap separately:

```bash
# Encrypt keymap with GPG
gpg -c veriduct_key.zst

# Or with OpenSSL
openssl enc -aes-256-cbc -salt -in veriduct_key.zst -out veriduct_key.zst.enc
```

## Performance Characteristics

| Operation | Complexity | Typical Speed |
|-----------|------------|---------------|
| Annihilate | O(n) | ~100 MB/s |
| Reassemble | O(n) | ~150 MB/s |
| Semantic Exec | O(n) + loader | ~50 MB/s |

- SQLite WAL mode for concurrent reads
- Batch chunk insertion (1000 chunks/transaction)
- Streaming disentanglement (memory efficient)
- zstd compression (fast + good ratio)

## Future Architecture

Planned enhancements:

1. **Distributed chunks** — Chunks across multiple storage backends
2. **Key splitting** — Shamir's secret sharing for keymap
3. **Steganographic storage** — Chunks embedded in images
4. **Platform expansion** — macOS Mach-O support
5. **Remote execution** — Semantic execution over network
