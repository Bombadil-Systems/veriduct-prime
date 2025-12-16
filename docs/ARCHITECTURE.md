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
│  - 0x610D0D0A → Python bytecode              │
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
│  2. ALLOCATE MEMORY                                             │
│     ├─ VirtualAlloc(size_of_image)                             │
│     ├─ PAGE_EXECUTE_READWRITE initially                         │
│     └─ Preferred base or relocated                              │
│                                                                 │
│  3. MAP SECTIONS                                                │
│     ├─ .text → Code                                             │
│     ├─ .rdata → Read-only data                                  │
│     ├─ .data → Initialized data                                 │
│     └─ .bss → Uninitialized data (zero-fill)                   │
│                                                                 │
│  4. APPLY RELOCATIONS                                           │
│     ├─ Calculate delta (actual_base - preferred_base)           │
│     ├─ IMAGE_REL_BASED_HIGHLOW (32-bit)                        │
│     └─ IMAGE_REL_BASED_DIR64 (64-bit)                          │
│                                                                 │
│  5. RESOLVE IMPORTS                                             │
│     ├─ Walk Import Descriptor Table                             │
│     ├─ LoadLibraryA(dll_name)                                  │
│     ├─ GetProcAddress(func_name or ordinal)                     │
│     └─ Patch Import Address Table (IAT)                         │
│                                                                 │
│  6. RESOLVE DELAY-LOAD IMPORTS                                  │
│     ├─ Walk Delay Import Descriptor                             │
│     └─ Eagerly resolve (same as normal imports)                 │
│                                                                 │
│  7. EXECUTE TLS CALLBACKS                                       │
│     ├─ Parse IMAGE_TLS_DIRECTORY                               │
│     ├─ Walk callback array                                      │
│     └─ Call each with DLL_PROCESS_ATTACH                        │
│                                                                 │
│  8. REGISTER SEH (64-bit)                                       │
│     ├─ Parse .pdata (Exception Directory)                       │
│     └─ RtlAddFunctionTable()                                   │
│                                                                 │
│  9. APPLY SECTION PROTECTIONS                                   │
│     ├─ VirtualProtect per section                              │
│     ├─ .text → PAGE_EXECUTE_READ                               │
│     └─ .rdata → PAGE_READONLY                                  │
│                                                                 │
│  10. JUMP TO ENTRY POINT                                        │
│      ├─ EXE: mainCRTStartup()                                  │
│      └─ DLL: DllMain(hInstance, DLL_PROCESS_ATTACH, NULL)      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### ELF Loader (Linux)

```
┌─────────────────────────────────────────────────────────────────┐
│                     ELF LOADING SEQUENCE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. PARSE HEADERS                                               │
│     ├─ ELF Magic (0x7F 'E' 'L' 'F')                            │
│     ├─ ELF Header (class, machine, entry point)                 │
│     ├─ Program Headers (PT_LOAD segments)                       │
│     └─ Section Headers (for symbols)                            │
│                                                                 │
│  2. CALCULATE MEMORY LAYOUT                                     │
│     ├─ Find min/max virtual addresses                           │
│     └─ Calculate total size (page-aligned)                      │
│                                                                 │
│  3. ALLOCATE MEMORY                                             │
│     ├─ mmap(MAP_ANONYMOUS | MAP_PRIVATE)                       │
│     └─ PROT_READ | PROT_WRITE | PROT_EXEC                      │
│                                                                 │
│  4. MAP PT_LOAD SEGMENTS                                        │
│     ├─ Copy file data                                           │
│     └─ Zero BSS (memsz > filesz)                               │
│                                                                 │
│  5. PARSE DYNAMIC SECTION                                       │
│     ├─ DT_NEEDED (shared libraries)                            │
│     ├─ DT_SYMTAB / DT_STRTAB                                   │
│     ├─ DT_RELA / DT_REL                                        │
│     └─ DT_JMPREL (PLT relocations)                             │
│                                                                 │
│  6. LOAD DEPENDENCIES                                           │
│     ├─ ctypes.CDLL(library_name)                               │
│     └─ Store handles for symbol resolution                      │
│                                                                 │
│  7. APPLY RELOCATIONS                                           │
│     ├─ R_X86_64_RELATIVE (base adjustments)                    │
│     ├─ R_X86_64_GLOB_DAT (GOT entries)                         │
│     └─ R_X86_64_JUMP_SLOT (PLT entries)                        │
│                                                                 │
│  8. JUMP TO ENTRY POINT                                         │
│     ├─ _start (for static binaries)                            │
│     └─ Note: Stack layout incomplete (see limitations)          │
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
                {"hash": "chunk_hash_2", "size": 4096},
                ...
            ],
            "ssm": {
                "enabled": true,
                "seed": "base64_encoded_seed",
                "null_positions": [[0, 15, 42], [7, 23], ...]
            },
            "entanglement": {
                "enabled": true,
                "groups": [
                    {"idxs": [0,1,2], "maxlen": 4096, "original_lengths": [4096,4096,4096]},
                    ...
                ]
            }
        }
    ],
    "salt": "base64_encoded_salt",
    "hmac": "signature_for_tamper_detection",
    "created": "2025-12-15T12:00:00Z",
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

## Security Considerations

### What Veriduct Provides

1. **Format evasion** — Binary signatures don't match
2. **Fileless execution** — No artifact on disk
3. **Tamper detection** — HMAC verification
4. **Perfect reconstruction** — Byte-level integrity

### What Veriduct Does NOT Provide

1. **Confidentiality** — Anyone with keymap can reconstruct
2. **Encryption** — Content is chunked, not encrypted
3. **Anti-debugging** — No runtime protections
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
