# Veriduct Prime Advanced Features

This document covers Veriduct's anti-analysis features in depth: Semantic Shatter Mapping (SSM), XOR Entanglement, Substrate Poisoning, and Disguised Keymaps.

## Semantic Shatter Mapping (SSM)

### Overview

SSM permutes bytes within each chunk using a deterministic shuffle, then optionally inserts null bytes at random positions. This breaks byte-level pattern matching and signature detection.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                  SEMANTIC SHATTER MAPPING                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Original:     [41 42 43 44 45 46 47 48]  (A B C D E F G H)    │
│                                                                 │
│                         │                                       │
│                         ▼                                       │
│                 Generate SSM Seed                               │
│              (16 bytes of randomness)                           │
│                         │                                       │
│                         ▼                                       │
│                 Deterministic Shuffle                           │
│              (Fisher-Yates with seeded RNG)                     │
│                         │                                       │
│                         ▼                                       │
│                                                                 │
│  Permuted:     [44 48 41 46 43 42 47 45]  (D H A F C B G E)    │
│                                                                 │
│                         │                                       │
│                         ▼                                       │
│               Null Byte Insertion                               │
│              (configurable rate, ~1%)                           │
│                         │                                       │
│                         ▼                                       │
│                                                                 │
│  Shattered:    [44 00 48 41 46 00 43 42 47 45]                 │
│                     ↑        ↑                                  │
│              null insertions recorded in metadata               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Usage

```bash
# Enable SSM
python veriduct_prime.py annihilate target.exe output/ --ssm

# With higher null insertion rate
python veriduct_prime.py annihilate target.exe output/ --ssm --ssm-null-rate 0.05
```

### Parameters

| Parameter | Range | Default | Effect |
|-----------|-------|---------|--------|
| `--ssm` | Flag | Off | Enable SSM |
| `--ssm-null-rate` | 0.0-0.1 | 0.01 | Null insertion probability per byte |

### Security Properties

1. **Byte patterns destroyed** — No contiguous byte sequence matches original
2. **Deterministic** — Same seed produces same shuffle (reversible)
3. **Per-chunk variation** — Each chunk uses different positions from RNG stream
4. **Length obfuscation** — Null insertions change chunk sizes slightly

### Reversal

SSM is reversed during reassembly/execution:

```python
# Reversal process
1. Load SSM seed from keymap
2. Remove null bytes at recorded positions
3. Reverse the permutation using same seed
4. Original bytes restored
```

---

## XOR Entanglement

### Overview

XOR Entanglement makes chunks interdependent. To recover any chunk in a group, you need all chunks in that group. This prevents single-chunk analysis.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                     XOR ENTANGLEMENT                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Original chunks (group of 3):                                  │
│                                                                 │
│  C1 = [AA BB CC DD]                                            │
│  C2 = [11 22 33 44]                                            │
│  C3 = [FF EE DD CC]                                            │
│                                                                 │
│  Entanglement (XOR prefix accumulation):                        │
│                                                                 │
│  E1 = C1                    = [AA BB CC DD]                    │
│  E2 = C1 ⊕ C2               = [BB 99 FF 99]                    │
│  E3 = C1 ⊕ C2 ⊕ C3          = [44 77 22 55]                    │
│                                                                 │
│  Stored in database: E1, E2, E3                                │
│                                                                 │
│  ─────────────────────────────────────────────────────────────│
│                                                                 │
│  Disentanglement (to recover C2):                              │
│                                                                 │
│  C1 = E1                    = [AA BB CC DD]                    │
│  C2 = E2 ⊕ E1               = [BB 99 FF 99] ⊕ [AA BB CC DD]    │
│                             = [11 22 33 44] ✓                  │
│                                                                 │
│  You MUST have E1 to recover C2.                               │
│  You MUST have E1 and E2 to recover C3.                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Usage

```bash
# Enable entanglement with default group size (3)
python veriduct_prime.py annihilate target.exe output/ --entanglement

# Larger groups (more interdependency)
python veriduct_prime.py annihilate target.exe output/ --entanglement --entanglement-groups 5
```

### Parameters

| Parameter | Range | Default | Effect |
|-----------|-------|---------|--------|
| `--entanglement` | Flag | Off | Enable XOR entanglement |
| `--entanglement-groups` | 2+ | 3 | Chunks per entanglement group |

### Security Properties

1. **Interdependency** — No chunk reveals content alone
2. **Group isolation** — Groups are independent (partial reconstruction possible)
3. **No size increase** — XOR preserves original sizes
4. **Deterministic** — Group assignments stored in keymap

### Chunk Padding

When chunks have different sizes, they're padded to equal length for XOR:

```python
# Padding handling
- Pad shorter chunks with 0xFF
- XOR operation on padded data
- Truncate result to original length
- Store original lengths in metadata
```

### Trade-offs

| Group Size | Interdependency | Reconstruction Complexity |
|------------|-----------------|---------------------------|
| 2 | Low | Simple |
| 3 | Medium | Moderate |
| 5 | High | Complex |
| 10+ | Very High | Significant overhead |

---

## Substrate Poisoning

### Overview

Substrate Poisoning adds fake chunks to the database, making it harder to identify which chunks are real. Forensic analysis must examine all chunks or correlate with keymap.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    SUBSTRATE POISONING                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Real chunks from target.exe:                                   │
│                                                                 │
│  [R1: 4096 bytes] [R2: 4096 bytes] [R3: 2048 bytes]            │
│                                                                 │
│  Fake chunks generated:                                         │
│                                                                 │
│  [F1: 512 bytes]  [F2: 2048 bytes] [F3: 4096 bytes]            │
│       random           random           random                  │
│                                                                 │
│  Database contents (interleaved):                               │
│                                                                 │
│  ┌────────────────────────────────────────────────────┐        │
│  │ hash_R1 │ hash_F1 │ hash_R2 │ hash_F2 │ hash_F3 │ ...│       │
│  │ (real)  │ (fake)  │ (real)  │ (fake)  │ (fake)  │    │       │
│  └────────────────────────────────────────────────────┘        │
│                                                                 │
│  From database alone:                                           │
│  - Cannot distinguish real from fake                            │
│  - All hashes look equally random                               │
│  - All data looks equally random                                │
│                                                                 │
│  Keymap only references real chunks (R1, R2, R3)               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Usage

```bash
# Enable with default ratio (25% fake)
python veriduct_prime.py annihilate target.exe output/ --fake-chunks

# Higher ratio (more fake chunks)
python veriduct_prime.py annihilate target.exe output/ --fake-chunks --fake-ratio 0.5

# Combined with other features
python veriduct_prime.py annihilate target.exe output/ --ssm --entanglement --fake-chunks
```

### Parameters

| Parameter | Range | Default | Effect |
|-----------|-------|---------|--------|
| `--fake-chunks` | Flag | Off | Enable substrate poisoning |
| `--fake-ratio` | 0.0-1.0 | 0.25 | Ratio of fake to real chunks |

### Fake Chunk Properties

- Random content (`os.urandom()`)
- Variable sizes: 256, 512, 1024, 2048, or 4096 bytes
- Same hash algorithm as real chunks
- Stored with `is_fake=1` flag in SQLite (for internal filtering)

### Database Schema

```sql
CREATE TABLE chunks (
    hash TEXT PRIMARY KEY,
    data BLOB,
    is_fake INTEGER DEFAULT 0  -- 1 for fake, 0 for real
);
```

**Note:** The `is_fake` column is for internal use. An attacker examining the database must check the keymap to know which chunks are real.

### Forensic Resistance

| Fake Ratio | Real Chunks | Fake Chunks | Analysis Complexity |
|------------|-------------|-------------|---------------------|
| 0.0 | 100 | 0 | Low |
| 0.25 | 100 | 25 | Moderate |
| 0.5 | 100 | 50 | High |
| 1.0 | 100 | 100 | Very High |

---

## Disguised Keymaps

### Overview

Keymaps can be disguised as innocent file types: CSV data, log files, or config files. The actual keymap data is base64-encoded and embedded within the disguise format.

### Format: CSV

```csv
id,data,timestamp
1,"system_metrics",2025-12-15T12:00:00
2,"network_stats",2025-12-15T12:00:01
3,"eJzNVk1v2zAMv...base64_keymap_data...",2025-12-15T12:00:02
```

The keymap is embedded in the data column of the last row.

### Format: Log

```
2025-12-15 12:00:00 INFO Application started
2025-12-15 12:00:01 DEBUG Loading configuration
2025-12-15 12:00:02 INFO Processing request - data:eJzNVk1v2zAMv...base64_keymap_data...
```

The keymap follows `data:` at the end of the last log line.

### Format: Config

```ini
[application]
name=SystemService
version=1.0.0

[settings]
timeout=30
retries=3

[cache]
data=eJzNVk1v2zAMv...base64_keymap_data...
```

The keymap is stored as the `data` value in the `[cache]` section.

### Usage

```bash
# Disguise as CSV
python veriduct_prime.py annihilate target.exe output/ --disguise csv

# Disguise as log file
python veriduct_prime.py annihilate target.exe output/ --disguise log

# Disguise as config file
python veriduct_prime.py annihilate target.exe output/ --disguise conf

# Use disguised keymap for reassembly
python veriduct_prime.py reassemble output/veriduct_key.csv rebuilt/ --disguise csv

# Semantic execution with disguised keymap
python veriduct_prime.py run output/system.log --disguise log
```

### Disguise Detection

When using `--disguise`, you must specify the format during reassembly/run. The parser:

1. Reads the file as the specified format
2. Extracts the base64-encoded data
3. Decodes and decompresses
4. Parses as JSON keymap

### Combined with File Extension

Rename the output file to match the disguise:

```bash
# Create disguised keymap
python veriduct_prime.py annihilate target.exe output/ --disguise csv

# Rename to match format
mv output/veriduct_key.zst output/metrics.csv

# Use with correct format
python veriduct_prime.py run output/metrics.csv --disguise csv
```

---

## Variable Chunking

### Overview

Variable chunking randomizes chunk sizes within a range, breaking patterns that might emerge from fixed-size chunking.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    VARIABLE CHUNKING                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Fixed chunking (4096 base):                                    │
│                                                                 │
│  [4096] [4096] [4096] [4096] [4096] [remainder]                │
│                                                                 │
│  Variable chunking (4096 base, 0.3 jitter):                    │
│                                                                 │
│  Size range: 4096 × (1 - 0.3) to 4096 × (1 + 0.3)             │
│            = 2867 to 5324 bytes                                 │
│                                                                 │
│  [3412] [4891] [2934] [5102] [4234] [remainder]                │
│                                                                 │
│  Each chunk size is randomized within the range.               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Usage

```bash
# Enable variable chunking with default jitter
python veriduct_prime.py annihilate target.exe output/ --variable-chunks

# Custom jitter factor (0.0-0.5)
python veriduct_prime.py annihilate target.exe output/ --variable-chunks --chunk-jitter 0.4
```

### Parameters

| Parameter | Range | Default | Effect |
|-----------|-------|---------|--------|
| `--variable-chunks` | Flag | Off | Enable variable sizing |
| `--chunk-jitter` | 0.0-0.5 | 0.0 | Size variation factor |

### Jitter Examples

| Base Size | Jitter | Min Size | Max Size |
|-----------|--------|----------|----------|
| 4096 | 0.0 | 4096 | 4096 |
| 4096 | 0.1 | 3686 | 4505 |
| 4096 | 0.2 | 3276 | 4915 |
| 4096 | 0.3 | 2867 | 5324 |
| 4096 | 0.5 | 2048 | 6144 |

---

## Combining Features

### Maximum Stealth Configuration

```bash
python veriduct_prime.py annihilate target.exe output/ \
    --ssm \
    --ssm-null-rate 0.02 \
    --entanglement \
    --entanglement-groups 4 \
    --fake-chunks \
    --fake-ratio 0.4 \
    --variable-chunks \
    --chunk-jitter 0.3 \
    --disguise log \
    --verbose
```

### Feature Interaction Matrix

| Feature Combination | Effect |
|---------------------|--------|
| SSM + Entanglement | Byte permutation + interdependency |
| SSM + Poisoning | Shattered real + random fake |
| Entanglement + Poisoning | Interdependent real + noise |
| All three | Maximum anti-analysis |
| + Disguise | Keymap also hidden |
| + Variable chunks | Size patterns eliminated |

### Processing Order

Features are applied in this order during annihilation:

1. **Chunking** — Split file into chunks
2. **SSM** — Permute bytes within each chunk
3. **Entanglement** — XOR chunks into groups
4. **Storage** — Write to database
5. **Poisoning** — Add fake chunks
6. **Keymap** — Build and optionally disguise

Reversal during execution/reassembly:

1. **Load keymap** — Parse (un-disguise if needed)
2. **Stream chunks** — Read from database
3. **Disentangle** — Reverse XOR
4. **Unshatter** — Reverse SSM
5. **Concatenate** — Rebuild original bytes

---

## Performance Impact

| Feature | Annihilation | Reassembly | Execution |
|---------|--------------|------------|-----------|
| None | 1.0x | 1.0x | 1.0x |
| SSM | 1.3x | 1.3x | 1.3x |
| Entanglement | 1.1x | 1.2x | 1.2x |
| Poisoning | 1.2x | 1.0x | 1.0x |
| Variable | 1.0x | 1.0x | 1.0x |
| Disguise | 1.0x | 1.0x | 1.0x |
| All | 1.8x | 1.5x | 1.5x |

(Relative to baseline, approximate)

---

## Security Analysis

### Threat Model

Veriduct defends against:
- **Signature-based detection** — File format destroyed
- **Static analysis** — No complete binary to analyze
- **Forensic recovery** — Chunks indistinguishable without keymap
- **Pattern matching** — SSM breaks byte sequences

Veriduct does NOT defend against:
- **Behavioral analysis** — Runtime behavior unchanged
- **Memory forensics** — Binary exists in memory during execution
- **Keymap compromise** — Anyone with keymap can reconstruct

### Attack Vectors

| Attack | Defense |
|--------|---------|
| Chunk analysis | Poisoning + SSM |
| Group recovery | Entanglement |
| Size analysis | Variable chunking |
| Keymap identification | Disguise |
| Tamper detection | HMAC |

### Operational Recommendations

1. **Always use HMAC** — Detects tampering
2. **Protect the keymap** — Encrypt separately if confidentiality needed
3. **Use multiple features** — Defense in depth
4. **Match disguise to context** — CSV for data exfil, log for persistence
5. **Test before deployment** — Verify with target environment
