# Veriduct Prime API Reference

## Command Line Interface

### Global Options

```bash
veriduct_prime.py [-h] [-v] {annihilate,reassemble,run} ...
```

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-v, --version` | Show version number |

---

## annihilate

Destroy file format into chunks.

### Usage

```bash
veriduct_prime.py annihilate INPUT OUTPUT [OPTIONS]
```

### Required Arguments

| Argument | Description |
|----------|-------------|
| `INPUT` | Path to file or directory to annihilate |
| `OUTPUT` | Output directory for chunks and keymap |

### Options

#### Chunk Control

| Option | Default | Description |
|--------|---------|-------------|
| `--chunk-size SIZE` | 4096 | Base chunk size in bytes |
| `--variable-chunks` | False | Enable variable-size chunking |
| `--chunk-jitter FLOAT` | 0.0 | Jitter factor (0.0-0.5) for variable chunks |
| `--wipe-bytes SIZE` | 256 | USF wipe size (header destruction) |

#### Anti-Analysis

| Option | Default | Description |
|--------|---------|-------------|
| `--ssm` | False | Enable Semantic Shatter Mapping |
| `--ssm-null-rate FLOAT` | 0.01 | Null insertion rate (0.0-0.1) |
| `--entanglement` | False | Enable XOR entanglement |
| `--entanglement-groups INT` | 3 | Size of entanglement groups |
| `--fake-chunks` | False | Enable substrate poisoning |
| `--fake-ratio FLOAT` | 0.25 | Ratio of fake to real chunks |

#### Security

| Option | Default | Description |
|--------|---------|-------------|
| `--no-hmac` | False | Disable HMAC tamper detection |
| `--disguise FORMAT` | None | Disguise keymap as format (csv/log/conf) |

#### Output

| Option | Default | Description |
|--------|---------|-------------|
| `--blob` | False | Create self-executing blob (.vdb) |
| `--blob-output PATH` | None | Custom blob output path |
| `--blob-quiet` | False | Suppress blob runtime output |
| `--verbose` | False | Enable verbose logging |
| `--force-internal` | False | Allow output inside input path |

### Examples

```bash
# Basic annihilation
python veriduct_prime.py annihilate target.exe output/

# Full stealth mode
python veriduct_prime.py annihilate target.exe output/ \
    --ssm \
    --entanglement \
    --fake-chunks \
    --disguise log \
    --verbose

# Variable chunking with jitter
python veriduct_prime.py annihilate large.exe output/ \
    --variable-chunks \
    --chunk-jitter 0.3

# Create self-executing blob
python veriduct_prime.py annihilate agent.exe output/ --blob
```

### Output Files

| File | Description |
|------|-------------|
| `veriduct_key.zst` | Compressed keymap (or disguised format) |
| `veriduct_chunks.db` | SQLite database containing chunks |
| `*.vdb` | Self-executing blob (if --blob) |

---

## reassemble

Reconstruct files from chunks.

### Usage

```bash
veriduct_prime.py reassemble KEYMAP OUTPUT [OPTIONS]
```

### Required Arguments

| Argument | Description |
|----------|-------------|
| `KEYMAP` | Path to keymap file (veriduct_key.zst) |
| `OUTPUT` | Output directory for reconstructed files |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--disguise FORMAT` | None | Specify keymap disguise format |
| `--ignore-integrity` | False | Ignore integrity check failures |
| `--verbose` | False | Enable verbose logging |

### Examples

```bash
# Basic reassembly
python veriduct_prime.py reassemble chunks/veriduct_key.zst rebuilt/

# With disguised keymap
python veriduct_prime.py reassemble chunks/data.csv rebuilt/ --disguise csv

# Force reassembly despite integrity warnings
python veriduct_prime.py reassemble chunks/veriduct_key.zst rebuilt/ --ignore-integrity
```

### Integrity Verification

Reassembly automatically verifies:
1. HMAC signature (keymap not tampered)
2. Chunk availability (all chunks present)
3. SHA256 hash (reconstructed == original)

---

## run

Execute files directly from chunks (semantic execution).

### Usage

```bash
veriduct_prime.py run KEYMAP [OPTIONS]
```

### Required Arguments

| Argument | Description |
|----------|-------------|
| `KEYMAP` | Path to keymap file (veriduct_key.zst) |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--disguise FORMAT` | None | Specify keymap disguise format |
| `--ignore-integrity` | False | Ignore integrity check failures |
| `--verbose` | False | Enable verbose logging |

### Examples

```bash
# Basic semantic execution
python veriduct_prime.py run chunks/veriduct_key.zst

# With verbose output
python veriduct_prime.py run chunks/veriduct_key.zst --verbose

# Disguised keymap
python veriduct_prime.py run chunks/system.log --disguise log
```

### Supported Binary Types

| Type | Extension | Platform | Status |
|------|-----------|----------|--------|
| Windows PE | .exe | Windows | ✅ Production |
| Windows DLL | .dll | Windows | ⚠️ Limited |
| Linux ELF | (none) | Linux | ⚠️ Limited |
| Python bytecode | .pyc | Any | ✅ Production |

---

## Python API

### VeriductPrime Class

```python
from veriduct_prime import VeriductPrime

# Create instance
vp = VeriductPrime()
```

### annihilate_path()

Annihilate a file or directory.

```python
def annihilate_path(
    input_path: str,
    out_dir: str,
    wipe_size: int = 256,
    use_variable_chunks: bool = False,
    chunk_jitter: float = 0.0,
    use_ssm: bool = False,
    ssm_null_rate: float = 0.01,
    use_entanglement: bool = False,
    entanglement_group_size: int = 3,
    use_fake_chunks: bool = False,
    fake_ratio: float = 0.25,
    add_hmac: bool = True,
    disguise: str = None,
    force_internal: bool = False,
    verbose: bool = False
) -> int:
    """
    Returns:
        0 on success, non-zero on failure
    """
```

**Example:**

```python
result = annihilate_path(
    input_path="agent.exe",
    out_dir="chunks/",
    use_ssm=True,
    use_entanglement=True,
    verbose=True
)
```

### reassemble_path()

Reconstruct files from chunks.

```python
def reassemble_path(
    key_path: str,
    out_dir: str,
    disguise: str = None,
    ignore_integrity: bool = False,
    verbose: bool = False
) -> int:
    """
    Returns:
        0 on success, non-zero on failure
    """
```

**Example:**

```python
result = reassemble_path(
    key_path="chunks/veriduct_key.zst",
    out_dir="rebuilt/",
    verbose=True
)
```

### run_annihilated_path()

Execute from chunks semantically.

```python
def run_annihilated_path(
    key_path: str,
    disguise: str = None,
    ignore_integrity: bool = False,
    verbose: bool = False
) -> int:
    """
    Returns:
        Binary's exit code, or non-zero on failure
    """
```

**Example:**

```python
exit_code = run_annihilated_path(
    key_path="chunks/veriduct_key.zst",
    verbose=True
)
```

---

## ChunkStorage Class

Direct access to chunk database.

```python
from veriduct_prime import ChunkStorage

# Open database
storage = ChunkStorage("veriduct_chunks.db")

# Store chunks
storage.store_chunks_batch([
    (hash1, data1, False),  # (hash, data, is_fake)
    (hash2, data2, False),
])

# Retrieve chunk
chunk_data = storage.retrieve_chunk(chunk_hash)

# Get count
count = storage.get_chunk_count()

# Close
storage.close()
```

---

## VeriductNativeLoader Class

Low-level native binary loader.

```python
from veriduct_prime import VeriductNativeLoader

# Create loader with binary data
loader = VeriductNativeLoader(bytearray(binary_data))

# Parse headers
loader.parse_headers()

# Check validity
if loader.is_valid:
    print(f"Architecture: {loader.architecture}")
    print(f"Entry point: {loader.entry_point}")
    print(f"Image base: {loader.image_base}")

# Execute
result = loader.execute_native_direct()

# Cleanup
loader.cleanup()
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `is_valid` | bool | Headers parsed successfully |
| `architecture` | str | "PE", "ELF", or "Unknown" |
| `entry_point` | int | Entry point RVA |
| `image_base` | int | Preferred load address |
| `mapped_memory` | int | Base address of mapped image |
| `mapped_size` | int | Size of mapped image |

---

## MemorySubstrate Class

In-memory filesystem for fileless execution.

```python
from veriduct_prime import MemorySubstrate

# Create substrate
substrate = MemorySubstrate()

# Write file to memory
substrate.write_file("/memory/agent.exe", binary_data)

# Read file from memory
data = substrate.read_file("/memory/agent.exe")

# Check existence
if substrate.exists("/memory/agent.exe"):
    print("File in memory")

# Get total size
print(f"Memory usage: {substrate.get_size()} bytes")

# List files
for path in substrate.list_files():
    print(path)
```

---

## Cryptographic Functions

### calculate_salted_chunk_hash()

```python
def calculate_salted_chunk_hash(salt: bytes, chunk_data: bytes) -> str:
    """
    Calculate SHA256 hash with salt prefix.
    
    Args:
        salt: Random salt bytes
        chunk_data: Chunk content
        
    Returns:
        Hex-encoded SHA256 hash
    """
```

### calculate_file_hash()

```python
def calculate_file_hash(filepath: str) -> str:
    """
    Calculate SHA256 hash of entire file.
    
    Args:
        filepath: Path to file
        
    Returns:
        Hex-encoded SHA256 hash, or None on error
    """
```

### calculate_hmac()

```python
def calculate_hmac(key: bytes, message: bytes) -> str:
    """
    Calculate HMAC-SHA256.
    
    Args:
        key: HMAC key
        message: Message to authenticate
        
    Returns:
        Hex-encoded HMAC
    """
```

---

## Transformation Functions

### semantic_shatter()

```python
def semantic_shatter(
    data: bytes,
    ssm_seed: bytes = None,
    null_insert_rate: float = 0.01
) -> Tuple[bytes, bytes, List[int]]:
    """
    Apply Semantic Shatter Mapping.
    
    Args:
        data: Input bytes
        ssm_seed: Seed for deterministic shuffle (generated if None)
        null_insert_rate: Rate of null byte insertion (0.0-0.1)
        
    Returns:
        (shattered_data, ssm_seed, null_positions)
    """
```

### semantic_unshatter()

```python
def semantic_unshatter(
    shattered: bytes,
    ssm_seed: bytes,
    insert_positions: List[int]
) -> bytes:
    """
    Reverse Semantic Shatter Mapping.
    
    Args:
        shattered: Shattered bytes
        ssm_seed: Original SSM seed
        insert_positions: Positions of inserted nulls
        
    Returns:
        Original bytes
    """
```

### entangle_chunks()

```python
def entangle_chunks(
    chunks: List[bytes],
    group_size: int = 3
) -> Tuple[List[bytes], Dict]:
    """
    Apply XOR entanglement.
    
    Args:
        chunks: List of chunk data
        group_size: Chunks per entanglement group
        
    Returns:
        (entangled_chunks, entanglement_info)
    """
```

### disentangle_chunks()

```python
def disentangle_chunks(
    entangled: List[bytes],
    info: Dict
) -> List[bytes]:
    """
    Reverse XOR entanglement.
    
    Args:
        entangled: Entangled chunks
        info: Entanglement metadata from entangle_chunks()
        
    Returns:
        Original chunks
    """
```

---

## Constants

```python
CHUNK_SIZE = 4096                # Default chunk size
KEY_FILE = "veriduct_key.zst"    # Default keymap filename
DB_FILE = "veriduct_chunks.db"   # Default chunks database
DISGUISE_FORMATS = ["csv", "log", "conf"]
DEFAULT_USF_WIPE_SIZE = 256
BATCH_FLUSH_THRESHOLD = 1000
FILE_SALT_SIZE = 16
KEYMAP_FORMAT_VERSION = 7

# Memory protection constants
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

# PE section characteristics
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
```

---

## Error Handling

All functions return `0` on success, non-zero on failure. Errors are logged via Python's `logging` module.

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Or capture logs
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
logging.getLogger().addHandler(handler)
```

Common error codes:
- `1` — General error
- `2` — File not found
- `3` — Integrity check failed
- `130` — User cancelled (Ctrl+C)
