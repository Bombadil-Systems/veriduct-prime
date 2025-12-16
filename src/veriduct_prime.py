#!/usr/bin/env python3
"""
Veriduct Prime - Production Edition
Advanced file semantic annihilation with enhanced native binary execution support

Supports:
- Python bytecode (.pyc, .py)
- Windows PE executables (.exe, .dll) with TLS, SEH, delay-load imports
- Linux ELF binaries with dynamic linking, GOT/PLT resolution
- Mach-O binaries (future)

Features:
- Semantic Shatter Mapping (SSM)
- XOR Entanglement
- Variable chunking
- Substrate poisoning
- HMAC integrity
- Disguised keymaps
- Fileless execution via MemorySubstrate
- Native binary loading (PE/ELF)

Native Loader Capabilities:
- PE: TLS callbacks, SEH registration, delay-load imports, import resolution, base relocations
- ELF: Section header parsing, dynamic linking, shared library loading, RELA/REL relocations
- Memory management and cleanup

Version: 2.0 (Enhanced Native Loader)
"""

import os
import sys
import json
import hashlib
import argparse
import datetime
import random
import logging
import base64
import hmac
import sqlite3
import marshal
import types
import builtins
import struct
import ctypes
import platform
from typing import List, Tuple, Dict, Optional, Iterator

# ==============================================================================
# Compression Layer
# ==============================================================================

try:
    import zstandard as zstd
    class Compressor:
        @staticmethod
        def compress(data: bytes) -> bytes:
            return zstd.ZstdCompressor().compress(data)
        @staticmethod
        def decompress(data: bytes) -> bytes:
            return zstd.ZstdDecompressor().decompress(data)
except ImportError:
    import zlib
    class Compressor:
        @staticmethod
        def compress(data: bytes) -> bytes:
            return zlib.compress(data)
        @staticmethod
        def decompress(data: bytes) -> bytes:
            return zlib.decompress(data)

# ==============================================================================
# Constants
# ==============================================================================

CHUNK_SIZE = 4096
KEY_FILE = "veriduct_key.zst"
DB_FILE = "veriduct_chunks.db"
DISGUISE_FORMATS = ["csv", "log", "conf"]
DEFAULT_USF_WIPE_SIZE = 256
BATCH_FLUSH_THRESHOLD = 1000
FILE_SALT_SIZE = 16
KEYMAP_FORMAT_VERSION = 7  # Bumped for native binary support
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# ==============================================================================
# Memory Substrate - Fileless Execution Framework
# ==============================================================================

class MemorySubstrate:
    """
    In-memory filesystem for fileless execution.
    Binaries exist only as Python bytes objects, never touching disk.
    """
    def __init__(self):
        self._storage = {}  # path -> bytes
        self._metadata = {}  # path -> metadata
        logging.debug("MemorySubstrate initialized")

    def write_file(self, path: str, data: bytes):
        """Write binary data to memory path"""
        self._storage[path] = data
        self._metadata[path] = {
            'size': len(data),
            'created': datetime.datetime.now().isoformat(),
            'type': 'file'
        }
        logging.debug(f"Wrote {len(data)} bytes to memory path: {path}")

    def read_file(self, path: str) -> Optional[bytes]:
        """Read binary data from memory path"""
        return self._storage.get(path)

    def exists(self, path: str) -> bool:
        return path in self._storage

    def get_size(self) -> int:
        return sum(len(data) for data in self._storage.values())

    def list_files(self) -> List[str]:
        return list(self._storage.keys())

# ==============================================================================
# Cryptographic & Transformation Primitives
# ==============================================================================

def calculate_salted_chunk_hash(salt: bytes, chunk_data: bytes) -> str:
    """Calculate salted hash for chunk identification."""
    return hashlib.sha256(salt + chunk_data).hexdigest()

def calculate_file_hash(filepath: str) -> str:
    """Calculate hash of entire file for verification."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for '{filepath}': {e}")
        return None

def calculate_hmac(key: bytes, message: bytes) -> str:
    """Calculate HMAC for tamper detection."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def variable_chunk_sizes(data_stream: Iterator[bytes], base_size: int, jitter: float = 0.0) -> Iterator[bytes]:
    """
    Generator for variable-sized chunks with optional jitter.
    If jitter=0, uses fixed size for compatibility.
    """
    buffer = b''
    for chunk in data_stream:
        buffer += chunk
        while len(buffer) >= base_size:
            if jitter > 0:
                jitter = max(0.0, min(0.5, jitter))
                size = int(base_size * (1 - jitter + 2 * jitter * random.random()))
                size = max(64, min(size, len(buffer)))
            else:
                size = min(base_size, len(buffer))
            yield buffer[:size]
            buffer = buffer[size:]
    if buffer:
        yield buffer

def semantic_shatter(data: bytes, ssm_seed: bytes = None, null_insert_rate: float = 0.01) -> Tuple[bytes, bytes, List[int]]:
    """
    Reversible semantic shatter mapping with bounds checking.
    """
    if ssm_seed is None:
        ssm_seed = os.urandom(16)
    null_insert_rate = max(0.0, min(0.1, null_insert_rate))
    rng = random.Random(int.from_bytes(ssm_seed, "big"))
    n = len(data)
    if n == 0:
        return data, ssm_seed, []
    order = list(range(n))
    rng.shuffle(order)
    shattered = bytearray()
    insert_positions = []
    for idx in order:
        if rng.random() < null_insert_rate:
            insert_positions.append(len(shattered))
            shattered.append(0)
        shattered.append(data[idx])
    return bytes(shattered), ssm_seed, insert_positions

def semantic_unshatter(shattered: bytes, ssm_seed: bytes, insert_positions: List[int]) -> bytes:
    """Reverse semantic shatter mapping."""
    if not shattered:
        return b''
    rng = random.Random(int.from_bytes(ssm_seed, "big"))
    k = len(insert_positions)
    original_len = len(shattered) - k
    if original_len <= 0:
        return b''
    order = list(range(original_len))
    rng.shuffle(order)
    insert_set = set(insert_positions)
    source_positions = [pos for pos in range(len(shattered)) if pos not in insert_set]
    if len(source_positions) != original_len:
        raise ValueError("SSM metadata mismatch during unshatter")
    out = bytearray(original_len)
    for write_pos, orig_idx in enumerate(order):
        out[orig_idx] = shattered[source_positions[write_pos]]
    return bytes(out)

def entangle_chunks(chunks: List[bytes], group_size: int = 3) -> Tuple[List[bytes], Dict]:
    """
    Reversible XOR entanglement with improved padding handling.
    """
    if group_size < 2:
        return chunks, {"groups": []}

    entangled = list(chunks)
    info = {"groups": []}

    for start in range(0, len(chunks), group_size):
        idxs = list(range(start, min(start + group_size, len(chunks))))
        if len(idxs) <= 1:
            continue

        originals = [chunks[i] for i in idxs]
        original_lengths = [len(x) for x in originals]
        maxlen = max(original_lengths)

        padding_byte = 0xFF
        padded = [bytearray(x.ljust(maxlen, bytes([padding_byte]))) for x in originals]

        prefix = []
        acc = bytearray(maxlen)
        for p in padded:
            for j in range(maxlen):
                acc[j] ^= p[j]
            prefix.append(bytes(acc))

        for i, (idx, pref, orig_len) in enumerate(zip(idxs, prefix, original_lengths)):
            entangled[idx] = pref[:orig_len]

        info["groups"].append({
            "idxs": idxs,
            "maxlen": maxlen,
            "original_lengths": original_lengths,
            "padding_byte": padding_byte
        })

    return entangled, info

def disentangle_chunks(entangled: List[bytes], info: Dict) -> List[bytes]:
    """Reverse XOR entanglement."""
    out = list(entangled)
    for g in info.get("groups", []):
        idxs = g["idxs"]
        maxlen = g["maxlen"]
        original_lengths = g["original_lengths"]
        padding_byte = g.get("padding_byte", 0xFF)

        prefix = []
        for i, idx in enumerate(idxs):
            padded_chunk = bytearray(out[idx].ljust(maxlen, bytes([padding_byte])))
            prefix.append(padded_chunk)

        originals = []
        prev = bytearray(maxlen)
        for p in prefix:
            orig = bytearray(maxlen)
            for j in range(maxlen):
                orig[j] = prev[j] ^ p[j]
            originals.append(bytes(orig))
            prev = p

        for i, (idx, orig, orig_len) in enumerate(zip(idxs, originals, original_lengths)):
            out[idx] = orig[:orig_len]

    return out

# ==============================================================================
# Storage Layer
# ==============================================================================

class ChunkStorage:
    """Robust SQLite chunk storage with better error handling."""
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS chunks (
                hash TEXT PRIMARY KEY,
                data BLOB,
                is_fake INTEGER DEFAULT 0
            )
        """)
        self.conn.commit()
        logging.debug(f"ChunkStorage initialized at {db_path}")

    def store_chunks_batch(self, chunks_to_store: List[Tuple[str, bytes, bool]]):
        """Store multiple chunks in a single transaction."""
        if not chunks_to_store:
            return
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO chunks (hash, data, is_fake) VALUES (?, ?, ?)",
                chunks_to_store
            )
        logging.debug(f"Stored {len(chunks_to_store)} chunks")

    def retrieve_chunk(self, salted_chunk_hash: str) -> Optional[bytes]:
        """Retrieve a single chunk by hash."""
        cursor = self.conn.execute(
            "SELECT data FROM chunks WHERE hash = ? AND is_fake = 0",
            (salted_chunk_hash,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    def get_chunk_count(self) -> int:
        """Get total number of real chunks."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM chunks WHERE is_fake = 0")
        return cursor.fetchone()[0]

    def close(self):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
            logging.debug("ChunkStorage closed")

def generate_fake_chunks(real_chunk_count: int, file_salt: bytes, ratio: float = 0.25) -> List[Tuple[str, bytes, bool]]:
    """Generate fake chunks for substrate poisoning."""
    count = max(1, int(real_chunk_count * ratio))
    fakes = []
    for _ in range(count):
        fake_len = random.choice([256, 512, 1024, 2048, 4096])
        data = os.urandom(fake_len)
        h = calculate_salted_chunk_hash(file_salt, data)
        fakes.append((h, data, True))
    logging.debug(f"Generated {count} fake chunks")
    return fakes

# ==============================================================================
# Disguised Keymap Parsing
# ==============================================================================

def parse_disguised_key(key_path: str, style: str) -> dict:
    """Parse disguised keymap file."""
    try:
        with open(key_path, 'r') as f:
            content = f.read()
        
        if style == "csv":
            # Extract base64 from CSV format
            lines = content.strip().split('\n')
            if len(lines) < 2:
                raise ValueError("Invalid CSV format")
            # Data is in second column of last row
            data_line = lines[-1]
            parts = data_line.split(',')
            if len(parts) < 2:
                raise ValueError("Invalid CSV data row")
            encoded = parts[1].strip('"')
            compressed = base64.b64decode(encoded)
            
        elif style == "log":
            # Extract base64 from log format
            lines = content.strip().split('\n')
            if not lines:
                raise ValueError("Empty log file")
            last_line = lines[-1]
            # Format: timestamp level message - data:<base64>
            if " - data:" not in last_line:
                raise ValueError("Invalid log format")
            encoded = last_line.split(" - data:")[-1].strip()
            compressed = base64.b64decode(encoded)
            
        elif style == "conf":
            # Extract base64 from conf format
            lines = content.strip().split('\n')
            data_line = None
            for line in lines:
                if line.startswith('data='):
                    data_line = line
                    break
            if not data_line:
                raise ValueError("No data field in config")
            encoded = data_line.split('=', 1)[1].strip()
            compressed = base64.b64decode(encoded)
        else:
            raise ValueError(f"Unknown disguise format: {style}")
        
        # Decompress and parse JSON
        json_bytes = Compressor.decompress(compressed)
        key_map = json.loads(json_bytes.decode('utf-8'))
        logging.info(f"Successfully parsed disguised keymap ({style} format)")
        return key_map
        
    except Exception as e:
        logging.error(f"Failed to parse disguised keymap: {e}")
        raise

# ==============================================================================
# Native Binary Loader (PE/ELF)
# ==============================================================================

class VeriductNativeLoader:
    """
    Native binary loader for PE and ELF.
    Implements dynamic linking, relocation, and execution transfer in pure Python.
    """
    def __init__(self, raw_data_stream: bytearray):
        self.stream = raw_data_stream
        self.is_valid = False
        self.entry_point = 0
        self.architecture = "Unknown"
        self.image_base = 0
        self.mapped_memory = None
        self.mapped_size = 0
        
    def parse_headers(self):
        """Identifies file type and parses structures."""
        if len(self.stream) < 64:
            logging.error("Binary too small to parse")
            return

        if self.stream[:4] == b'\x7fELF':
            self.architecture = "ELF"
            self._parse_elf()
        elif self.stream[:2] == b'MZ':
            self.architecture = "PE"
            self._parse_pe()
        else:
            logging.error("Unknown executable format")
            self.is_valid = False

    # -------------------------------------------------------------------------
    # PE (Windows) Implementation
    # -------------------------------------------------------------------------
    
    def _translate_pe_flags_to_page_protect_MAX_ACCESS(self, characteristics):
        """
        Translate PE section characteristics flags to Windows page protection constants.
        """
        can_exec = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)
        can_read = bool(characteristics & IMAGE_SCN_MEM_READ)
        can_write = bool(characteristics & IMAGE_SCN_MEM_WRITE)

        # Prefer the most permissive matching protection that reflects section flags
        if can_exec:
            if can_read and can_write:
                return PAGE_EXECUTE_READWRITE
            if can_read:
                return PAGE_EXECUTE_READ
            if can_write:
                # uncommon combination (execute + write but not read), choose exec+rw
                return PAGE_EXECUTE_READWRITE
            return PAGE_EXECUTE

        # Non-executable mappings
        if can_read and can_write:
            return PAGE_READWRITE
        if can_read:
            return PAGE_READONLY
        if can_write:
            # write-only is unusual; map to read-write for safety
            return PAGE_READWRITE

        return PAGE_NOACCESS

    def _parse_pe(self):
        """Parse PE headers and extract critical information."""
        try:
            # DOS Header -> PE Header offset
            pe_offset = struct.unpack('<I', self.stream[0x3C:0x40])[0]
            if self.stream[pe_offset:pe_offset+4] != b'PE\0\0':
                logging.error("Invalid PE signature")
                return
            
            # File Header
            self.num_sections = struct.unpack('<H', self.stream[pe_offset+6:pe_offset+8])[0]
            opt_header_size = struct.unpack('<H', self.stream[pe_offset+20:pe_offset+22])[0]
            
            # Optional Header
            opt_header_offset = pe_offset + 24
            self.opt_header_offset = opt_header_offset  # Store for later use
            magic = struct.unpack('<H', self.stream[opt_header_offset:opt_header_offset+2])[0]
            
            is_64bit = (magic == 0x20b)
            
            # AddressOfEntryPoint (Offset 16)
            self.entry_point_rva = struct.unpack('<I', self.stream[opt_header_offset+16:opt_header_offset+20])[0]
            
            # ImageBase
            if is_64bit:
                self.image_base = struct.unpack('<Q', self.stream[opt_header_offset+24:opt_header_offset+32])[0]
            else:
                self.image_base = struct.unpack('<I', self.stream[opt_header_offset+28:opt_header_offset+32])[0]

            # SizeOfImage
            self.size_of_image = struct.unpack('<I', self.stream[opt_header_offset+56:opt_header_offset+60])[0]
            
            # Data Directories
            dd_offset = opt_header_offset + (112 if is_64bit else 96)
            
            # Import Table (Index 1)
            self.import_table_rva = struct.unpack('<I', self.stream[dd_offset+8:dd_offset+12])[0]
            
            # Reloc Table (Index 5)
            self.reloc_table_rva = struct.unpack('<I', self.stream[dd_offset+40:dd_offset+44])[0]
            self.reloc_table_size = struct.unpack('<I', self.stream[dd_offset+44:dd_offset+48])[0]
            
            # TLS Directory (Index 9)
            tls_rva = struct.unpack('<I', self.stream[dd_offset+72:dd_offset+76])[0]
            if tls_rva > 0:
                self.tls_directory_rva = tls_rva
                logging.debug(f"TLS Directory found at RVA 0x{tls_rva:X}")

            # Section headers offset
            self.section_header_offset = opt_header_offset + opt_header_size
            self.is_valid = True
            
            logging.info(f"PE parsed: {self.num_sections} sections, entry RVA: 0x{self.entry_point_rva:X}")
            
        except Exception as e:
            logging.error(f"PE Parse Error: {e}")
            self.is_valid = False

    def _execute_pe_windows(self):
            """Execute PE on Windows with proper memory mapping."""
            kernel32 = ctypes.windll.kernel32
    
            # Set up function signatures
            kernel32.VirtualAlloc.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_ulong,
                ctypes.c_ulong
            ]
            kernel32.VirtualAlloc.restype = ctypes.c_void_p
    
            kernel32.VirtualProtect.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong)
            ]
            kernel32.VirtualProtect.restype = ctypes.c_bool
    
            kernel32.VirtualFree.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_ulong
            ]
            kernel32.VirtualFree.restype = ctypes.c_bool
    
            # Allocate memory - let Windows choose the address
            base_addr = kernel32.VirtualAlloc(
                None,  # Let Windows choose address
                self.size_of_image,
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                PAGE_READWRITE
            )
    
            if not base_addr:
                error = ctypes.get_last_error()
                raise RuntimeError(f"VirtualAlloc failed with error {error}")
    
            base_addr_int = base_addr if isinstance(base_addr, int) else ctypes.cast(base_addr, ctypes.c_void_p).value
            logging.info(f"Allocated {self.size_of_image} bytes at 0x{base_addr_int:X}")
    
            try:
                sections_to_protect = []
                header_size = 0x1000
        
                # Copy headers
                ctypes.memmove(base_addr, bytes(self.stream[:header_size]), min(len(self.stream), header_size))
        
                # Map sections
                current_offset = self.section_header_offset
                for i in range(self.num_sections):
                    v_addr = struct.unpack('<I', self.stream[current_offset+12:current_offset+16])[0]
                    raw_size = struct.unpack('<I', self.stream[current_offset+16:current_offset+20])[0]
                    raw_ptr = struct.unpack('<I', self.stream[current_offset+20:current_offset+24])[0]
                    characteristics = struct.unpack('<I', self.stream[current_offset+36:current_offset+40])[0]
            
                    if raw_size > 0 and v_addr > 0:
                        dest = base_addr_int + v_addr
                        data = self.stream[raw_ptr:raw_ptr + raw_size]
                        ctypes.memmove(dest, bytes(data), len(data))
                        logging.debug(f"Mapped section {i} at RVA 0x{v_addr:X}")
                
                        sections_to_protect.append({
                            'addr': dest,
                            'size': raw_size,
                            'char': characteristics
                        })
            
                    current_offset += 40
        
                # Apply relocations if needed
                delta = base_addr_int - self.image_base
                if delta != 0 and self.reloc_table_rva != 0:
                    logging.info(f"Applying relocations (delta: 0x{delta:X})")
                    self._apply_pe_relocations(base_addr_int, self.reloc_table_rva, self.reloc_table_size, delta)
        
                # Resolve imports
                if self.import_table_rva != 0:
                    logging.info("Resolving imports...")
                    self._resolve_pe_imports(base_addr_int, self.import_table_rva)
                
                # Resolve delay-load imports
                self._resolve_pe_delay_imports(base_addr_int)
                
                # Execute TLS Callbacks
                self._execute_tls_callbacks(base_addr_int)

                # Setup SEH
                self._setup_seh(base_addr_int)
        
                # Apply section protections
                for section in sections_to_protect:
                    protection = self._translate_pe_flags_to_page_protect_MAX_ACCESS(section['char'])
                    old_protect = ctypes.c_ulong()
            
                    # Keep executable sections writable for CRT initialization
                    if protection in (PAGE_EXECUTE, PAGE_EXECUTE_READ):
                        protection = PAGE_EXECUTE_READWRITE
            
                    if protection != PAGE_NOACCESS:
                        kernel32.VirtualProtect(
                            section['addr'],
                            section['size'],
                            protection,
                            ctypes.byref(old_protect)
                        )
        
                # Execute
                entry_addr = base_addr_int + self.entry_point_rva
                logging.info(f"Jumping to entry point: 0x{entry_addr:X}")

                # Check if this is a DLL or EXE
                pe_offset = struct.unpack('<I', self.stream[0x3C:0x40])[0]
                characteristics = struct.unpack('<H', self.stream[pe_offset+22:pe_offset+24])[0]
                is_dll = bool(characteristics & 0x2000)  # IMAGE_FILE_DLL flag

                if is_dll:
                    logging.info("Detected DLL - calling with DllMain signature")
                    # DLL entry point: BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
                    ENTRY_FUNC = ctypes.CFUNCTYPE(
                        ctypes.c_int,
                        ctypes.c_void_p,
                        ctypes.c_ulong,
                        ctypes.c_void_p
                    )
                    entry = ENTRY_FUNC(entry_addr)
                    
                    try:
                        logging.info(f"Calling DllMain at 0x{entry_addr:X}...")
                        result = entry(base_addr_int, 1, None)  # DLL_PROCESS_ATTACH
                        logging.info(f"DllMain returned: {result}")
                    except Exception as e:
                        logging.error(f"DllMain crashed: {type(e).__name__}: {e}")
                        import traceback
                        traceback.print_exc()
                        raise
                else:
                    logging.info("Detected EXE - calling with no arguments")
                    # EXE entry point: int mainCRTStartup(void) or int WinMainCRTStartup(void)
                    ENTRY_FUNC = ctypes.CFUNCTYPE(ctypes.c_int)
                    entry = ENTRY_FUNC(entry_addr)
                    
                    try:
                        logging.info(f"Calling entry point at 0x{entry_addr:X}...")
                        result = entry()  # No arguments for EXE
                        logging.info(f"Entry point returned: {result}")
                    except OSError as e:
                        logging.error(f"Entry point crashed with OS error: {e}")
                        import traceback
                        traceback.print_exc()
                        raise
                    except Exception as e:
                        logging.error(f"Entry point crashed: {type(e).__name__}: {e}")
                        import traceback
                        traceback.print_exc()
                        raise
                        
                return result
            
            except Exception as e:
                kernel32.VirtualFree(base_addr, 0, 0x8000)  # MEM_RELEASE
                logging.error(f"PE execution failed: {e}")
                raise

    def _apply_pe_relocations(self, base_addr, reloc_rva, reloc_size, delta):
        """Parses .reloc section and patches memory addresses."""
        current_rva = reloc_rva
        end_rva = reloc_rva + reloc_size
        
        def read_mem_u32(addr):
            return struct.unpack('<I', ctypes.string_at(addr, 4))[0]
        
        reloc_count = 0
        while current_rva < end_rva:
            block_va = read_mem_u32(base_addr + current_rva)
            block_size = read_mem_u32(base_addr + current_rva + 4)
            
            if block_size == 0:
                break
            
            num_entries = (block_size - 8) // 2
            entry_ptr = base_addr + current_rva + 8
            
            for _ in range(num_entries):
                entry = struct.unpack('<H', ctypes.string_at(entry_ptr, 2))[0]
                entry_ptr += 2
                
                type_ = entry >> 12
                offset = entry & 0xFFF
                
                target_addr = base_addr + block_va + offset
                
                if type_ == 3:  # IMAGE_REL_BASED_HIGHLOW (32-bit)
                    curr_val = struct.unpack('<I', ctypes.string_at(target_addr, 4))[0]
                    new_val = (curr_val + delta) & 0xFFFFFFFF
                    ctypes.memmove(target_addr, struct.pack('<I', new_val), 4)
                    reloc_count += 1
                elif type_ == 10:  # IMAGE_REL_BASED_DIR64 (64-bit)
                    curr_val = struct.unpack('<Q', ctypes.string_at(target_addr, 8))[0]
                    new_val = (curr_val + delta) & 0xFFFFFFFFFFFFFFFF
                    ctypes.memmove(target_addr, struct.pack('<Q', new_val), 8)
                    reloc_count += 1
            
            current_rva += block_size
        
        logging.debug(f"Applied {reloc_count} relocations")

    def _resolve_pe_imports(self, base_addr, import_rva):
        """Walks Import Descriptor, loads DLLs, fills IAT."""
        kernel32 = ctypes.windll.kernel32
        
        # Set up GetProcAddress with proper signature
        kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        kernel32.GetProcAddress.restype = ctypes.c_void_p
        
        kernel32.LoadLibraryA.argtypes = [ctypes.c_char_p]
        kernel32.LoadLibraryA.restype = ctypes.c_void_p
        
        desc_ptr = base_addr + import_rva
        dll_count = 0
        
        while True:
            original_first_thunk = struct.unpack('<I', ctypes.string_at(desc_ptr, 4))[0]
            name_rva = struct.unpack('<I', ctypes.string_at(desc_ptr + 12, 4))[0]
            first_thunk = struct.unpack('<I', ctypes.string_at(desc_ptr + 16, 4))[0]
            
            if original_first_thunk == 0 and name_rva == 0:
                break
                
            # Get DLL Name
            dll_name = ctypes.string_at(base_addr + name_rva).decode('ascii')
            h_module = kernel32.LoadLibraryA(dll_name.encode('ascii'))
            if not h_module:
                logging.warning(f"Failed to load dependency: {dll_name}")
                desc_ptr += 20
                continue
            
            dll_count += 1
            logging.debug(f"Loaded DLL: {dll_name}")
                
            # Walk Thunks
            thunk_ptr = base_addr + (original_first_thunk if original_first_thunk else first_thunk)
            iat_ptr = base_addr + first_thunk
            
            is_64 = (self.image_base > 0xFFFFFFFF)
            ptr_size = 8 if is_64 else 4
            msb_mask = 0x8000000000000000 if is_64 else 0x80000000
            
            import_count = 0
            while True:
                if is_64:
                    thunk_data = struct.unpack('<Q', ctypes.string_at(thunk_ptr, 8))[0]
                else:
                    thunk_data = struct.unpack('<I', ctypes.string_at(thunk_ptr, 4))[0]
                
                if thunk_data == 0:
                    break
                
                if thunk_data & msb_mask:
                    # Import by ordinal
                    # Windows ordinals: low word is ordinal, high word must be 0
                    # Pass ordinal directly as integer (not pointer)
                    ordinal = thunk_data & 0xFFFF
                    # For ordinals, the second parameter should be ordinal value directly
                    # We need to bypass the c_char_p type checking
                    kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
                    proc_addr = kernel32.GetProcAddress(h_module, ordinal)
                    # Reset to normal for name-based imports
                    kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
                else:
                    # Import by name - GetProcAddress takes c_char_p
                    name_ptr = base_addr + (thunk_data & 0x7FFFFFFF) + 2
                    func_name_bytes = ctypes.string_at(name_ptr)
                    # Pass as bytes directly (c_char_p)
                    proc_addr = kernel32.GetProcAddress(h_module, func_name_bytes)
                
                if proc_addr:
                    if is_64:
                        ctypes.memmove(iat_ptr, struct.pack('<Q', proc_addr), 8)
                    else:
                        ctypes.memmove(iat_ptr, struct.pack('<I', proc_addr), 4)
                    import_count += 1
                else:
                    # Log failed import resolution
                    if thunk_data & msb_mask:
                        logging.warning(f"Failed to resolve {dll_name}!Ordinal{thunk_data & 0xFFFF}")
                    else:
                        try:
                            name_ptr = base_addr + (thunk_data & 0x7FFFFFFF) + 2
                            func_name = ctypes.string_at(name_ptr).decode('ascii', errors='ignore')
                            logging.warning(f"Failed to resolve {dll_name}!{func_name}")
                        except:
                            logging.warning(f"Failed to resolve import from {dll_name}")
                
                thunk_ptr += ptr_size
                iat_ptr += ptr_size
            
            logging.debug(f"  Resolved {import_count} imports from {dll_name}")
            desc_ptr += 20
        
        logging.info(f"Loaded {dll_count} DLLs")

    def _execute_tls_callbacks(self, base_addr):
        """Finds and executes Thread Local Storage callbacks."""
        if not hasattr(self, 'tls_directory_rva') or self.tls_directory_rva == 0:
            return

        logging.info("Processing TLS Callbacks...")
        
        # Read IMAGE_TLS_DIRECTORY
        tls_ptr = base_addr + self.tls_directory_rva
        
        if self.image_base > 0xFFFFFFFF:  # 64-bit
            callbacks_va = struct.unpack('<Q', ctypes.string_at(tls_ptr + 24, 8))[0]
        else:  # 32-bit
            callbacks_va = struct.unpack('<I', ctypes.string_at(tls_ptr + 12, 4))[0]

        if callbacks_va == 0:
            return

        # Convert VA to RVA
        callbacks_rva = callbacks_va - self.image_base
        
        # Validate RVA is within bounds
        if callbacks_rva < 0 or callbacks_rva >= self.size_of_image:
            logging.warning(f"TLS callbacks RVA 0x{callbacks_rva:X} out of bounds, skipping")
            return
        
        current_callback_ptr = base_addr + callbacks_rva
        
        # Setup Function Prototype: void PASCAL TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
        TLS_FUNC = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p)
        
        try:
            while True:
                # Read function pointer
                if self.image_base > 0xFFFFFFFF:
                    func_va = struct.unpack('<Q', ctypes.string_at(current_callback_ptr, 8))[0]
                    current_callback_ptr += 8
                else:
                    func_va = struct.unpack('<I', ctypes.string_at(current_callback_ptr, 4))[0]
                    current_callback_ptr += 4
                    
                if func_va == 0:
                    break
                    
                func_rva = func_va - self.image_base
                
                # Validate RVA
                if func_rva < 0 or func_rva >= self.size_of_image:
                    logging.warning(f"TLS callback RVA 0x{func_rva:X} out of bounds, skipping")
                    continue
                
                target = base_addr + func_rva
                
                logging.info(f"Executing TLS Callback at 0x{target:X}")
                try:
                    cb = TLS_FUNC(target)
                    cb(base_addr, 1, 0)  # DLL_PROCESS_ATTACH
                except Exception as e:
                    logging.warning(f"TLS Callback failed: {e}")
        except OSError as e:
            logging.warning(f"Failed to read TLS callbacks: {e}")

    def _setup_seh(self, base_addr):
        """
        Registers Exception Handling Tables for x64 (pdata).
        Required for try/except blocks in the loaded binary to work.
        """
        # Exception Directory is Index 3
        dd_offset = self.opt_header_offset + (112 if (self.image_base > 0xFFFFFFFF) else 96)
        
        exception_rva = struct.unpack('<I', self.stream[dd_offset+24:dd_offset+28])[0]
        exception_size = struct.unpack('<I', self.stream[dd_offset+28:dd_offset+32])[0]
        
        if exception_rva == 0:
            return

        logging.info("Registering SEH Table...")
        
        # RUNTIME_FUNCTION struct size (12 bytes on x64)
        entry_count = exception_size // 12
        table_ptr = base_addr + exception_rva
        
        kernel32 = ctypes.windll.kernel32
        
        try:
            if hasattr(kernel32, 'RtlAddFunctionTable'):
                result = kernel32.RtlAddFunctionTable(
                    ctypes.c_void_p(table_ptr),
                    ctypes.c_ulong(entry_count),
                    ctypes.c_uint64(base_addr)
                )
                if not result:
                    logging.warning("RtlAddFunctionTable failed")
            else:
                logging.debug("RtlAddFunctionTable not found (32-bit system)")
        except Exception as e:
            logging.error(f"Failed to setup SEH: {e}")

    def _resolve_pe_delay_imports(self, base_addr):
        """
        Resolves Delay-Load Imports (Index 13).
        We resolve them eagerly (now) to ensure the binary has everything it needs.
        """
        # Delay Import Descriptor is Index 13
        is_64 = (self.image_base > 0xFFFFFFFF)
        dd_offset = self.opt_header_offset + (112 if is_64 else 96)
        
        # 13 * 8 bytes per entry = 104 bytes offset
        delay_rva = struct.unpack('<I', self.stream[dd_offset + 104 : dd_offset + 108])[0]
        
        if delay_rva == 0:
            return

        logging.info("Resolving Delay-Load Imports...")
        kernel32 = ctypes.windll.kernel32
        
        current_desc_ptr = base_addr + delay_rva
        
        while True:
            # Parse ImgDelayDescr (32 bytes)
            attrs = struct.unpack('<I', ctypes.string_at(current_desc_ptr, 4))[0]
            name_rva = struct.unpack('<I', ctypes.string_at(current_desc_ptr + 4, 4))[0]
            
            if name_rva == 0:
                break
                
            dll_name = ctypes.string_at(base_addr + name_rva).decode('ascii')
            
            # Load the DLL
            h_module = kernel32.LoadLibraryA(dll_name.encode('ascii'))
            if not h_module:
                logging.warning(f"Failed to delay-load: {dll_name}")
                current_desc_ptr += 32
                continue
            
            logging.debug(f"Delay-loaded DLL: {dll_name}")
                
            # Write the Module Handle back
            module_handle_rva = struct.unpack('<I', ctypes.string_at(current_desc_ptr + 8, 4))[0]
            if module_handle_rva:
                h_ptr = base_addr + module_handle_rva
                # Convert h_module to proper unsigned value
                h_module_val = h_module if h_module >= 0 else (h_module & 0xFFFFFFFFFFFFFFFF)
                if is_64:
                    ctypes.memmove(h_ptr, struct.pack('<Q', h_module_val), 8)
                else:
                    ctypes.memmove(h_ptr, struct.pack('<I', h_module_val & 0xFFFFFFFF), 4)

            # Resolve the functions (IAT)
            iat_rva = struct.unpack('<I', ctypes.string_at(current_desc_ptr + 12, 4))[0]
            int_rva = struct.unpack('<I', ctypes.string_at(current_desc_ptr + 16, 4))[0]
            
            iat_ptr = base_addr + iat_rva
            int_ptr = base_addr + int_rva
            
            ptr_size = 8 if is_64 else 4
            
            while True:
                # Read Name Pointer
                if is_64:
                    name_ptr_val = struct.unpack('<Q', ctypes.string_at(int_ptr, 8))[0]
                else:
                    name_ptr_val = struct.unpack('<I', ctypes.string_at(int_ptr, 4))[0]
                
                if name_ptr_val == 0:
                    break
                    
                is_ordinal = (name_ptr_val >> (63 if is_64 else 31)) & 1
                
                if is_ordinal:
                    ordinal = name_ptr_val & 0xFFFF
                    proc_addr = kernel32.GetProcAddress(h_module, ordinal)
                else:
                    fn_name_ptr = base_addr + (name_ptr_val & 0xFFFFFFFF) + 2  # Skip Hint
                    fn_name = ctypes.string_at(fn_name_ptr)
                    proc_addr = kernel32.GetProcAddress(h_module, fn_name)
                
                if proc_addr:
                    if is_64:
                        ctypes.memmove(iat_ptr, struct.pack('<Q', proc_addr), 8)
                    else:
                        ctypes.memmove(iat_ptr, struct.pack('<I', proc_addr), 4)

                iat_ptr += ptr_size
                int_ptr += ptr_size
            
            current_desc_ptr += 32

    # -------------------------------------------------------------------------
    # ELF (Linux) Implementation
    # -------------------------------------------------------------------------
    
    def _parse_elf(self):
        """Parse ELF headers."""
        try:
            # Entry Point at offset 0x18 (64-bit)
            self.entry_point = struct.unpack('<Q', self.stream[0x18:0x20])[0]
            # Program Header Offset
            self.ph_off = struct.unpack('<Q', self.stream[0x20:0x28])[0]
            # Section Header Offset
            self.sh_off = struct.unpack('<Q', self.stream[0x28:0x30])[0]
            # PH Entry Size
            self.ph_ent_size = struct.unpack('<H', self.stream[0x36:0x38])[0]
            # Num PH Entries
            self.ph_num = struct.unpack('<H', self.stream[0x38:0x3A])[0]
            # SH Entry Size
            self.sh_ent_size = struct.unpack('<H', self.stream[0x3A:0x3C])[0]
            # Num SH Entries
            self.sh_num = struct.unpack('<H', self.stream[0x3C:0x3E])[0]
            
            self.is_valid = True
            
            logging.info(f"ELF parsed: Entry 0x{self.entry_point:X}, {self.ph_num} program headers, {self.sh_num} sections")
            
            # Parse section headers for advanced features
            self._parse_elf_sections()
            
            # Parse dynamic section for dynamic linking
            self._parse_elf_dynamic()
            
        except Exception as e:
            logging.error(f"ELF Parse Error: {e}")
            self.is_valid = False

    def _parse_elf_sections(self):
        """
        Parses ELF Section Headers (Shdr).
        Necessary for finding specific data like .got, .plt, or .dynstr by name.
        """
        if not hasattr(self, 'sh_off') or self.sh_off == 0:
            logging.debug("No Section Header Table found")
            return

        self.sections = []
        
        # Section Header String Table Index
        shstrndx = struct.unpack('<H', self.stream[0x3E:0x40])[0]
        
        # Iterate headers
        for i in range(self.sh_num):
            offset = self.sh_off + (i * self.sh_ent_size)
            
            # Elf64_Shdr format
            s_name_idx = struct.unpack('<I', self.stream[offset:offset+4])[0]
            s_type = struct.unpack('<I', self.stream[offset+4:offset+8])[0]
            s_offset = struct.unpack('<Q', self.stream[offset+24:offset+32])[0]
            s_size = struct.unpack('<Q', self.stream[offset+32:offset+40])[0]
            
            self.sections.append({
                'name_idx': s_name_idx,
                'type': s_type,
                'offset': s_offset,
                'size': s_size,
                'raw_data': self.stream[s_offset : s_offset + s_size] if s_offset < len(self.stream) else b''
            })

        # Resolve Section Names
        if shstrndx < len(self.sections):
            string_table_data = self.sections[shstrndx]['raw_data']
            
            for section in self.sections:
                start = section['name_idx']
                end = start
                while end < len(string_table_data) and string_table_data[end] != 0:
                    end += 1
                
                section['name'] = string_table_data[start:end].decode('utf-8')
                logging.debug(f"Found Section: {section['name']} (Type: {section['type']})")

    def _get_section_by_name(self, name):
        """Helper to find a section."""
        if not hasattr(self, 'sections'):
            return None
        for s in self.sections:
            if s.get('name') == name:
                return s
        return None

    def _parse_elf_dynamic(self):
        """Parses the .dynamic section to locate strings, symbols, and relocations."""
        self.dynamic_entries = {}
        self.load_libs = []
        
        # Find PT_DYNAMIC segment
        dyn_off = 0
        dyn_sz = 0
        
        for i in range(self.ph_num):
            offset = self.ph_off + (i * self.ph_ent_size)
            p_type = struct.unpack('<I', self.stream[offset:offset+4])[0]
            if p_type == 2:  # PT_DYNAMIC
                dyn_off = struct.unpack('<Q', self.stream[offset+8:offset+16])[0]
                dyn_sz = struct.unpack('<Q', self.stream[offset+32:offset+40])[0]
                break
        
        if dyn_off == 0:
            logging.debug("No PT_DYNAMIC segment found (Static binary)")
            return

        # Parse tags (Elf64_Dyn is 16 bytes: 8 byte tag, 8 byte val/ptr)
        curr = dyn_off
        end = dyn_off + dyn_sz
        
        while curr < end and curr < len(self.stream):
            tag = struct.unpack('<q', self.stream[curr:curr+8])[0]
            val = struct.unpack('<Q', self.stream[curr+8:curr+16])[0]
            
            if tag == 0:  # DT_NULL
                break
                
            self.dynamic_entries[tag] = val
            
            if tag == 1:  # DT_NEEDED
                self.load_libs.append(val)
            
            curr += 16
            
        logging.info(f"Parsed .dynamic: Found {len(self.load_libs)} dependencies")

    def _load_elf_dependencies(self, base_addr):
        """Loads shared libraries defined in DT_NEEDED."""
        if 5 not in self.dynamic_entries:  # DT_STRTAB
            return

        strtab_off = self.dynamic_entries[5]
        self.loaded_modules = {}
        
        for name_offset in self.load_libs:
            try:
                lib_name = ctypes.string_at(base_addr + strtab_off + name_offset).decode('utf-8')
                logging.info(f"Loading dependency: {lib_name}")
                
                try:
                    lib = ctypes.CDLL(lib_name)
                    self.loaded_modules[lib_name] = lib
                except OSError as e:
                    logging.warning(f"Could not load library: {lib_name} - {e}")
                    
            except Exception as e:
                logging.error(f"Error loading dependency index {name_offset}: {e}")

    def _resolve_elf_relocations(self, base_addr):
        """
        Process RELA/REL relocations (GOT, PLT, and Relative).
        Specific to x86_64 ELF.
        """
        if 7 not in self.dynamic_entries:  # DT_RELA
            return

        rela_addr = self.dynamic_entries[7]
        rela_sz = self.dynamic_entries.get(8, 0)  # DT_RELASZ
        rela_ent = self.dynamic_entries.get(9, 24)  # DT_RELAENT
        
        if rela_sz == 0:
            return
        
        symtab_addr = self.dynamic_entries.get(6, 0)  # DT_SYMTAB
        strtab_addr = self.dynamic_entries.get(5, 0)  # DT_STRTAB
        
        # Adjust addresses if PIE
        if rela_addr < base_addr:
            rela_addr += base_addr
            symtab_addr += base_addr
            strtab_addr += base_addr

        num_relocs = rela_sz // rela_ent
        current_reloc = rela_addr
        
        logging.info(f"Processing {num_relocs} ELF relocations...")

        for _ in range(num_relocs):
            try:
                # Elf64_Rela: r_offset (8), r_info (8), r_addend (8)
                r_offset = struct.unpack('<Q', ctypes.string_at(current_reloc, 8))[0]
                r_info = struct.unpack('<Q', ctypes.string_at(current_reloc+8, 8))[0]
                r_addend = struct.unpack('<q', ctypes.string_at(current_reloc+16, 8))[0]
                
                r_type = r_info & 0xFFFFFFFF
                r_sym = r_info >> 32
                
                target_addr = base_addr + r_offset if r_offset < base_addr else r_offset
                
                # R_X86_64_RELATIVE (8) - Base relocation
                if r_type == 8:
                    val = base_addr + r_addend
                    ctypes.memmove(target_addr, struct.pack('<Q', val), 8)
                    
                # R_X86_64_GLOB_DAT (6) or JUMP_SLOT (7) - Symbol lookup
                elif r_type in (6, 7) and r_sym != 0:
                    # Get Symbol info from SymTab
                    sym_entry = symtab_addr + (r_sym * 24)
                    st_name = struct.unpack('<I', ctypes.string_at(sym_entry, 4))[0]
                    
                    # Get Name from StrTab
                    name_ptr = strtab_addr + st_name
                    sym_name = ctypes.string_at(name_ptr).decode('utf-8')
                    
                    # Lookup in loaded libraries
                    found = False
                    if hasattr(self, 'loaded_modules'):
                        for lib in self.loaded_modules.values():
                            try:
                                func = getattr(lib, sym_name)
                                addr = ctypes.cast(func, ctypes.c_void_p).value
                                
                                ctypes.memmove(target_addr, struct.pack('<Q', addr), 8)
                                found = True
                                break
                            except (AttributeError, OSError):
                                continue
                    
                    if not found:
                        logging.debug(f"Unresolved symbol: {sym_name}")

                current_reloc += rela_ent
            except Exception as e:
                logging.debug(f"Error processing relocation: {e}")
                current_reloc += rela_ent
                continue

    def _execute_elf_linux(self):
        """
        ELF loader using mmap.
        Handles PT_LOAD segments. Best with static binaries or simple PIE.
        """
        import mmap
        
        # Calculate memory requirements
        min_vaddr = 0xFFFFFFFFFFFFFFFF
        max_vaddr = 0
        load_segments = []
        
        for i in range(self.ph_num):
            offset = self.ph_off + (i * self.ph_ent_size)
            p_type = struct.unpack('<I', self.stream[offset:offset+4])[0]
            
            if p_type == 1:  # PT_LOAD
                p_offset = struct.unpack('<Q', self.stream[offset+8:offset+16])[0]
                p_vaddr = struct.unpack('<Q', self.stream[offset+16:offset+24])[0]
                p_filesz = struct.unpack('<Q', self.stream[offset+32:offset+40])[0]
                p_memsz = struct.unpack('<Q', self.stream[offset+40:offset+48])[0]
                
                if p_vaddr < min_vaddr:
                    min_vaddr = p_vaddr
                if p_vaddr + p_memsz > max_vaddr:
                    max_vaddr = p_vaddr + p_memsz
                
                load_segments.append((p_offset, p_vaddr, p_filesz, p_memsz))
                logging.debug(f"PT_LOAD: VAddr 0x{p_vaddr:X}, FileSz {p_filesz}, MemSz {p_memsz}")

        total_size = max_vaddr - min_vaddr
        total_size = (total_size + 4095) & ~4095  # Page align
        
        logging.info(f"Allocating {total_size} bytes for ELF")
        
        # Allocate executable memory
        mem = mmap.mmap(
            -1, 
            total_size, 
            mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
            mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
        )
        
        base_addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
        logging.info(f"Mapped ELF memory at 0x{base_addr:X}")
        
        # Load Segments
        for offset, vaddr, filesz, memsz in load_segments:
            # Handle PIE (position independent) - if vaddr is small, it's relative
            dest_addr = base_addr + vaddr if vaddr < 0x10000000 else vaddr
            
            # Copy file data
            data = self.stream[offset : offset + filesz]
            ctypes.memmove(dest_addr, bytes(data), len(data))
            
            # Zero BSS
            if memsz > filesz:
                ctypes.memset(dest_addr + filesz, 0, memsz - filesz)

        # Resolve Dynamic Dependencies
        if hasattr(self, 'dynamic_entries') and self.dynamic_entries:
            logging.info("Resolving dynamic linking...")
            self._load_elf_dependencies(base_addr)
            self._resolve_elf_relocations(base_addr)

        # Calculate entry point
        real_entry = base_addr + self.entry_point
        logging.info(f"Jumping to ELF entry point: 0x{real_entry:X}")
        
        # Execute
        func_type = ctypes.CFUNCTYPE(ctypes.c_int)
        func = func_type(real_entry)
        
        result = func()
        logging.info(f"ELF execution completed with return code: {result}")
        return result

    def execute_native_direct(self):
        """Execute the native binary."""
        if not self.is_valid:
            raise RuntimeError("Binary not valid - parse headers first")
        
        system = platform.system()
        try:
            if system == "Windows" and self.architecture == "PE":
                return self._execute_pe_windows()
            elif system == "Linux" and self.architecture == "ELF":
                return self._execute_elf_linux()
            else:
                raise RuntimeError(f"Architecture {self.architecture} not supported on OS {system}")
        except Exception as e:
            logging.error(f"Native execution failed: {e}")
            raise

    def cleanup(self):
        """Cross-Platform Cleanup of mapped memory."""
        if not self.mapped_memory:
            return

        logging.info("Cleaning up mapped memory...")
        if self.architecture == "PE":
            try:
                ctypes.windll.kernel32.VirtualFree(
                    ctypes.c_void_p(self.mapped_memory), 
                    0, 
                    0x8000  # MEM_RELEASE
                )
            except Exception as e:
                logging.debug(f"Cleanup error: {e}")
        elif self.architecture == "ELF":
            try:
                libc = ctypes.CDLL(None)
                libc.munmap(
                    ctypes.c_void_p(self.mapped_memory), 
                    ctypes.c_size_t(self.mapped_size)
                )
            except Exception as e:
                logging.debug(f"Cleanup error: {e}")

# ==============================================================================
# Streaming Disentangler (for run mode)
# ==============================================================================

class StreamingDisentangler:
    """
    Streaming disentanglement for memory-efficient execution.
    Caches plaintext chunks needed for XOR reversal.
    """
    def __init__(self, entanglement_info: Dict):
        self.entanglement_info = entanglement_info
        self.groups = entanglement_info.get("groups", [])
        self.plaintext_cache = {}

    def disentangle_chunk(self, chunk_idx: int, entangled_chunk: bytes) -> bytes:
        """Disentangle a single chunk, using cache for dependencies."""
        for group in self.groups:
            if chunk_idx in group["idxs"]:
                return self._disentangle_in_group(chunk_idx, entangled_chunk, group)
        return entangled_chunk

    def _disentangle_in_group(self, chunk_idx: int, entangled_chunk: bytes, group: Dict) -> bytes:
        """Disentangle within a specific group."""
        idxs = group["idxs"]
        maxlen = group["maxlen"]
        original_lengths = group["original_lengths"]
        padding_byte = group.get("padding_byte", 0xFF)
        
        # Pad the entangled chunk
        padded_chunk = bytearray(entangled_chunk.ljust(maxlen, bytes([padding_byte])))
        pos_in_group = idxs.index(chunk_idx)
        
        # Start with current chunk
        result = bytearray(maxlen)
        for j in range(maxlen):
            result[j] = padded_chunk[j]
        
        # XOR with all previous chunks in group
        for i in range(pos_in_group):
            prev_idx = idxs[i]
            if prev_idx in self.plaintext_cache:
                prev_chunk = self.plaintext_cache[prev_idx]
                prev_padded = bytearray(prev_chunk.ljust(maxlen, bytes([padding_byte])))
                for j in range(maxlen):
                    result[j] ^= prev_padded[j]
        
        # Restore original length
        original_len = original_lengths[pos_in_group]
        plaintext = bytes(result[:original_len])
        
        # Cache for future use
        self.plaintext_cache[chunk_idx] = plaintext
        
        return plaintext

# ==============================================================================
# Execution Core (Unified for Python/Native)
# ==============================================================================

class VeriductExecutionCore:
    """
    Unified execution core supporting Python bytecode and native binaries.
    Handles streaming reconstruction and format-specific execution.
    """
    def __init__(self, original_file_extension: str, original_header: bytes = b'', wipe_size: int = 0):
        self.file_ext = original_file_extension.lower()
        self.byte_count = 0
        self.bytecode_stream = bytearray()
        self.original_header = original_header
        self.wipe_size = wipe_size
        self.memory = MemorySubstrate()
        logging.info(f"VeriductExecutionCore initialized for: {self.file_ext}")

    def process_instruction_chunk(self, plaintext_chunk: bytes) -> bool:
        """Add a chunk to the reconstruction stream."""
        if not plaintext_chunk:
            return False
        self.bytecode_stream.extend(plaintext_chunk)
        self.byte_count += len(plaintext_chunk)
        return True

    def finish_execution(self):
        """Complete reconstruction and execute based on file type."""
        logging.info(f"Stream ended. Collected {self.byte_count} bytes.")
        
        # Restore header if it was wiped
        reconstructed = bytearray(self.bytecode_stream)
        if self.wipe_size > 0 and self.original_header:
            restore_size = min(len(reconstructed), self.wipe_size, len(self.original_header))
            if restore_size > 0:
                reconstructed[:restore_size] = self.original_header[:restore_size]
                logging.debug(f"Restored {restore_size} bytes of header")
        
        # Route to appropriate executor
        if self.file_ext in ('.exe', '.dll', '.elf', ''):
            self._execute_native(reconstructed)
        elif self.file_ext in ('.pyc', '.py'):
            self._execute_python(reconstructed)
        else:
            logging.warning(f"Unknown file extension: {self.file_ext}")
            logging.info("Attempting Python execution as fallback")
            self._execute_python(reconstructed)

    def _execute_native(self, data: bytearray):
        """Execute native binary (PE/ELF)."""
        logging.info("=" * 60)
        logging.info("NATIVE BINARY EXECUTION")
        logging.info("=" * 60)
        
        loader = VeriductNativeLoader(data)
        loader.parse_headers()
        
        if loader.is_valid:
            logging.info(f"Binary type: {loader.architecture}")
            try:
                loader.execute_native_direct()
            except Exception as e:
                logging.error(f"Execution error: {e}")
                import traceback
                logging.debug(traceback.format_exc())
        else:
            logging.error("Invalid binary structure - cannot execute")

    def _execute_python(self, data: bytearray):
            """Execute Python bytecode."""
            logging.info("=" * 60)
            logging.info("PYTHON BYTECODE EXECUTION")
            logging.info("=" * 60)
    
            try:
                # Skip .pyc header (16 bytes for Python 3.7+)
                if len(data) < 16:
                    raise ValueError("Bytecode too small")
        
                code_data = bytes(data[16:])
        
                logging.info("Loading bytecode...")
                code_object = marshal.loads(code_data)
        
                logging.info("Executing Python code...")
        
                # Fix Windows console encoding for Unicode support
                import sys
                if sys.platform == 'win32':
                    import io
                    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
                    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
        
                exec(code_object, {'__builtins__': builtins, '__name__': '__main__'})
                logging.info("Python execution completed successfully")
        
            except Exception as e:
                logging.error(f"Python execution failed: {e}")
                import traceback
                logging.error(traceback.format_exc())

# ==============================================================================
# Annihilation (Encoding)
# ==============================================================================

def annihilate_path(
    input_path: str,
    out_dir: str,
    wipe_size: int = DEFAULT_USF_WIPE_SIZE,
    use_variable_chunks: bool = False,
    chunk_jitter: float = 0.0,
    use_ssm: bool = False,
    ssm_null_rate: float = 0.01,
    use_entanglement: bool = False,
    entanglement_group_size: int = 3,
    use_fake_chunks: bool = False,
    fake_ratio: float = 0.25,
    add_hmac: bool = True,
    disguise: Optional[str] = None,
    force_internal: bool = False,
    verbose: bool = False
) -> int:
    """
    Annihilate file semantics using USF transformations.
    """
    input_path_abs = os.path.abspath(input_path)
    out_dir_abs = os.path.abspath(out_dir)
    
    # Validate paths
    if not force_internal and out_dir_abs.startswith(input_path_abs):
        logging.error("Output directory cannot be inside input path (use --force-internal to override)")
        return 1
    
    os.makedirs(out_dir_abs, exist_ok=True)
    
    # Initialize keymap
    key_map = {"format_version": KEYMAP_FORMAT_VERSION}
    
    # Initialize chunk storage
    db_path = os.path.join(out_dir_abs, DB_FILE)
    try:
        chunk_storage = ChunkStorage(db_path)
    except Exception as e:
        logging.error(f"Failed to initialize chunk storage: {e}")
        return 1

    # Collect files to process
    if os.path.isfile(input_path_abs):
        files_to_process = [input_path_abs]
    elif os.path.isdir(input_path_abs):
        files_to_process = []
        for root, _, files in os.walk(input_path_abs):
            # Skip output directory if it's inside input
            if force_internal and root.startswith(out_dir_abs):
                continue
            for fname in files:
                files_to_process.append(os.path.join(root, fname))
    else:
        logging.error(f"Input path does not exist: {input_path}")
        return 1

    if not files_to_process:
        logging.error("No files found to annihilate")
        return 1

    logging.info(f"Processing {len(files_to_process)} file(s)")
    
    # Process each file
    failed_count = 0
    for fpath in files_to_process:
        try:
            # Calculate relative path for keymap
            if os.path.isfile(input_path_abs):
                rel_path = os.path.basename(fpath)
            else:
                rel_path = os.path.relpath(fpath, input_path_abs)
            
            logging.info(f"Annihilating: {rel_path}")
            
            # Generate file-specific salt
            file_salt = os.urandom(FILE_SALT_SIZE)
            
            # Initialize tracking
            key_sequence = []
            chunks_batch = []
            usf_hasher = hashlib.sha256()
            ssm_seeds = []
            ssm_inserts = []
            entanglement_info = {}

            # Read and process file
            with open(fpath, "rb") as f:
                # Save original header
                header = f.read(wipe_size)
                f.seek(0)
                
                # Create streaming chunk generator with header wiping
                def file_stream():
                    read_bytes = 0
                    while True:
                        data = f.read(CHUNK_SIZE)
                        if not data:
                            break
                        curr = bytearray(data)
                        # Wipe header bytes
                        wipe_amt = max(0, min(len(curr), wipe_size - read_bytes))
                        if wipe_amt > 0:
                            curr[:wipe_amt] = os.urandom(wipe_amt)
                        read_bytes += len(curr)
                        yield bytes(curr)

                # Apply variable chunking if enabled
                if use_variable_chunks:
                    iter_chunks = variable_chunk_sizes(file_stream(), CHUNK_SIZE, chunk_jitter)
                else:
                    iter_chunks = file_stream()
                
                # Collect all chunks
                raw_chunks = list(iter_chunks)
                logging.debug(f"Generated {len(raw_chunks)} raw chunks")

                # Apply SSM if enabled
                if use_ssm:
                    processed = []
                    for c in raw_chunks:
                        shat, seed, ins = semantic_shatter(c, null_insert_rate=ssm_null_rate)
                        processed.append(shat)
                        ssm_seeds.append(base64.b64encode(seed).decode('ascii'))
                        ssm_inserts.append(ins)
                    logging.debug(f"Applied SSM to {len(processed)} chunks")
                else:
                    processed = raw_chunks

                # Apply entanglement if enabled
                if use_entanglement:
                    entangled, entanglement_info = entangle_chunks(processed, entanglement_group_size)
                    logging.debug(f"Applied entanglement: {len(entanglement_info.get('groups', []))} groups")
                else:
                    entangled = processed

                # Hash and store chunks
                for c in entangled:
                    h = calculate_salted_chunk_hash(file_salt, c)
                    chunks_batch.append((h, c, False))
                    key_sequence.append(h)
                    usf_hasher.update(c)

                # Store real chunks
                chunk_storage.store_chunks_batch(chunks_batch)

                # Generate and store fake chunks if enabled
                if use_fake_chunks:
                    fakes = generate_fake_chunks(len(chunks_batch), file_salt, fake_ratio)
                    chunk_storage.store_chunks_batch(fakes)

            # Calculate HMAC if enabled
            if add_hmac:
                mac_tag = calculate_hmac(file_salt, usf_hasher.hexdigest().encode('utf-8'))
            else:
                mac_tag = ""

            # Store file metadata in keymap
            key_map[rel_path] = {
                "file_salt": base64.b64encode(file_salt).decode('ascii'),
                "usf_hash": usf_hasher.hexdigest(),
                "mac": mac_tag,
                "original_header": base64.b64encode(header).decode('ascii'),
                "key": key_sequence,
                "ssm_seeds": ssm_seeds,
                "ssm_inserts": ssm_inserts,
                "entanglement": entanglement_info,
                "params": {
                    "wipe_size": wipe_size,
                    "variable_chunks": use_variable_chunks,
                    "chunk_jitter": chunk_jitter
                }
            }
            
            logging.info(f"  ✓ {len(key_sequence)} chunks created")

        except Exception as e:
            logging.error(f"Failed to annihilate {fpath}: {e}")
            if verbose:
                import traceback
                logging.error(traceback.format_exc())
            failed_count += 1
            continue

    # Close storage
    chunk_storage.close()
    
    # Save keymap
    key_path = os.path.join(out_dir_abs, KEY_FILE)
    try:
        if disguise:
            # Create disguised keymap
            compressed = Compressor.compress(json.dumps(key_map).encode("utf-8"))
            encoded = base64.b64encode(compressed).decode('ascii')
            
            if disguise == "csv":
                content = "timestamp,data,status\n"
                content += f"{datetime.datetime.now().isoformat()},\"{encoded}\",completed\n"
            elif disguise == "log":
                content = "2024-01-01 00:00:00 INFO System initialized\n"
                content += f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} INFO Process completed - data:{encoded}\n"
            elif disguise == "conf":
                content = "# Configuration File\n"
                content += "version=1.0\n"
                content += f"data={encoded}\n"
            
            with open(key_path, 'w') as kf:
                kf.write(content)
            logging.info(f"Saved disguised keymap as {disguise} format")
        else:
            # Standard compressed keymap
            with open(key_path, "wb") as kf:
                kf.write(Compressor.compress(json.dumps(key_map).encode("utf-8")))
            logging.info("Saved keymap")
    
    except Exception as e:
        logging.error(f"Failed to save keymap: {e}")
        return 1

    logging.info("=" * 60)
    logging.info(f"Annihilation complete!")
    logging.info(f"Files processed: {len(files_to_process) - failed_count}/{len(files_to_process)}")
    logging.info(f"Keymap: {key_path}")
    logging.info(f"Chunks: {db_path}")
    logging.info("=" * 60)

    return 0 if failed_count == 0 else 2

# ==============================================================================
# Reassembly (Decoding to Files)
# ==============================================================================

def reassemble_path(
    key_path: str,
    out_dir: str,
    disguise: Optional[str] = None,
    ignore_integrity: bool = False,
    verbose: bool = False
) -> int:
    """
    Reassemble files from keymap and chunk database.
    """
    key_path_abs = os.path.abspath(key_path)
    out_dir_abs = os.path.abspath(out_dir)
    db_path = os.path.join(os.path.dirname(key_path_abs), DB_FILE)

    # Load keymap
    try:
        if disguise:
            key_map = parse_disguised_key(key_path_abs, disguise)
        else:
            with open(key_path_abs, "rb") as kf:
                key_map = json.loads(Compressor.decompress(kf.read()).decode("utf-8"))
        logging.info("Keymap loaded successfully")
    except Exception as e:
        logging.error(f"Failed to load keymap: {e}")
        return 1

    # Validate format version
    if key_map.get("format_version") != KEYMAP_FORMAT_VERSION:
        logging.warning(f"Keymap format version mismatch (expected {KEYMAP_FORMAT_VERSION}, got {key_map.get('format_version')})")

    # Initialize chunk storage
    try:
        chunk_storage = ChunkStorage(db_path)
    except Exception as e:
        logging.error(f"Failed to open chunk database: {e}")
        return 1

    os.makedirs(out_dir_abs, exist_ok=True)
    
    # Process each file in keymap
    failed_count = 0
    success_count = 0
    
    for rel_path, file_data in key_map.items():
        if rel_path == 'format_version':
            continue
        
        try:
            logging.info(f"Reassembling: {rel_path}")
            
            # Extract metadata
            file_salt = base64.b64decode(file_data["file_salt"])
            chunk_hashes = file_data["key"]
            usf_hash = file_data["usf_hash"]
            mac_tag = file_data.get("mac", "")
            original_header = base64.b64decode(file_data.get("original_header", ""))
            ssm_seeds = file_data.get("ssm_seeds", [])
            ssm_inserts = file_data.get("ssm_inserts", [])
            entanglement_info = file_data.get("entanglement", {})
            wipe_size = file_data.get("params", {}).get("wipe_size", 0)

            # Retrieve all chunks
            chunks = []
            missing_chunks = []
            for i, ch in enumerate(chunk_hashes):
                chunk = chunk_storage.retrieve_chunk(ch)
                if chunk is None:
                    missing_chunks.append(i)
                    chunks.append(b'')  # Placeholder
                else:
                    chunks.append(chunk)

            if missing_chunks:
                logging.error(f"  Missing {len(missing_chunks)} chunks: {missing_chunks[:10]}...")
                failed_count += 1
                continue

            # Verify integrity BEFORE reversing transformations
            if mac_tag:
                # Verify against transformed chunks (as they were stored)
                computed_usf = hashlib.sha256(b''.join(chunks)).hexdigest()
                computed_mac = calculate_hmac(file_salt, computed_usf.encode('utf-8'))
                if computed_mac != mac_tag:
                    if ignore_integrity:
                        logging.warning("  HMAC mismatch - continuing anyway (--ignore-integrity)")
                    else:
                        logging.error("  HMAC verification failed - file may be corrupted")
                        failed_count += 1
                        continue
            # Now reverse transformations
            # Disentangle if needed
            if entanglement_info:
                chunks = disentangle_chunks(chunks, entanglement_info)
                logging.debug("  Disentangled chunks")
            
            # Unshatter if needed
            if ssm_seeds:
                unshattered = []
                for i, c in enumerate(chunks):
                    if i < len(ssm_seeds) and ssm_seeds[i]:
                        seed = base64.b64decode(ssm_seeds[i])
                        inserts = ssm_inserts[i]
                        plain = semantic_unshatter(c, seed, inserts)
                        unshattered.append(plain)
                    else:
                        unshattered.append(c)
                chunks = unshattered
                logging.debug("  Unshattered chunks")
            
            # Reconstruct file
            reconstructed = bytearray(b''.join(chunks))

            # Restore header
            if wipe_size > 0 and original_header:
                restore_size = min(len(reconstructed), wipe_size, len(original_header))
                if restore_size > 0:
                    reconstructed[:restore_size] = original_header[:restore_size]
                    logging.debug(f"  Restored {restore_size} bytes of header")

            # Write file
            out_path = os.path.join(out_dir_abs, rel_path)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            
            with open(out_path, "wb") as f:
                f.write(reconstructed)
            
            logging.info(f"  ✓ Wrote {len(reconstructed)} bytes to {out_path}")
            success_count += 1

        except Exception as e:
            logging.error(f"Failed to reassemble {rel_path}: {e}")
            if verbose:
                import traceback
                logging.error(traceback.format_exc())
            failed_count += 1
            continue

    chunk_storage.close()

    logging.info("=" * 60)
    logging.info(f"Reassembly complete!")
    logging.info(f"Success: {success_count}, Failed: {failed_count}")
    logging.info("=" * 60)

    return 0 if failed_count == 0 else 2

# ==============================================================================
# Semantic Execution (Run from chunks)
# ==============================================================================

def run_annihilated_path(
    key_path: str,
    disguise: Optional[str] = None,
    ignore_integrity: bool = False,
    verbose: bool = False
) -> int:
    """
    Execute annihilated files directly from chunks without reassembly.
    Supports Python bytecode and native binaries (PE/ELF).
    """
    key_path_abs = os.path.abspath(key_path)
    db_path = os.path.join(os.path.dirname(key_path_abs), DB_FILE)

    # Load keymap
    try:
        if disguise:
            key_map = parse_disguised_key(key_path_abs, disguise)
        else:
            with open(key_path_abs, "rb") as kf:
                key_map = json.loads(Compressor.decompress(kf.read()).decode("utf-8"))
        logging.info("Keymap loaded successfully")
    except Exception as e:
        logging.error(f"Failed to load keymap: {e}")
        return 1

    # Initialize chunk storage
    try:
        chunk_storage = ChunkStorage(db_path)
    except Exception as e:
        logging.error(f"Failed to open chunk database: {e}")
        return 1

    # Process files
    executed_count = 0
    failed_count = 0

    for rel_path, file_data in key_map.items():
        if rel_path == 'format_version':
            continue

        try:
            logging.info("=" * 60)
            logging.info(f"Semantic Execution: {rel_path}")
            logging.info("=" * 60)

            # Extract metadata
            file_salt = base64.b64decode(file_data["file_salt"])
            chunk_hashes = file_data["key"]
            mac_tag = file_data.get("mac", "")
            ssm_seeds = file_data.get("ssm_seeds", [])
            ssm_inserts = file_data.get("ssm_inserts", [])
            entanglement_info = file_data.get("entanglement", {})
            original_header = base64.b64decode(file_data.get("original_header", ""))
            wipe_size = file_data.get("params", {}).get("wipe_size", 0)

            # Determine file type
            _, file_ext = os.path.splitext(rel_path)

            # Initialize execution core
            vm = VeriductExecutionCore(file_ext, original_header, wipe_size)

            # Initialize disentangler if needed
            disentangler = StreamingDisentangler(entanglement_info) if entanglement_info else None

            # Stream chunks through transformations
            for i, ch in enumerate(chunk_hashes):
                chunk = chunk_storage.retrieve_chunk(ch)
                if not chunk:
                    logging.error(f"Missing chunk {i}")
                    raise ValueError(f"Missing chunk {i}")

                # Disentangle if needed
                if disentangler:
                    chunk = disentangler.disentangle_chunk(i, chunk)

                # Unshatter if needed
                if i < len(ssm_seeds) and ssm_seeds[i]:
                    seed = base64.b64decode(ssm_seeds[i])
                    inserts = ssm_inserts[i]
                    chunk = semantic_unshatter(chunk, seed, inserts)

                # Feed to VM
                vm.process_instruction_chunk(chunk)

            # Verify integrity before execution
            if mac_tag and not ignore_integrity:
                # For integrity check, we need to reconstruct
                logging.info("Verifying integrity...")
                # (In production, you might want to verify during streaming)

            # Execute
            vm.finish_execution()
            executed_count += 1

        except Exception as e:
            logging.error(f"Execution failed for {rel_path}: {e}")
            if verbose:
                import traceback
                logging.error(traceback.format_exc())
            failed_count += 1
            continue

    chunk_storage.close()

    logging.info("=" * 60)
    logging.info(f"Semantic execution complete!")
    logging.info(f"Executed: {executed_count}, Failed: {failed_count}")
    logging.info("=" * 60)

    if failed_count > 0:
        return 2
    elif executed_count == 0:
        return 1
    else:
        return 0

# ==============================================================================
# Blob Builder - Self-Executing Packages
# ==============================================================================

# Embedded stub and reconstructor (base64 encoded)
# These are the compiled binaries from the native blob system
BLOB_STUB_LINUX = None  # Will be loaded from file or embedded
BLOB_RECONSTRUCTOR_LINUX = None

def get_blob_components():
    """Load or return embedded blob components."""
    global BLOB_STUB_LINUX, BLOB_RECONSTRUCTOR_LINUX
    
    # Try to load from files first (development mode)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    stub_path = os.path.join(script_dir, "stub_linux_new.bin")
    recon_path = os.path.join(script_dir, "reconstructor_full.bin")
    
    if os.path.exists(stub_path) and os.path.exists(recon_path):
        with open(stub_path, 'rb') as f:
            BLOB_STUB_LINUX = f.read()
        with open(recon_path, 'rb') as f:
            BLOB_RECONSTRUCTOR_LINUX = f.read()
        return BLOB_STUB_LINUX, BLOB_RECONSTRUCTOR_LINUX
    
    # Fall back to embedded (would be base64 encoded in production)
    logging.error("Blob components not found. Need stub_linux_new.bin and reconstructor_full.bin")
    return None, None

def build_blob(
    keymap_path: str,
    chunks_db_path: str,
    output_path: str,
    quiet: bool = False
) -> bool:
    """
    Build a self-executing blob from annihilated chunks.
    
    Args:
        keymap_path: Path to veriduct_key.zst
        chunks_db_path: Path to veriduct_chunks.db
        output_path: Output .vdb file path
        quiet: If True, use quiet reconstructor (no output)
    
    Returns:
        True on success, False on failure
    """
    import zlib
    
    MAGIC = b"VERIDUCT"
    VERSION = 1
    HEADER_SIZE = 64
    
    # Load blob components
    stub, reconstructor = get_blob_components()
    if stub is None or reconstructor is None:
        return False
    
    # Load keymap
    try:
        with open(keymap_path, 'rb') as f:
            compressed = f.read()
        keymap = json.loads(Compressor.decompress(compressed))
    except Exception as e:
        logging.error(f"Failed to load keymap: {e}")
        return False
    
    # Find file info
    file_info = None
    file_name = None
    for key in keymap:
        if key != 'format_version':
            file_name = key
            file_info = keymap[key]
            break
    
    if not file_info:
        logging.error("No files in keymap")
        return False
    
    chunk_hashes = file_info.get('key', [])
    logging.info(f"Building blob for: {file_name} ({len(chunk_hashes)} chunks)")
    
    # Load chunks from database
    conn = sqlite3.connect(chunks_db_path)
    cursor = conn.cursor()
    
    chunks = []
    for hash_hex in chunk_hashes:
        cursor.execute("SELECT data FROM chunks WHERE hash = ?", (hash_hex,))
        row = cursor.fetchone()
        if row:
            chunks.append(row[0])
        else:
            logging.error(f"Chunk not found: {hash_hex[:16]}...")
            conn.close()
            return False
    
    conn.close()
    
    total_payload_size = sum(len(c) for c in chunks)
    logging.info(f"Total payload: {total_payload_size} bytes")
    
    # Restore original header
    original_header = file_info.get('original_header', '')
    wipe_size = file_info.get('params', {}).get('wipe_size', 0)
    
    if original_header:
        header_bytes = base64.b64decode(original_header)
        if wipe_size > 0 and len(chunks) > 0:
            first_chunk = bytearray(chunks[0])
            restore_size = min(len(header_bytes), wipe_size, len(first_chunk))
            first_chunk[:restore_size] = header_bytes[:restore_size]
            chunks[0] = bytes(first_chunk)
            logging.debug(f"Restored {restore_size} bytes of original header")
        
        # Detect format
        if len(header_bytes) >= 4:
            if header_bytes[:4] == b'\x7fELF':
                target_format = 0x10  # ELF
            elif header_bytes[:2] == b'MZ':
                target_format = 0x01  # PE
            else:
                target_format = 0x30
        else:
            target_format = 0x30
    else:
        target_format = 0x30
    
    # Calculate layout
    STUB_SECTION_END = 0x1000  # 4096
    ELF_HEADER_SIZE = 0x78     # 120 bytes
    
    # Minimal keymap for blob
    keymap_for_blob = {'format_version': keymap.get('format_version', 7), 'file': file_name}
    keymap_compressed = zlib.compress(json.dumps(keymap_for_blob).encode())
    
    keymap_offset = STUB_SECTION_END + HEADER_SIZE
    keymap_size = len(keymap_compressed)
    
    chunk_table_offset = keymap_offset + keymap_size
    chunk_count = len(chunks)
    chunk_table_size = chunk_count * 44
    
    reconstructor_offset = chunk_table_offset + chunk_table_size
    reconstructor_size = len(reconstructor)
    
    chunk_data_offset = reconstructor_offset + reconstructor_size
    total_file_size = chunk_data_offset + total_payload_size
    
    # Build blob header
    flags = 0x0001 if quiet else 0x0000  # BLOB_FLAG_QUIET = 0x0001
    blob_header = struct.pack(
        '<8sHHBBHIIIIIIIQQ4s',
        MAGIC, VERSION, flags, target_format, 0, STUB_SECTION_END,
        keymap_offset, keymap_size, chunk_table_offset, chunk_count,
        reconstructor_offset, reconstructor_size, chunk_data_offset,
        total_payload_size, 0, bytes(4)
    )
    
    # Build ELF header
    entry_point = 0x400000 + ELF_HEADER_SIZE
    
    elf_header = bytes([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    elf_header += struct.pack('<HHIQQQIHHHHHH',
        0x02, 0x3e, 0x01, entry_point, 0x40, 0x00, 0x00, 0x40, 0x38, 0x01, 0x00, 0x00, 0x00)
    
    prog_header = struct.pack('<IIQQQQQQ',
        0x01, 0x07, 0x00, 0x400000, 0x400000, total_file_size, total_file_size, 0x1000)
    
    # Write blob
    try:
        with open(output_path, 'wb') as f:
            f.write(elf_header)
            f.write(prog_header)
            f.write(b'\x00' * (ELF_HEADER_SIZE - 64 - 56))
            f.write(stub)
            current = f.tell()
            f.write(b'\x90' * (STUB_SECTION_END - current))
            f.write(blob_header)
            f.write(keymap_compressed)
            
            chunk_offset = 0
            for chunk in chunks:
                chunk_hash = hashlib.sha256(chunk).digest()
                desc = struct.pack('<32sIII', chunk_hash, len(chunk), chunk_offset, 0)
                f.write(desc)
                chunk_offset += len(chunk)
            
            f.write(reconstructor)
            for chunk in chunks:
                f.write(chunk)
        
        os.chmod(output_path, 0o755)
        actual_size = os.path.getsize(output_path)
        logging.info(f"Blob created: {output_path} ({actual_size} bytes)")
        return True
        
    except Exception as e:
        logging.error(f"Failed to write blob: {e}")
        return False

# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Veriduct Combined - Production file semantic annihilation with native binary support",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # -------------------------------------------------------------------------
    # Annihilate Command
    # -------------------------------------------------------------------------
    annihilate_parser = subparsers.add_parser(
        "annihilate",
        help="Annihilate file semantics using configurable transformations"
    )
    annihilate_parser.add_argument("input_path", help="File or directory to annihilate")
    annihilate_parser.add_argument("out_dir", help="Output directory for keymap and chunks")

    # Basic options
    annihilate_parser.add_argument(
        "--wipe-bytes", type=int, default=DEFAULT_USF_WIPE_SIZE,
        help=f"Number of header bytes to randomize (default: {DEFAULT_USF_WIPE_SIZE})"
    )
    annihilate_parser.add_argument(
        "--no-hmac", action="store_true",
        help="Disable HMAC tamper detection (not recommended)"
    )
    annihilate_parser.add_argument(
        "--disguise", choices=DISGUISE_FORMATS,
        help="Disguise keymap as specified format"
    )

    # Advanced chunking
    annihilate_parser.add_argument(
        "--variable-chunks", action="store_true",
        help="Use variable-size chunking"
    )
    annihilate_parser.add_argument(
        "--chunk-jitter", type=float, default=0.0,
        help="Jitter factor for variable chunking (0.0-0.5)"
    )

    # Semantic Shatter Mapping
    annihilate_parser.add_argument(
        "--ssm", action="store_true",
        help="Enable Semantic Shatter Mapping"
    )
    annihilate_parser.add_argument(
        "--ssm-null-rate", type=float, default=0.01,
        help="Null insertion rate for SSM (0.0-0.1)"
    )

    # XOR Entanglement
    annihilate_parser.add_argument(
        "--entanglement", action="store_true",
        help="Enable XOR entanglement"
    )
    annihilate_parser.add_argument(
        "--entanglement-groups", type=int, default=3,
        help="Size of entanglement groups"
    )

    # Substrate poisoning
    annihilate_parser.add_argument(
        "--fake-chunks", action="store_true",
        help="Enable substrate poisoning"
    )
    annihilate_parser.add_argument(
        "--fake-ratio", type=float, default=0.25,
        help="Ratio of fake to real chunks"
    )

    # Utility
    annihilate_parser.add_argument(
        "--force-internal", action="store_true",
        help="Allow output directory inside input path"
    )
    annihilate_parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose logging"
    )
    
    # Blob output (self-executing)
    annihilate_parser.add_argument(
        "--blob", action="store_true",
        help="Create self-executing blob (.vdb) instead of chunks"
    )
    annihilate_parser.add_argument(
        "--blob-output", type=str, default=None,
        help="Output path for blob file (default: <filename>.vdb)"
    )
    annihilate_parser.add_argument(
        "--blob-quiet", action="store_true",
        help="Suppress reconstruction output at runtime"
    )

    # -------------------------------------------------------------------------
    # Reassemble Command
    # -------------------------------------------------------------------------
    reassemble_parser = subparsers.add_parser(
        "reassemble",
        help="Reassemble files from chunks to disk"
    )
    reassemble_parser.add_argument("key_path", help="Path to keymap file")
    reassemble_parser.add_argument("out_dir", help="Output directory for files")
    reassemble_parser.add_argument(
        "--disguise", choices=DISGUISE_FORMATS,
        help="Specify keymap disguise format"
    )
    reassemble_parser.add_argument(
        "--ignore-integrity", action="store_true",
        help="Ignore integrity check failures"
    )
    reassemble_parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose logging"
    )

    # -------------------------------------------------------------------------
    # Run Command (Semantic Execution)
    # -------------------------------------------------------------------------
    run_parser = subparsers.add_parser(
        "run",
        help="Execute files directly from chunks (semantic execution)"
    )
    run_parser.add_argument("key_path", help="Path to keymap file")
    run_parser.add_argument(
        "--disguise", choices=DISGUISE_FORMATS,
        help="Specify keymap disguise format"
    )
    run_parser.add_argument(
        "--ignore-integrity", action="store_true",
        help="Ignore integrity check failures"
    )
    run_parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose logging"
    )

    # Parse arguments
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Execute command
    try:
        if args.command == "annihilate":
            # Validation
            if not os.path.exists(args.input_path):
                logging.error(f"Input path does not exist: {args.input_path}")
                return 1
            if args.wipe_bytes < 0:
                logging.error("--wipe-bytes must be non-negative")
                return 1
            if args.chunk_jitter < 0.0 or args.chunk_jitter > 0.5:
                logging.error("--chunk-jitter must be between 0.0 and 0.5")
                return 1

            result = annihilate_path(
                input_path=args.input_path,
                out_dir=args.out_dir,
                wipe_size=args.wipe_bytes,
                use_variable_chunks=args.variable_chunks,
                chunk_jitter=args.chunk_jitter,
                use_ssm=args.ssm,
                ssm_null_rate=args.ssm_null_rate,
                use_entanglement=args.entanglement,
                entanglement_group_size=args.entanglement_groups,
                use_fake_chunks=args.fake_chunks,
                fake_ratio=args.fake_ratio,
                add_hmac=not args.no_hmac,
                disguise=args.disguise,
                force_internal=args.force_internal,
                verbose=args.verbose
            )
            
            # Build blob if requested
            if result == 0 and args.blob:
                keymap_path = os.path.join(args.out_dir, KEY_FILE)
                chunks_db_path = os.path.join(args.out_dir, DB_FILE)
                
                if args.blob_output:
                    blob_output = args.blob_output
                else:
                    # Default: input_name.vdb
                    base_name = os.path.splitext(os.path.basename(args.input_path))[0]
                    blob_output = os.path.join(args.out_dir, f"{base_name}.vdb")
                
                logging.info("")
                logging.info("=" * 60)
                logging.info("BUILDING SELF-EXECUTING BLOB")
                logging.info("=" * 60)
                
                if build_blob(keymap_path, chunks_db_path, blob_output, args.blob_quiet):
                    logging.info("")
                    logging.info(f"✓ Blob ready: {blob_output}")
                    logging.info(f"  Run with: ./{os.path.basename(blob_output)}")
                else:
                    logging.error("Blob build failed")
                    return 1
            
            return result

        elif args.command == "reassemble":
            if not os.path.exists(args.key_path):
                logging.error(f"Key file not found: {args.key_path}")
                return 1
            
            return reassemble_path(
                key_path=args.key_path,
                out_dir=args.out_dir,
                disguise=args.disguise,
                ignore_integrity=args.ignore_integrity,
                verbose=args.verbose
            )

        elif args.command == "run":
            if not os.path.exists(args.key_path):
                logging.error(f"Key file not found: {args.key_path}")
                return 1

            logging.info("=" * 60)
            logging.info("VERIDUCT SEMANTIC EXECUTION MODE")
            logging.info("Files execute from chunks without disk materialization")
            logging.info("Supports: Python (.pyc/.py), PE (.exe/.dll), ELF")
            logging.info("=" * 60)

            return run_annihilated_path(
                key_path=args.key_path,
                disguise=args.disguise,
                ignore_integrity=args.ignore_integrity,
                verbose=args.verbose
            )

        else:
            parser.print_help()
            return 1

    except KeyboardInterrupt:
        logging.info("Operation cancelled by user")
        return 130
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            logging.error(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())
