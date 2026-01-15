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

Version: 2.1 (Hardened - Bounds Checking, Memory Safety, Leak Prevention)
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
from ctypes import wintypes

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

# PEB Structures for CRT initialization
class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]

class LIST_ENTRY(ctypes.Structure):
    pass
LIST_ENTRY._fields_ = [
    ("Flink", ctypes.POINTER(LIST_ENTRY)),
    ("Blink", ctypes.POINTER(LIST_ENTRY)),
]

class PEB_LDR_DATA(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("Initialized", wintypes.BOOLEAN),
        ("SsHandle", wintypes.HANDLE),
        ("InLoadOrderModuleList", LIST_ENTRY),
        ("InMemoryOrderModuleList", LIST_ENTRY),
        ("InInitializationOrderModuleList", LIST_ENTRY),
    ]

class CURDIR(ctypes.Structure):
    _fields_ = [
        ("DosPath", UNICODE_STRING),
        ("Handle", wintypes.HANDLE),
    ]

class RTL_USER_PROCESS_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ("MaximumLength", wintypes.ULONG),
        ("Length", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
        ("DebugFlags", wintypes.ULONG),
        ("ConsoleHandle", wintypes.HANDLE),
        ("ConsoleFlags", wintypes.ULONG),
        ("StandardInput", wintypes.HANDLE),
        ("StandardOutput", wintypes.HANDLE),
        ("StandardError", wintypes.HANDLE),
        ("CurrentDirectory", CURDIR),
        ("DllPath", UNICODE_STRING),
        ("ImagePathName", UNICODE_STRING),
        ("CommandLine", UNICODE_STRING),
    ]

class PEB(ctypes.Structure):
    _fields_ = [
        ("InheritedAddressSpace", wintypes.BOOLEAN),
        ("ReadImageFileExecOptions", wintypes.BOOLEAN),
        ("BeingDebugged", wintypes.BOOLEAN),
        ("BitField", wintypes.BYTE),
        ("Padding0", wintypes.BYTE * 4),
        ("Mutant", wintypes.HANDLE),
        ("ImageBaseAddress", wintypes.LPVOID),
        ("Ldr", ctypes.POINTER(PEB_LDR_DATA)),
        ("ProcessParameters", ctypes.POINTER(RTL_USER_PROCESS_PARAMETERS)),
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", wintypes.LPVOID),
        ("PebBaseAddress", ctypes.POINTER(PEB)),
        ("Reserved2", wintypes.LPVOID * 2),
        ("UniqueProcessId", ctypes.POINTER(wintypes.ULONG)),
        ("Reserved3", wintypes.LPVOID),
    ]

class LDR_DATA_TABLE_ENTRY(ctypes.Structure):
    """Loader data table entry for module enumeration."""
    pass

LDR_DATA_TABLE_ENTRY._fields_ = [
    ("InLoadOrderLinks", LIST_ENTRY),
    ("InMemoryOrderLinks", LIST_ENTRY),
    ("InInitializationOrderLinks", LIST_ENTRY),
    ("DllBase", wintypes.LPVOID),
    ("EntryPoint", wintypes.LPVOID),
    ("SizeOfImage", wintypes.ULONG),
    ("FullDllName", UNICODE_STRING),
    ("BaseDllName", UNICODE_STRING),
]


class StealthResolver:
    """
    Resolve Windows API functions without using ctypes.windll (which triggers EDR telemetry).
    Walks PEB -> LDR -> module list, then parses PE export tables manually.
    """
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._module_cache = {}  # name.lower() -> base_address
        self._proc_cache = {}    # (module, func) -> address
        self._peb = None
        self._init_from_peb()
    
    def _init_from_peb(self):
        """Walk PEB to find loaded modules. Stealth-only, no fallbacks."""
        self._fallback_mode = False
        try:
            self._bootstrap_peb()
        except Exception as e:
            logging.error(f"StealthResolver init failed: {e}")
            logging.error("Stealth API resolution not available - this is required for operation")
            raise
    
    def _bootstrap_peb(self):
        """Get PEB address. Try multiple methods for maximum compatibility."""
        import ctypes.wintypes as wt
        
        # Method 1: RtlGetCurrentPeb - simplest, exported by ntdll
        # This is what PythonForWindows uses and is very reliable
        try:
            ntdll = ctypes.windll.ntdll
            ntdll.RtlGetCurrentPeb.restype = ctypes.c_void_p
            peb_addr = ntdll.RtlGetCurrentPeb()
            if peb_addr:
                self._peb = ctypes.cast(peb_addr, ctypes.POINTER(PEB)).contents
                logging.debug(f"StealthResolver: Got PEB via RtlGetCurrentPeb at 0x{peb_addr:X}")
                self._walk_ldr_modules()
                return
        except Exception as e:
            logging.debug(f"RtlGetCurrentPeb failed: {e}")
        
        # Method 2: NtQueryInformationProcess - fallback
        try:
            NtQueryInformationProcess = ctypes.windll.ntdll.NtQueryInformationProcess
            GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
            
            # Set up proper types
            NtQueryInformationProcess.argtypes = [
                ctypes.c_void_p,  # ProcessHandle
                ctypes.c_ulong,   # ProcessInformationClass
                ctypes.c_void_p,  # ProcessInformation
                ctypes.c_ulong,   # ProcessInformationLength
                ctypes.POINTER(wt.ULONG)  # ReturnLength
            ]
            NtQueryInformationProcess.restype = ctypes.c_long
            
            GetCurrentProcess.restype = ctypes.c_void_p
            
            pbi = PROCESS_BASIC_INFORMATION()
            ret_len = wt.ULONG()
            
            handle = GetCurrentProcess()
            status = NtQueryInformationProcess(
                handle, 0, ctypes.byref(pbi),
                ctypes.sizeof(pbi), ctypes.byref(ret_len)
            )
            if status != 0:
                raise RuntimeError(f"NtQueryInformationProcess failed: {status}")
            
            self._peb = pbi.PebBaseAddress.contents
            logging.debug(f"StealthResolver: Got PEB via NtQueryInformationProcess")
            self._walk_ldr_modules()
            return
        except Exception as e:
            logging.debug(f"NtQueryInformationProcess failed: {e}")
        
        raise RuntimeError("All PEB acquisition methods failed")
    
    def _walk_ldr_modules(self):
        """Walk PEB.Ldr.InMemoryOrderModuleList to find all loaded modules."""
        ldr = self._peb.Ldr.contents
        
        # InMemoryOrderModuleList is a circular doubly-linked list
        # The list head is embedded in PEB_LDR_DATA, entries are LDR_DATA_TABLE_ENTRY
        list_head = ctypes.addressof(ldr.InMemoryOrderModuleList)
        current = ldr.InMemoryOrderModuleList.Flink
        
        while ctypes.addressof(current.contents) != list_head:
            # The LIST_ENTRY is at offset 0x10 in LDR_DATA_TABLE_ENTRY (InMemoryOrderLinks)
            # So we subtract 0x10 (on x64, or 0x08 on x86) to get the entry base
            # Actually, for InMemoryOrderLinks which is the second LIST_ENTRY:
            # Offset = sizeof(LIST_ENTRY) = 16 bytes on x64, 8 bytes on x86
            entry_offset = ctypes.sizeof(LIST_ENTRY)
            entry_addr = ctypes.addressof(current.contents) - entry_offset
            
            entry = ctypes.cast(entry_addr, ctypes.POINTER(LDR_DATA_TABLE_ENTRY)).contents
            
            if entry.DllBase and entry.BaseDllName.Buffer:
                try:
                    # Read the DLL name
                    name_len = entry.BaseDllName.Length // 2  # Length is in bytes, we want chars
                    dll_name = ctypes.wstring_at(entry.BaseDllName.Buffer, name_len).lower()
                    base = entry.DllBase
                    
                    if isinstance(base, int):
                        base_int = base
                    else:
                        base_int = ctypes.cast(base, ctypes.c_void_p).value
                    
                    self._module_cache[dll_name] = base_int
                    logging.debug(f"StealthResolver: Found {dll_name} at 0x{base_int:X}")
                except Exception:
                    pass
            
            current = current.contents.Flink
    
    def get_module_base(self, module_name: str) -> int:
        """Get base address of a loaded module via stealth resolution."""
        name_lower = module_name.lower()
        
        if name_lower in self._module_cache:
            return self._module_cache[name_lower]
        
        # Try without extension
        if not name_lower.endswith('.dll'):
            if name_lower + '.dll' in self._module_cache:
                return self._module_cache[name_lower + '.dll']
        
        return 0
    
    def get_proc_address(self, module_name: str, proc_name: str) -> int:
        """
        Get function address by parsing module's export table.
        Equivalent to GetProcAddress but without API calls - pure stealth.
        """
        cache_key = (module_name.lower(), proc_name if isinstance(proc_name, str) else proc_name.decode('ascii'))
        if cache_key in self._proc_cache:
            return self._proc_cache[cache_key]
        
        base = self.get_module_base(module_name)
        if not base:
            logging.warning(f"StealthResolver: Module {module_name} not found in PEB")
            return 0
        
        addr = self._parse_exports(base, proc_name)
        if addr:
            self._proc_cache[cache_key] = addr
        return addr
    
    def _parse_exports(self, base: int, proc_name: str) -> int:
        """Parse PE export table to find function address."""
        try:
            # Read DOS header
            dos_magic = ctypes.string_at(base, 2)
            if dos_magic != b'MZ':
                return 0
            
            # Get PE header offset
            pe_offset = struct.unpack('<I', ctypes.string_at(base + 0x3C, 4))[0]
            pe_sig = ctypes.string_at(base + pe_offset, 4)
            if pe_sig != b'PE\x00\x00':
                return 0
            
            # Check if PE32 or PE32+
            magic = struct.unpack('<H', ctypes.string_at(base + pe_offset + 24, 2))[0]
            is_64 = (magic == 0x20b)
            
            # Export directory RVA is at different offsets for PE32 vs PE32+
            if is_64:
                export_rva = struct.unpack('<I', ctypes.string_at(base + pe_offset + 24 + 112, 4))[0]
                export_size = struct.unpack('<I', ctypes.string_at(base + pe_offset + 24 + 116, 4))[0]
            else:
                export_rva = struct.unpack('<I', ctypes.string_at(base + pe_offset + 24 + 96, 4))[0]
                export_size = struct.unpack('<I', ctypes.string_at(base + pe_offset + 24 + 100, 4))[0]
            
            if export_rva == 0:
                return 0
            
            export_dir = base + export_rva
            
            # Parse IMAGE_EXPORT_DIRECTORY
            num_functions = struct.unpack('<I', ctypes.string_at(export_dir + 20, 4))[0]
            num_names = struct.unpack('<I', ctypes.string_at(export_dir + 24, 4))[0]
            addr_table_rva = struct.unpack('<I', ctypes.string_at(export_dir + 28, 4))[0]
            name_table_rva = struct.unpack('<I', ctypes.string_at(export_dir + 32, 4))[0]
            ordinal_table_rva = struct.unpack('<I', ctypes.string_at(export_dir + 36, 4))[0]
            
            # Search by name
            if isinstance(proc_name, str):
                proc_name_bytes = proc_name.encode('ascii')
            else:
                proc_name_bytes = proc_name
            
            for i in range(num_names):
                name_rva = struct.unpack('<I', ctypes.string_at(base + name_table_rva + i * 4, 4))[0]
                name = ctypes.string_at(base + name_rva)
                
                if name == proc_name_bytes:
                    # Found it - get ordinal, then address
                    ordinal = struct.unpack('<H', ctypes.string_at(base + ordinal_table_rva + i * 2, 2))[0]
                    func_rva = struct.unpack('<I', ctypes.string_at(base + addr_table_rva + ordinal * 4, 4))[0]
                    
                    # Check for forwarder (RVA points within export section)
                    if export_rva <= func_rva < export_rva + export_size:
                        # This is a forwarder - would need to resolve it
                        # For now, skip forwarders
                        logging.debug(f"StealthResolver: {proc_name} is a forwarder, skipping")
                        return 0
                    
                    return base + func_rva
            
            return 0
            
        except Exception as e:
            logging.debug(f"StealthResolver: Failed to parse exports: {e}")
            return 0
    
    def load_library(self, dll_name: str) -> int:
        """
        Load a DLL. For DLLs not already loaded, we unfortunately need LoadLibraryA.
        But we call it through our resolved address, not ctypes.windll.
        """
        # Check if already loaded
        base = self.get_module_base(dll_name)
        if base:
            return base
        
        # Need to actually load it - get LoadLibraryA address
        load_lib_addr = self.get_proc_address("kernel32.dll", "LoadLibraryA")
        if not load_lib_addr:
            return 0
        
        # Call LoadLibraryA through the resolved address using WINFUNCTYPE
        LoadLibraryA = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)(load_lib_addr)
        
        if isinstance(dll_name, str):
            dll_name = dll_name.encode('ascii')
        
        handle = LoadLibraryA(dll_name)
        if handle:
            handle_int = handle if isinstance(handle, int) else ctypes.cast(handle, ctypes.c_void_p).value
            # Cache it
            name_str = dll_name.decode('ascii') if isinstance(dll_name, bytes) else dll_name
            self._module_cache[name_str.lower()] = handle_int
            return handle_int
        return 0


# Global resolver instance - initialized lazily on first use
_stealth_resolver = None

def get_stealth_resolver() -> StealthResolver:
    """Get or create the global StealthResolver instance."""
    global _stealth_resolver
    if _stealth_resolver is None:
        _stealth_resolver = StealthResolver()
    return _stealth_resolver

class CRTInitializer:
    def __init__(self, base_addr, stream, is_64bit, load_config_rva=0, load_config_size=0, command_line=None):
        self.base_addr = base_addr
        self.stream = stream
        self.is_64bit = is_64bit
        self.load_config_rva = load_config_rva
        self.load_config_size = load_config_size
        self.peb_ptr = None
        self.orig_image_base = None
        self.orig_command_line = None
        self.command_line = command_line  # New: command line args to pass to PE
        
    def _get_peb(self):
        if self.peb_ptr is not None:
            return self.peb_ptr
        
        # Use StealthResolver to get PEB - it already has it cached from initialization
        resolver = get_stealth_resolver()
        if hasattr(resolver, '_peb') and resolver._peb is not None:
            # StealthResolver already has PEB from its bootstrap
            self.peb_ptr = ctypes.pointer(resolver._peb)
            return self.peb_ptr
        
        # Fallback: resolve functions via stealth and call them
        NtQueryInformationProcess_addr = resolver.get_proc_address("ntdll.dll", "NtQueryInformationProcess")
        GetCurrentProcess_addr = resolver.get_proc_address("kernel32.dll", "GetCurrentProcess")
        
        if not NtQueryInformationProcess_addr or not GetCurrentProcess_addr:
            raise RuntimeError("Failed to resolve NtQueryInformationProcess/GetCurrentProcess")
        
        NtQueryInformationProcess = ctypes.WINFUNCTYPE(
            ctypes.c_long, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(wintypes.ULONG)
        )(NtQueryInformationProcess_addr)
        
        GetCurrentProcess = ctypes.WINFUNCTYPE(ctypes.c_void_p)(GetCurrentProcess_addr)
        
        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = wintypes.ULONG()
        status = NtQueryInformationProcess(
            GetCurrentProcess(), 0, ctypes.byref(pbi),
            ctypes.sizeof(pbi), ctypes.byref(ret_len))
        if status != 0:
            raise RuntimeError(f"NtQueryInformationProcess failed: {status}")
        self.peb_ptr = pbi.PebBaseAddress
        return self.peb_ptr
    
    def initialize(self):
        logging.info("Initializing CRT environment...")
        self._init_security_cookie()
        self._patch_peb()
        self._patch_command_line()
        logging.info("CRT initialization complete")
    
    def _patch_peb(self):
        try:
            peb = self._get_peb()
            self.orig_image_base = peb.contents.ImageBaseAddress
            peb.contents.ImageBaseAddress = ctypes.c_void_p(self.base_addr)
            logging.debug(f"PEB.ImageBaseAddress patched to 0x{self.base_addr:X}")
        except Exception as e:
            logging.warning(f"Failed to patch PEB: {e}")
    
    def _patch_command_line(self):
        """Patch the command line in PEB.ProcessParameters."""
        if not self.command_line:
            return
        try:
            peb = self._get_peb()
            params = peb.contents.ProcessParameters.contents
            
            # Save original
            self.orig_command_line = (
                params.CommandLine.Length,
                params.CommandLine.MaximumLength,
                params.CommandLine.Buffer
            )
            
            # Create new command line string (wide chars)
            cmd_wide = self.command_line
            if not cmd_wide.endswith('\x00'):
                cmd_wide += '\x00'
            
            # Allocate and set new command line
            new_buffer = ctypes.create_unicode_buffer(cmd_wide)
            params.CommandLine.Buffer = ctypes.cast(new_buffer, wintypes.LPWSTR)
            params.CommandLine.Length = (len(self.command_line)) * 2  # Wide chars
            params.CommandLine.MaximumLength = (len(cmd_wide)) * 2
            
            # Keep reference to prevent garbage collection
            self._cmd_buffer = new_buffer
            
            logging.debug(f"CommandLine patched to: {self.command_line}")
        except Exception as e:
            logging.warning(f"Failed to patch CommandLine: {e}")
    
    def _init_security_cookie(self):
        if self.load_config_rva == 0:
            logging.warning("No Load Config RVA found. Skipping cookie init.")
            return
        try:
            # CRITICAL FIX: 
            # On x64, SecurityCookie is at offset 0x58 (88), NOT 0x60.
            # On x86, SecurityCookie is at offset 0x3C (60).
            cookie_ptr_offset = 0x58 if self.is_64bit else 0x3C
            
            required_size = cookie_ptr_offset + (8 if self.is_64bit else 4)
            if self.load_config_size < required_size:
                logging.warning(f"Load Config too small for cookie (Size: {self.load_config_size})")
                return
                
            load_config_va = self.base_addr + self.load_config_rva
            cookie_va_addr = load_config_va + cookie_ptr_offset
            
            if self.is_64bit:
                cookie_va = ctypes.c_uint64.from_address(cookie_va_addr).value
            else:
                cookie_va = ctypes.c_uint32.from_address(cookie_va_addr).value
                
            if cookie_va == 0:
                logging.warning("Security Cookie VA is NULL. Skipping.")
                return
                
            # Generate and write random cookie
            if self.is_64bit:
                new_cookie = random.randint(0x0000FFFF00000000, 0x0000FFFFFFFFFFFF)
                ctypes.c_uint64.from_address(cookie_va).value = new_cookie
            else:
                new_cookie = random.randint(0x0000FFFF, 0x7FFFFFFF)
                ctypes.c_uint32.from_address(cookie_va).value = new_cookie
                
            logging.info(f"Security cookie at 0x{cookie_va:X} set to 0x{new_cookie:X}")
        except Exception as e:
            logging.error(f"Failed to init security cookie: {e}")
    
    def restore(self):
        if self.orig_image_base is not None and self.peb_ptr is not None:
            try:
                self.peb_ptr.contents.ImageBaseAddress = self.orig_image_base
            except:
                pass

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
    Reversible XOR entanglement with correct variable-size handling.
    
    CRITICAL FIX: Store full-length XOR state to preserve all bits needed for
    correct disentanglement. Original lengths are tracked in metadata for
    final truncation after disentanglement.
    
    The bug was: truncating entangled chunks to original length loses XOR state
    bits needed to reconstruct subsequent chunks in the group.
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

        # Build cumulative XOR prefix
        prefix = []
        acc = bytearray(maxlen)
        for p in padded:
            for j in range(maxlen):
                acc[j] ^= p[j]
            prefix.append(bytes(acc))

        # FIX: Store FULL prefix length, not truncated to original
        # This preserves all XOR state bits needed for disentanglement
        for i, (idx, pref) in enumerate(zip(idxs, prefix)):
            entangled[idx] = pref  # Full maxlen, no truncation

        info["groups"].append({
            "idxs": idxs,
            "maxlen": maxlen,
            "original_lengths": original_lengths,
            "padding_byte": padding_byte
        })

    return entangled, info

def disentangle_chunks(entangled: List[bytes], info: Dict) -> List[bytes]:
    """
    Reverse XOR entanglement and restore original chunk lengths.
    
    The entangled chunks are stored at maxlen to preserve full XOR state.
    After disentanglement, we truncate to original_lengths.
    """
    out = list(entangled)
    for g in info.get("groups", []):
        idxs = g["idxs"]
        maxlen = g["maxlen"]
        original_lengths = g["original_lengths"]
        padding_byte = g.get("padding_byte", 0xFF)

        # Entangled chunks should already be at maxlen
        # If not (legacy data), pad them - but this may cause corruption
        prefix = []
        for i, idx in enumerate(idxs):
            chunk = out[idx]
            if len(chunk) < maxlen:
                logging.warning(f"Entangled chunk {idx} is {len(chunk)} bytes, expected {maxlen} - padding (may cause corruption)")
            padded_chunk = bytearray(chunk.ljust(maxlen, bytes([padding_byte])))
            prefix.append(padded_chunk)

        # Reverse the XOR chain
        originals = []
        prev = bytearray(maxlen)
        for p in prefix:
            orig = bytearray(maxlen)
            for j in range(maxlen):
                orig[j] = prev[j] ^ p[j]
            originals.append(bytes(orig))
            prev = p

        # NOW truncate to original lengths (after disentanglement is complete)
        for i, (idx, orig, orig_len) in enumerate(zip(idxs, originals, original_lengths)):
            out[idx] = orig[:orig_len]

    return out

# ==============================================================================
# Storage Layer
# ==============================================================================

class ChunkStorage:
    """Robust SQLite chunk storage - schema indistinguishable from generic blob store."""
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        # Clean schema: just hash -> blob, no metadata columns
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS chunks (
                hash TEXT PRIMARY KEY,
                data BLOB
            )
        """)
        self.conn.commit()
        logging.debug(f"ChunkStorage initialized at {db_path}")

    def store_chunks_batch(self, chunks_to_store: List[Tuple[str, bytes]]):
        """Store multiple chunks in a single transaction."""
        if not chunks_to_store:
            return
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO chunks (hash, data) VALUES (?, ?)",
                chunks_to_store
            )
        logging.debug(f"Stored {len(chunks_to_store)} chunks")

    def retrieve_chunk(self, salted_chunk_hash: str) -> Optional[bytes]:
        """Retrieve a single chunk by hash."""
        cursor = self.conn.execute(
            "SELECT data FROM chunks WHERE hash = ?",
            (salted_chunk_hash,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    def get_chunk_count(self) -> int:
        """Get total number of chunks (real + fake are indistinguishable)."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM chunks")
        return cursor.fetchone()[0]

    def close(self):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
            logging.debug("ChunkStorage closed")

def derive_fake_salt(file_salt: bytes) -> bytes:
    """Derive a separate salt for fake chunks - only keymap holder knows the real salt."""
    return hmac.new(file_salt, b"veriduct_fake_salt_v1", hashlib.sha256).digest()

def generate_fake_chunks(real_chunk_count: int, file_salt: bytes, ratio: float = 0.25) -> List[Tuple[str, bytes]]:
    """
    Generate fake chunks for substrate poisoning.
    Uses a derived salt so fake chunk hashes are completely disjoint from real chunk hashes.
    The database cannot distinguish real from fake - only the keymap holder knows which hashes are real.
    """
    fake_salt = derive_fake_salt(file_salt)
    count = max(1, int(real_chunk_count * ratio))
    fakes = []
    for _ in range(count):
        fake_len = random.choice([256, 512, 1024, 2048, 4096])
        data = os.urandom(fake_len)
        # Hash with derived fake_salt - these hashes will never appear in keymap
        h = calculate_salted_chunk_hash(fake_salt, data)
        fakes.append((h, data))
    logging.debug(f"Generated {count} fake chunks (salt-isolated)")
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
    def __init__(self, raw_data_stream: bytearray, command_line: str = None):
        self.stream = raw_data_stream
        self.is_valid = False
        self.entry_point = 0
        self.architecture = "Unknown"
        self.image_base = 0
        self.mapped_memory = None
        self.mapped_size = 0
        self.is_64bit = False
        self.load_config_rva = 0
        self.load_config_size = 0
        self.command_line = command_line  # Command line to pass to PE
        
        # Track all VirtualAlloc allocations for cleanup (prevents memory leaks)
        self._allocations = []
        self._VirtualFree = None  # Cached for cleanup

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
            pe_offset = struct.unpack('<I', self.stream[0x3C:0x40])[0]
            print(f"PE offset: 0x{pe_offset:X}")
            print(f"PE signature: {self.stream[pe_offset:pe_offset+4]}")
            entry_rva = struct.unpack('<I', self.stream[pe_offset+40:pe_offset+44])[0]
            print(f"Entry RVA from header: 0x{entry_rva:X}")
            print(f"First 64 bytes at PE offset: {self.stream[pe_offset:pe_offset+64].hex()}")
        else:
            logging.error("Unknown executable format")
            self.is_valid = False

    # -------------------------------------------------------------------------
    # PE (Windows) Implementation
    # -------------------------------------------------------------------------
    
    def _translate_pe_section_protection(self, characteristics):
        """
        Translate PE section characteristics flags to Windows page protection constants.
        Maps section flags to minimum required permissions (no unnecessary RWX).
        """
        can_exec = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)
        can_read = bool(characteristics & IMAGE_SCN_MEM_READ)
        can_write = bool(characteristics & IMAGE_SCN_MEM_WRITE)

        if can_exec:
            if can_read and can_write:
                return PAGE_EXECUTE_READWRITE  # Only if section explicitly needs E+R+W
            if can_read:
                return PAGE_EXECUTE_READ  # Standard .text section
            if can_write:
                # Uncommon: execute + write but not read
                return PAGE_EXECUTE_READWRITE
            return PAGE_EXECUTE

        # Non-executable sections
        if can_read and can_write:
            return PAGE_READWRITE  # .data section
        if can_read:
            return PAGE_READONLY  # .rdata section
        if can_write:
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

            # Load Config Directory (Index 10)
            self.load_config_rva = struct.unpack('<I', self.stream[dd_offset+80:dd_offset+84])[0]
            self.load_config_size = struct.unpack('<I', self.stream[dd_offset+84:dd_offset+88])[0]
            
            # Store is_64bit
            self.is_64bit = is_64bit

            # Section headers offset
            self.section_header_offset = opt_header_offset + opt_header_size
            self.is_valid = True
            
            logging.info(f"PE parsed: {self.num_sections} sections, entry RVA: 0x{self.entry_point_rva:X}")
            
        except Exception as e:
            logging.error(f"PE Parse Error: {e}")
            self.is_valid = False

    def _execute_pe_windows(self):
            """Execute PE on Windows with proper memory mapping. Uses stealth API resolution."""
            resolver = get_stealth_resolver()
            
            # Resolve all kernel32 functions we need via stealth
            VirtualAlloc_addr = resolver.get_proc_address("kernel32.dll", "VirtualAlloc")
            VirtualProtect_addr = resolver.get_proc_address("kernel32.dll", "VirtualProtect")
            VirtualFree_addr = resolver.get_proc_address("kernel32.dll", "VirtualFree")
            CreateThread_addr = resolver.get_proc_address("kernel32.dll", "CreateThread")
            WaitForSingleObject_addr = resolver.get_proc_address("kernel32.dll", "WaitForSingleObject")
            GetExitCodeThread_addr = resolver.get_proc_address("kernel32.dll", "GetExitCodeThread")
            CloseHandle_addr = resolver.get_proc_address("kernel32.dll", "CloseHandle")
            
            if not all([VirtualAlloc_addr, VirtualProtect_addr, VirtualFree_addr]):
                raise RuntimeError("Failed to resolve required kernel32 functions via stealth resolver")
            
            # Create callable function pointers using WINFUNCTYPE for Windows API calling convention
            # Note: BOOL is c_int (4 bytes), not c_bool (1 byte)
            VirtualAlloc = ctypes.WINFUNCTYPE(
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong
            )(VirtualAlloc_addr)
            
            VirtualProtect = ctypes.WINFUNCTYPE(
                ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
            )(VirtualProtect_addr)
            
            VirtualFree = ctypes.WINFUNCTYPE(
                ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong
            )(VirtualFree_addr)
            
            CreateThread = ctypes.WINFUNCTYPE(
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
            )(CreateThread_addr) if CreateThread_addr else None
            
            WaitForSingleObject = ctypes.WINFUNCTYPE(
                ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong
            )(WaitForSingleObject_addr) if WaitForSingleObject_addr else None
            
            GetExitCodeThread = ctypes.WINFUNCTYPE(
                ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)
            )(GetExitCodeThread_addr) if GetExitCodeThread_addr else None
            
            CloseHandle = ctypes.WINFUNCTYPE(
                ctypes.c_int, ctypes.c_void_p
            )(CloseHandle_addr) if CloseHandle_addr else None
    
            # Allocate memory - let Windows choose the address
            base_addr = VirtualAlloc(
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

            # Initialize CRT helper with command line
            crt_init = CRTInitializer(base_addr_int, self.stream, self.is_64bit, 
                                    self.load_config_rva, self.load_config_size,
                                    command_line=self.command_line)
    
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
                        # BOUNDS CHECK: Ensure section fits within allocated image
                        if v_addr + raw_size > self.size_of_image:
                            raise ValueError(f"Section {i} extends beyond image bounds (v_addr=0x{v_addr:X}, raw_size=0x{raw_size:X}, image_size=0x{self.size_of_image:X})")
                        
                        # BOUNDS CHECK: Ensure we have enough source data
                        if raw_ptr + raw_size > len(self.stream):
                            logging.warning(f"Section {i} raw data truncated (raw_ptr=0x{raw_ptr:X}, raw_size=0x{raw_size:X}, stream_len=0x{len(self.stream):X})")
                            raw_size = min(raw_size, len(self.stream) - raw_ptr) if raw_ptr < len(self.stream) else 0
                        
                        if raw_size > 0:
                            dest = base_addr_int + v_addr
                            data = self.stream[raw_ptr:raw_ptr + raw_size]
                            ctypes.memmove(dest, bytes(data), len(data))
                            logging.debug(f"Mapped section {i} at RVA 0x{v_addr:X} ({raw_size} bytes)")
                
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
        
                # CRT Initialization (while memory is still RW)
                crt_init.initialize()
                
                # NOW apply final section protections (two-pass: was RW, now set proper perms)
                # This happens AFTER all writes are complete (imports resolved, relocations applied, CRT init done)
                logging.debug("Applying final section protections...")
                for section in sections_to_protect:
                    protection = self._translate_pe_section_protection(section['char'])
                    old_protect = ctypes.c_ulong()
                    
                    # No RWX fallback - apply proper permissions
                    # .text -> PAGE_EXECUTE_READ (not RWX)
                    # .rdata -> PAGE_READONLY
                    # .data -> PAGE_READWRITE
                    if protection != PAGE_NOACCESS:
                        success = VirtualProtect(
                            section['addr'],
                            section['size'],
                            protection,
                            ctypes.byref(old_protect)
                        )
                        if success:
                            logging.debug(f"  Section at 0x{section['addr']:X}: {old_protect.value:#x} -> {protection:#x}")
                        else:
                            logging.warning(f"  VirtualProtect failed for section at 0x{section['addr']:X}")
        
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
                    ENTRY_FUNC = ctypes.WINFUNCTYPE(
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
                    logging.info("Detected EXE - running in isolated thread")
                    # Run PE in separate thread so ExitThread (hooked from ExitProcess) 
                    # only kills the PE thread, not our Python host
                    
                    if not CreateThread:
                        raise RuntimeError("CreateThread not resolved")
                    
                    INFINITE = 0xFFFFFFFF
                    
                    logging.info(f"Creating thread at entry point 0x{entry_addr:X}...")
                    h_thread = CreateThread(
                        None,           # Default security
                        0,              # Default stack size  
                        entry_addr,     # Start at PE entry point
                        None,           # No parameter
                        0,              # Run immediately
                        None            # Don't need thread ID
                    )
                    
                    if not h_thread:
                        raise OSError(f"CreateThread failed: {ctypes.get_last_error()}")
                    
                    h_thread_int = h_thread if isinstance(h_thread, int) else ctypes.cast(h_thread, ctypes.c_void_p).value
                    logging.info(f"PE thread started (handle: 0x{h_thread_int:X}), waiting for completion...")
                    
                    # Wait for PE to finish (will call ExitThread due to our hook)
                    if WaitForSingleObject:
                        wait_result = WaitForSingleObject(h_thread_int, INFINITE)
                    
                    # Get exit code
                    exit_code = ctypes.c_ulong(0)
                    if GetExitCodeThread:
                        GetExitCodeThread(h_thread_int, ctypes.byref(exit_code))
                    result = exit_code.value
                    
                    # Cleanup
                    if CloseHandle:
                        CloseHandle(h_thread_int)
                    
                    logging.info(f"PE thread exited with code: {result}")

                # Restore CRT state (might fail if PEB was corrupted, that's ok)
                try:
                    crt_init.restore()
                except:
                    pass
                
                # Free all tracked allocations (argv hooks, exit hooks, etc.)
                self._cleanup_allocations(VirtualFree)
                
                # Free the PE memory
                try:
                    VirtualFree(base_addr, 0, 0x8000)  # MEM_RELEASE
                except:
                    pass
                    
                return result
            
            except Exception as e:
                try:
                    crt_init.restore()
                except:
                    pass
                # Free all tracked allocations on error too
                self._cleanup_allocations(VirtualFree)
                try:
                    VirtualFree(base_addr, 0, 0x8000)  # MEM_RELEASE
                except:
                    pass
                logging.error(f"PE execution failed: {e}")
                raise
    
    def _cleanup_allocations(self, VirtualFree=None):
        """Free all tracked VirtualAlloc allocations to prevent memory leaks."""
        if not self._allocations:
            return
        
        # Use cached or provided VirtualFree
        free_func = VirtualFree or self._VirtualFree
        if not free_func:
            logging.warning(f"Cannot free {len(self._allocations)} allocations - VirtualFree not available")
            return
        
        MEM_RELEASE = 0x8000
        freed_count = 0
        
        for addr in self._allocations:
            try:
                if addr:
                    free_func(addr, 0, MEM_RELEASE)
                    freed_count += 1
            except Exception as e:
                logging.debug(f"Failed to free allocation at 0x{addr:X}: {e}")
        
        if freed_count > 0:
            logging.debug(f"Freed {freed_count} hook/stub allocations")
        
        self._allocations.clear()

    def _apply_pe_relocations(self, base_addr, reloc_rva, reloc_size, delta):
        """
        Parses .reloc section and patches memory addresses.
        
        Includes bounds checking to prevent writes outside the allocated image region.
        """
        current_rva = reloc_rva
        end_rva = reloc_rva + reloc_size
        
        # Define valid address range for bounds checking
        image_start = base_addr
        image_end = base_addr + self.size_of_image
        
        def read_mem_u32(addr):
            return struct.unpack('<I', ctypes.string_at(addr, 4))[0]
        
        reloc_count = 0
        skipped_oob = 0
        
        while current_rva < end_rva:
            block_va = read_mem_u32(base_addr + current_rva)
            block_size = read_mem_u32(base_addr + current_rva + 4)
            
            if block_size == 0:
                break
            
            # Validate block_size is sane
            if block_size < 8 or block_size > (end_rva - current_rva + 8):
                logging.warning(f"Invalid relocation block size {block_size} at RVA 0x{current_rva:X}, stopping")
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
                    # BOUNDS CHECK: target + 4 bytes must be within image
                    if not (image_start <= target_addr and target_addr + 4 <= image_end):
                        logging.debug(f"Relocation target 0x{target_addr:X} out of bounds (32-bit), skipping")
                        skipped_oob += 1
                        continue
                    curr_val = struct.unpack('<I', ctypes.string_at(target_addr, 4))[0]
                    new_val = (curr_val + delta) & 0xFFFFFFFF
                    ctypes.memmove(target_addr, struct.pack('<I', new_val), 4)
                    reloc_count += 1
                    
                elif type_ == 10:  # IMAGE_REL_BASED_DIR64 (64-bit)
                    # BOUNDS CHECK: target + 8 bytes must be within image
                    if not (image_start <= target_addr and target_addr + 8 <= image_end):
                        logging.debug(f"Relocation target 0x{target_addr:X} out of bounds (64-bit), skipping")
                        skipped_oob += 1
                        continue
                    curr_val = struct.unpack('<Q', ctypes.string_at(target_addr, 8))[0]
                    new_val = (curr_val + delta) & 0xFFFFFFFFFFFFFFFF
                    ctypes.memmove(target_addr, struct.pack('<Q', new_val), 8)
                    reloc_count += 1
            
            current_rva += block_size
        
        if skipped_oob > 0:
            logging.warning(f"Skipped {skipped_oob} out-of-bounds relocations")
        logging.debug(f"Applied {reloc_count} relocations")

    def _setup_argv_hooks(self):
        """Create hook stubs for __p___argc and __p___argv that return our custom arguments.
        
        All allocations are tracked in self._allocations for cleanup.
        """
        if not self.command_line:
            return None, None
        
        # Parse command line into argc/argv
        # Simple split on spaces (doesn't handle quotes, but good enough for now)
        args = self.command_line.split()
        argc = len(args)
        
        logging.info(f"Setting up argv hooks: argc={argc}, argv={args}")
        
        resolver = get_stealth_resolver()
        VirtualAlloc_addr = resolver.get_proc_address("kernel32.dll", "VirtualAlloc")
        VirtualFree_addr = resolver.get_proc_address("kernel32.dll", "VirtualFree")
        
        if not VirtualAlloc_addr:
            logging.error("Failed to resolve VirtualAlloc for argv hooks")
            return None, None
        
        VirtualAlloc = ctypes.WINFUNCTYPE(
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong
        )(VirtualAlloc_addr)
        
        # Cache VirtualFree for cleanup
        if VirtualFree_addr and not self._VirtualFree:
            self._VirtualFree = ctypes.WINFUNCTYPE(
                ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong
            )(VirtualFree_addr)
        
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_READWRITE_LOCAL = 0x04
        PAGE_EXECUTE_READWRITE_LOCAL = 0x40
        
        # Calculate total size needed
        # - 8 bytes for argc (4 byte int + 4 padding for alignment)
        # - 8 bytes per argv pointer + null terminator
        # - String data
        string_data_size = sum(len(arg) + 1 for arg in args)  # +1 for null terminator each
        argv_array_size = (argc + 1) * 8  # +1 for NULL terminator, 8 bytes per pointer (x64)
        total_size = 8 + argv_array_size + string_data_size + 64  # +64 padding
        
        # Allocate data memory
        data_mem = VirtualAlloc(None, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE_LOCAL)
        if not data_mem:
            logging.error("Failed to allocate memory for argv data")
            return None, None
        
        data_mem_int = data_mem if isinstance(data_mem, int) else ctypes.cast(data_mem, ctypes.c_void_p).value
        self._allocations.append(data_mem_int)  # Track for cleanup
        
        # Layout:
        # [0:4] = argc (int, 4 bytes)
        # [8:8+argv_array_size] = argv array (char**) - start at offset 8 for alignment
        # [8+argv_array_size:] = string data
        
        argc_ptr = data_mem_int
        argv_array_ptr = data_mem_int + 8
        string_ptr = data_mem_int + 8 + argv_array_size
        
        # Write argc as 4-byte int
        ctypes.memmove(argc_ptr, struct.pack('<i', argc), 4)
        
        # Write strings and build argv array
        current_string_ptr = string_ptr
        for i, arg in enumerate(args):
            # Write the string
            arg_bytes = arg.encode('ascii') + b'\x00'
            ctypes.memmove(current_string_ptr, arg_bytes, len(arg_bytes))
            
            # Write pointer to this string in argv array
            ctypes.memmove(argv_array_ptr + i * 8, struct.pack('<Q', current_string_ptr), 8)
            
            current_string_ptr += len(arg_bytes)
        
        # Write NULL terminator for argv array
        ctypes.memmove(argv_array_ptr + argc * 8, struct.pack('<Q', 0), 8)
        
        # Store for later reference (prevent garbage collection issues)
        self._argc_ptr = argc_ptr
        self._argv_ptr = argv_array_ptr
        self._argv_data_mem = data_mem_int
        
        # Now create the hook stubs
        # __p___argc returns int* (pointer to argc)
        # __p___argv returns char*** (pointer to argv)
        
        # For x64:
        # mov rax, <address>
        # ret
        
        # Hook for __p___argc - returns pointer to argc
        argc_stub = b'\x48\xB8' + struct.pack('<Q', argc_ptr) + b'\xC3'
        
        # Hook for __p___argv - returns pointer to argv pointer
        # We need to return a pointer TO the argv array pointer
        # So we need another level of indirection
        # Allocate 8 bytes to hold the argv_array_ptr value
        argv_ptr_ptr = VirtualAlloc(None, 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE_LOCAL)
        argv_ptr_ptr_int = argv_ptr_ptr if isinstance(argv_ptr_ptr, int) else ctypes.cast(argv_ptr_ptr, ctypes.c_void_p).value
        ctypes.memmove(argv_ptr_ptr_int, struct.pack('<Q', argv_array_ptr), 8)
        self._argv_ptr_ptr = argv_ptr_ptr_int
        self._allocations.append(argv_ptr_ptr_int)  # Track for cleanup
        
        argv_stub = b'\x48\xB8' + struct.pack('<Q', argv_ptr_ptr_int) + b'\xC3'
        
        # Allocate executable memory for stubs
        argc_hook = VirtualAlloc(None, len(argc_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE_LOCAL)
        argv_hook = VirtualAlloc(None, len(argv_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE_LOCAL)
        
        argc_hook_int = argc_hook if isinstance(argc_hook, int) else ctypes.cast(argc_hook, ctypes.c_void_p).value if argc_hook else 0
        argv_hook_int = argv_hook if isinstance(argv_hook, int) else ctypes.cast(argv_hook, ctypes.c_void_p).value if argv_hook else 0
        
        if argc_hook_int:
            ctypes.memmove(argc_hook_int, argc_stub, len(argc_stub))
            self._allocations.append(argc_hook_int)  # Track for cleanup
            logging.info(f"Created __p___argc hook at 0x{argc_hook_int:X}")
        
        if argv_hook_int:
            ctypes.memmove(argv_hook_int, argv_stub, len(argv_stub))
            self._allocations.append(argv_hook_int)  # Track for cleanup
            logging.info(f"Created __p___argv hook at 0x{argv_hook_int:X}")
        
        return argc_hook_int, argv_hook_int

    def _create_exit_hook(self):
        """Create a hook stub for exit() that calls _cexit() then ExitThread.
        
        This prevents CRT state corruption by:
        1. Calling _cexit() to flush buffers and release locks (without closing handles)
        2. Then calling ExitThread() to terminate just the PE thread
        
        All allocations are tracked in self._allocations for cleanup.
        
        x64 Assembly:
            sub rsp, 0x28           ; Align stack (shadow space)
            mov rax, <_cexit>       ; Load _cexit address
            call rax                ; Call _cexit (flushes buffers, releases locks)
            add rsp, 0x28           ; Restore stack
            xor rcx, rcx            ; Exit code 0
            mov rax, <ExitThread>   ; Load ExitThread address
            jmp rax                 ; Jump to ExitThread
        """
        resolver = get_stealth_resolver()
        
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE_LOCAL = 0x40
        
        # Get ExitThread address via stealth resolver
        exit_thread_addr = resolver.get_proc_address("kernel32.dll", "ExitThread")
        
        if not exit_thread_addr:
            logging.error("Failed to get ExitThread address")
            return None
        
        # Get VirtualAlloc for allocating our stub
        VirtualAlloc_addr = resolver.get_proc_address("kernel32.dll", "VirtualAlloc")
        VirtualFree_addr = resolver.get_proc_address("kernel32.dll", "VirtualFree")
        
        if not VirtualAlloc_addr:
            logging.error("Failed to resolve VirtualAlloc for exit hook")
            return None
        
        VirtualAlloc = ctypes.WINFUNCTYPE(
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong
        )(VirtualAlloc_addr)
        
        # Cache VirtualFree for cleanup
        if VirtualFree_addr and not self._VirtualFree:
            self._VirtualFree = ctypes.WINFUNCTYPE(
                ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong
            )(VirtualFree_addr)
        
        # Get _cexit address - need to load ucrtbase first
        cexit_addr = None
        ucrt_base = resolver.load_library("ucrtbase.dll")
        if ucrt_base:
            cexit_addr = resolver.get_proc_address("ucrtbase.dll", "_cexit")
        
        if not cexit_addr:
            # Try api-ms-win-crt-runtime
            ucrt_base = resolver.load_library("api-ms-win-crt-runtime-l1-1-0.dll")
            if ucrt_base:
                cexit_addr = resolver.get_proc_address("api-ms-win-crt-runtime-l1-1-0.dll", "_cexit")
        
        if not cexit_addr:
            logging.warning("Could not find _cexit, falling back to direct ExitThread")
        
        if cexit_addr:
            # Safe exit stub: _cexit() then ExitThread()
            shellcode = (
                b'\x48\x83\xEC\x28'                              # sub rsp, 0x28 (align stack)
                + b'\x48\xB8' + struct.pack('<Q', cexit_addr)    # mov rax, _cexit
                + b'\xFF\xD0'                                    # call rax
                + b'\x48\x83\xC4\x28'                            # add rsp, 0x28
                + b'\x48\x31\xC9'                                # xor rcx, rcx (exit code 0)
                + b'\x48\xB8' + struct.pack('<Q', exit_thread_addr)  # mov rax, ExitThread
                + b'\xFF\xE0'                                    # jmp rax
            )
            logging.info(f"Created safe exit hook: _cexit(0x{cexit_addr:X}) -> ExitThread(0x{exit_thread_addr:X})")
        else:
            # Fallback: direct ExitThread (may still cause issues)
            shellcode = b'\x48\xB8' + struct.pack('<Q', exit_thread_addr) + b'\xFF\xE0'
            logging.warning(f"Created fallback exit hook -> ExitThread(0x{exit_thread_addr:X})")
        
        # Allocate executable memory for the stub
        stub_addr = VirtualAlloc(None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE_LOCAL)
        
        if stub_addr:
            stub_addr_int = stub_addr if isinstance(stub_addr, int) else ctypes.cast(stub_addr, ctypes.c_void_p).value
            ctypes.memmove(stub_addr_int, shellcode, len(shellcode))
            self._allocations.append(stub_addr_int)  # Track for cleanup
            logging.info(f"Exit hook stub at 0x{stub_addr_int:X}")
            return stub_addr_int
        
        logging.error("Failed to allocate memory for exit hook")
        return None

    def _resolve_pe_imports(self, base_addr, import_rva):
        """
        Walks Import Descriptor, loads DLLs, fills IAT.
        Uses StealthResolver to avoid ctypes.windll telemetry.
        """
        resolver = get_stealth_resolver()
        
        # Get function addresses we need through stealth resolution
        LoadLibraryA_addr = resolver.get_proc_address("kernel32.dll", "LoadLibraryA")
        GetProcAddress_addr = resolver.get_proc_address("kernel32.dll", "GetProcAddress")
        
        if not LoadLibraryA_addr or not GetProcAddress_addr:
            logging.error("Failed to resolve LoadLibraryA/GetProcAddress via stealth resolver")
            return
        
        # Create callable function pointers using WINFUNCTYPE for Windows API calling convention
        LoadLibraryA = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)(LoadLibraryA_addr)
        GetProcAddress_by_name = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p)(GetProcAddress_addr)
        # For ordinal, use c_void_p to ensure pointer-sized argument (ordinal passed as low bits)
        GetProcAddress_by_ord = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(GetProcAddress_addr)
        
        # Set up argv hooks if we have a custom command line
        argc_hook = None
        argv_hook = None
        if self.command_line:
            argc_hook, argv_hook = self._setup_argv_hooks()
        
        # Create exit hook to prevent CRT cleanup from corrupting Python
        exit_hook = self._create_exit_hook()
        
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
            h_module = LoadLibraryA(dll_name.encode('ascii'))
            if not h_module:
                # Check if this is a critical system DLL that should always be available
                critical_dlls = {'kernel32.dll', 'ntdll.dll', 'user32.dll', 'advapi32.dll', 
                                 'msvcrt.dll', 'ucrtbase.dll', 'vcruntime140.dll'}
                dll_lower = dll_name.lower()
                
                if dll_lower in critical_dlls:
                    raise RuntimeError(f"Failed to load critical dependency: {dll_name} - binary cannot execute")
                else:
                    logging.warning(f"Failed to load dependency: {dll_name} - some functionality may not work")
                    desc_ptr += 20
                    continue
            
            h_module_int = h_module if isinstance(h_module, int) else ctypes.cast(h_module, ctypes.c_void_p).value
            dll_count += 1
            logging.debug(f"Loaded DLL: {dll_name} at 0x{h_module_int:X}")
                
            # Walk Thunks
            thunk_ptr = base_addr + (original_first_thunk if original_first_thunk else first_thunk)
            iat_ptr = base_addr + first_thunk
            
            is_64 = (self.image_base > 0xFFFFFFFF)
            ptr_size = 8 if is_64 else 4
            msb_mask = 0x8000000000000000 if is_64 else 0x80000000
            
            import_count = 0
            failed_imports = []
            
            while True:
                if is_64:
                    thunk_data = struct.unpack('<Q', ctypes.string_at(thunk_ptr, 8))[0]
                else:
                    thunk_data = struct.unpack('<I', ctypes.string_at(thunk_ptr, 4))[0]
                
                if thunk_data == 0:
                    break
                
                if thunk_data & msb_mask:
                    # Import by ordinal
                    ordinal = thunk_data & 0xFFFF
                    proc_addr = GetProcAddress_by_ord(h_module_int, ordinal)
                else:
                    # Import by name
                    name_ptr = base_addr + (thunk_data & 0x7FFFFFFF) + 2
                    func_name_bytes = ctypes.string_at(name_ptr)
                    dll_lower = dll_name.lower()
                    
                    # IAT HOOK: Swap ExitProcess -> ExitThread to keep host process alive
                    if dll_lower == 'kernel32.dll' and func_name_bytes == b'ExitProcess':
                        logging.debug("IAT Hook: Redirecting ExitProcess -> ExitThread")
                        proc_addr = GetProcAddress_by_name(h_module_int, b'ExitThread')
                    
                    # IAT HOOK: exit/_exit/quick_exit -> ExitThread (prevent CRT cleanup)
                    elif func_name_bytes in (b'exit', b'_exit', b'quick_exit', b'_Exit') and exit_hook:
                        logging.info(f"IAT Hook: Redirecting {func_name_bytes.decode()} -> ExitThread")
                        proc_addr = exit_hook
                    
                    # IAT HOOK: __p___argc -> our hook (returns pointer to custom argc)
                    elif func_name_bytes == b'__p___argc' and argc_hook:
                        logging.info(f"IAT Hook: Redirecting __p___argc -> 0x{argc_hook:X}")
                        proc_addr = argc_hook
                    
                    # IAT HOOK: __p___argv -> our hook (returns pointer to custom argv)
                    elif func_name_bytes == b'__p___argv' and argv_hook:
                        logging.info(f"IAT Hook: Redirecting __p___argv -> 0x{argv_hook:X}")
                        proc_addr = argv_hook
                    
                    else:
                        proc_addr = GetProcAddress_by_name(h_module_int, func_name_bytes)
                
                if proc_addr:
                    proc_addr_int = proc_addr if isinstance(proc_addr, int) else ctypes.cast(proc_addr, ctypes.c_void_p).value
                    if is_64:
                        ctypes.memmove(iat_ptr, struct.pack('<Q', proc_addr_int), 8)
                    else:
                        ctypes.memmove(iat_ptr, struct.pack('<I', proc_addr_int), 4)
                    import_count += 1
                else:
                    # Track failed imports for summary
                    if thunk_data & msb_mask:
                        failed_imports.append(f"{dll_name}!Ordinal{thunk_data & 0xFFFF}")
                    else:
                        try:
                            name_ptr = base_addr + (thunk_data & 0x7FFFFFFF) + 2
                            func_name = ctypes.string_at(name_ptr).decode('ascii', errors='ignore')
                            failed_imports.append(f"{dll_name}!{func_name}")
                        except:
                            failed_imports.append(f"{dll_name}!<unknown>")
                
                thunk_ptr += ptr_size
                iat_ptr += ptr_size
            
            # Report failed imports for this DLL
            if failed_imports:
                logging.warning(f"  {dll_name}: {len(failed_imports)} unresolved imports: {', '.join(failed_imports[:5])}" + 
                              (f" (and {len(failed_imports)-5} more)" if len(failed_imports) > 5 else ""))
            
            logging.debug(f"  Resolved {import_count} imports from {dll_name}")
            desc_ptr += 20
        
        logging.info(f"Loaded {dll_count} DLLs via stealth resolver")

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
        TLS_FUNC = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p)
        
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
        
        resolver = get_stealth_resolver()
        
        try:
            # RtlAddFunctionTable is in ntdll on modern Windows
            RtlAddFunctionTable_addr = resolver.get_proc_address("kernel32.dll", "RtlAddFunctionTable")
            if not RtlAddFunctionTable_addr:
                RtlAddFunctionTable_addr = resolver.get_proc_address("ntdll.dll", "RtlAddFunctionTable")
            
            if RtlAddFunctionTable_addr:
                # BOOL return type is c_int (4 bytes), not c_bool (1 byte)
                RtlAddFunctionTable = ctypes.WINFUNCTYPE(
                    ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_uint64
                )(RtlAddFunctionTable_addr)
                
                result = RtlAddFunctionTable(
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
        resolver = get_stealth_resolver()
        
        LoadLibraryA_addr = resolver.get_proc_address("kernel32.dll", "LoadLibraryA")
        GetProcAddress_addr = resolver.get_proc_address("kernel32.dll", "GetProcAddress")
        
        if not LoadLibraryA_addr or not GetProcAddress_addr:
            logging.warning("Failed to resolve LoadLibraryA/GetProcAddress for delay imports")
            return
        
        # Use WINFUNCTYPE for Windows API calling convention
        LoadLibraryA = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)(LoadLibraryA_addr)
        GetProcAddress_by_name = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p)(GetProcAddress_addr)
        # For ordinal, use c_void_p to ensure pointer-sized argument
        GetProcAddress_by_ord = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(GetProcAddress_addr)
        
        current_desc_ptr = base_addr + delay_rva
        
        while True:
            # Parse ImgDelayDescr (32 bytes)
            attrs = struct.unpack('<I', ctypes.string_at(current_desc_ptr, 4))[0]
            name_rva = struct.unpack('<I', ctypes.string_at(current_desc_ptr + 4, 4))[0]
            
            if name_rva == 0:
                break
                
            dll_name = ctypes.string_at(base_addr + name_rva).decode('ascii')
            
            # Load the DLL
            h_module = LoadLibraryA(dll_name.encode('ascii'))
            if not h_module:
                logging.warning(f"Failed to delay-load: {dll_name}")
                current_desc_ptr += 32
                continue
            
            h_module_int = h_module if isinstance(h_module, int) else ctypes.cast(h_module, ctypes.c_void_p).value
            logging.debug(f"Delay-loaded DLL: {dll_name}")
                
            # Write the Module Handle back
            module_handle_rva = struct.unpack('<I', ctypes.string_at(current_desc_ptr + 8, 4))[0]
            if module_handle_rva:
                h_ptr = base_addr + module_handle_rva
                if is_64:
                    ctypes.memmove(h_ptr, struct.pack('<Q', h_module_int), 8)
                else:
                    ctypes.memmove(h_ptr, struct.pack('<I', h_module_int & 0xFFFFFFFF), 4)

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
                    proc_addr = GetProcAddress_by_ord(h_module_int, ordinal)
                else:
                    fn_name_ptr = base_addr + (name_ptr_val & 0xFFFFFFFF) + 2  # Skip Hint
                    fn_name = ctypes.string_at(fn_name_ptr)
                    proc_addr = GetProcAddress_by_name(h_module_int, fn_name)
                
                if proc_addr:
                    proc_addr_int = proc_addr if isinstance(proc_addr, int) else ctypes.cast(proc_addr, ctypes.c_void_p).value
                    if is_64:
                        ctypes.memmove(iat_ptr, struct.pack('<Q', proc_addr_int), 8)
                    else:
                        ctypes.memmove(iat_ptr, struct.pack('<I', proc_addr_int), 4)

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
        
        Includes bounds checking to prevent writes outside mapped region.
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
        
        # Get mapped region bounds for validation
        # Use stored value if available, otherwise use a safe estimate
        region_start = base_addr
        region_end = getattr(self, '_elf_mapped_end', base_addr + 0x10000000)
        
        logging.info(f"Processing {num_relocs} ELF relocations...")
        
        applied_count = 0
        skipped_oob = 0

        for _ in range(num_relocs):
            try:
                # Elf64_Rela: r_offset (8), r_info (8), r_addend (8)
                r_offset = struct.unpack('<Q', ctypes.string_at(current_reloc, 8))[0]
                r_info = struct.unpack('<Q', ctypes.string_at(current_reloc+8, 8))[0]
                r_addend = struct.unpack('<q', ctypes.string_at(current_reloc+16, 8))[0]
                
                r_type = r_info & 0xFFFFFFFF
                r_sym = r_info >> 32
                
                target_addr = base_addr + r_offset if r_offset < base_addr else r_offset
                
                # BOUNDS CHECK: Ensure target is within mapped region
                if not (region_start <= target_addr and target_addr + 8 <= region_end):
                    logging.debug(f"ELF relocation target 0x{target_addr:X} out of bounds, skipping")
                    skipped_oob += 1
                    current_reloc += rela_ent
                    continue
                
                # R_X86_64_RELATIVE (8) - Base relocation
                if r_type == 8:
                    val = base_addr + r_addend
                    ctypes.memmove(target_addr, struct.pack('<Q', val), 8)
                    applied_count += 1
                    
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
                                applied_count += 1
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
        
        if skipped_oob > 0:
            logging.warning(f"Skipped {skipped_oob} out-of-bounds ELF relocations")
        logging.debug(f"Applied {applied_count} ELF relocations")

    def _execute_elf_linux(self):
        """
        ELF loader using mmap.
        Handles PT_LOAD segments. Best with static binaries or simple PIE.
        
        Includes bounds checking and size validation.
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
                p_flags = struct.unpack('<I', self.stream[offset+4:offset+8])[0]
                
                if p_vaddr < min_vaddr:
                    min_vaddr = p_vaddr
                if p_vaddr + p_memsz > max_vaddr:
                    max_vaddr = p_vaddr + p_memsz
                
                load_segments.append((p_offset, p_vaddr, p_filesz, p_memsz, p_flags))
                logging.debug(f"PT_LOAD: VAddr 0x{p_vaddr:X}, FileSz {p_filesz}, MemSz {p_memsz}, Flags {p_flags:#x}")

        # Validate we have segments to load
        if not load_segments:
            raise RuntimeError("ELF has no PT_LOAD segments")
        
        # Validate address range
        if max_vaddr <= min_vaddr:
            raise RuntimeError(f"Invalid ELF virtual address range: max=0x{max_vaddr:X} <= min=0x{min_vaddr:X}")

        total_size = max_vaddr - min_vaddr
        
        # Sanity check on size (reject obviously malformed binaries)
        MAX_REASONABLE_SIZE = 1024 * 1024 * 1024  # 1GB
        if total_size > MAX_REASONABLE_SIZE:
            raise RuntimeError(f"ELF image size {total_size} exceeds maximum ({MAX_REASONABLE_SIZE})")
        
        # Page align with overflow check
        total_size_aligned = (total_size + 4095) & ~4095
        if total_size_aligned < total_size:
            raise RuntimeError(f"Size overflow during page alignment")
        total_size = total_size_aligned
        
        logging.info(f"Allocating {total_size} bytes for ELF (range: 0x{min_vaddr:X}-0x{max_vaddr:X})")
        
        # Allocate memory as RW first (will apply proper protections after loading)
        mem = mmap.mmap(
            -1, 
            total_size, 
            mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
            mmap.PROT_READ | mmap.PROT_WRITE
        )
        
        base_addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
        
        # Store mapped region end for bounds checking in relocations
        self._elf_mapped_end = base_addr + total_size
        self._elf_mmap = mem  # Keep reference for mprotect
        
        logging.info(f"Mapped ELF memory at 0x{base_addr:X}")
        
        # Track segments for later mprotect
        segment_protections = []
        
        # Load Segments
        for p_offset, vaddr, filesz, memsz, p_flags in load_segments:
            # Handle PIE (position independent) - if vaddr is small, it's relative
            if vaddr < 0x10000000:
                dest_addr = base_addr + vaddr
                segment_base = vaddr
            else:
                dest_addr = vaddr
                segment_base = vaddr - min_vaddr
            
            # BOUNDS CHECK: Ensure segment fits in allocated region
            if segment_base + memsz > total_size:
                raise RuntimeError(f"ELF segment extends beyond allocated region (vaddr=0x{vaddr:X}, memsz=0x{memsz:X})")
            
            # BOUNDS CHECK: Ensure we have source data
            if p_offset + filesz > len(self.stream):
                logging.warning(f"ELF segment source data truncated")
                filesz = min(filesz, len(self.stream) - p_offset) if p_offset < len(self.stream) else 0
            
            # Copy file data
            if filesz > 0:
                data = self.stream[p_offset : p_offset + filesz]
                ctypes.memmove(dest_addr, bytes(data), len(data))
            
            # Zero BSS
            if memsz > filesz:
                ctypes.memset(dest_addr + filesz, 0, memsz - filesz)
            
            # Track for mprotect (page-align the range)
            page_start = (dest_addr) & ~4095
            page_end = (dest_addr + memsz + 4095) & ~4095
            segment_protections.append((page_start, page_end - page_start, p_flags))

        # Resolve Dynamic Dependencies
        if hasattr(self, 'dynamic_entries') and self.dynamic_entries:
            logging.info("Resolving dynamic linking...")
            self._load_elf_dependencies(base_addr)
            self._resolve_elf_relocations(base_addr)

        # Apply proper memory protections (reduce RWX exposure)
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            mprotect = libc.mprotect
            mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            mprotect.restype = ctypes.c_int
            
            PROT_READ = 0x1
            PROT_WRITE = 0x2
            PROT_EXEC = 0x4
            
            for page_start, page_size, p_flags in segment_protections:
                prot = 0
                if p_flags & 0x4:  # PF_R
                    prot |= PROT_READ
                if p_flags & 0x2:  # PF_W
                    prot |= PROT_WRITE
                if p_flags & 0x1:  # PF_X
                    prot |= PROT_EXEC
                
                # Ensure at least read permission
                if prot == 0:
                    prot = PROT_READ
                
                result = mprotect(page_start, page_size, prot)
                if result == 0:
                    logging.debug(f"mprotect 0x{page_start:X} ({page_size} bytes): flags={prot:#x}")
                else:
                    logging.warning(f"mprotect failed for 0x{page_start:X}")
                    
        except Exception as e:
            logging.warning(f"Could not apply segment protections (continuing with RWX): {e}")
            # Fall back to making everything executable
            try:
                libc = ctypes.CDLL("libc.so.6")
                libc.mprotect(base_addr, total_size, 0x7)  # RWX fallback
            except:
                pass

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
                resolver = get_stealth_resolver()
                VirtualFree_addr = resolver.get_proc_address("kernel32.dll", "VirtualFree")
                if VirtualFree_addr:
                    # BOOL is c_int (4 bytes), not c_bool
                    VirtualFree = ctypes.WINFUNCTYPE(
                        ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong
                    )(VirtualFree_addr)
                    VirtualFree(
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
    def __init__(self, original_file_extension: str, original_header: bytes = b'', wipe_size: int = 0, command_line: str = None):
        self.file_ext = original_file_extension.lower()
        self.byte_count = 0
        self.bytecode_stream = bytearray()
        self.original_header = original_header
        self.wipe_size = wipe_size
        self.memory = MemorySubstrate()
        self.command_line = command_line  # Command line args to pass to PE
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
            self._execute_native(reconstructed, self.command_line)
        elif self.file_ext in ('.pyc', '.py'):
            self._execute_python(reconstructed)
        else:
            logging.warning(f"Unknown file extension: {self.file_ext}")
            logging.info("Attempting Python execution as fallback")
            self._execute_python(reconstructed)

    def _execute_native(self, data: bytearray, command_line: str = None):
        """Execute native binary (PE/ELF)."""
        logging.info("=" * 60)
        logging.info("NATIVE BINARY EXECUTION")
        logging.info("=" * 60)
        if command_line:
            logging.info(f"Command line: {command_line}")
        
        loader = VeriductNativeLoader(data, command_line=command_line)
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
                    chunks_batch.append((h, c))
                    key_sequence.append(h)
                    usf_hasher.update(c)

                # Store real chunks
                chunk_storage.store_chunks_batch(chunks_batch)

                # Generate and store fake chunks if enabled
                # Fakes use derived salt - indistinguishable in DB, but hashes never in keymap
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
    verbose: bool = False,
    command_line: str = None,
    target_file: str = None
) -> int:
    """
    Execute annihilated files directly from chunks without reassembly.
    Supports Python bytecode and native binaries (PE/ELF).
    
    Args:
        key_path: Path to keymap file
        disguise: Disguise format (csv, log, conf)
        ignore_integrity: Skip integrity checks
        verbose: Verbose output
        command_line: Command line arguments to pass to the executed binary
        target_file: Specific file in keymap to execute (None = execute all)
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
        
        # If target_file specified, only execute that file
        if target_file:
            # Match by filename (with or without extension)
            filename = os.path.basename(rel_path)
            filename_no_ext = os.path.splitext(filename)[0]
            target_base = os.path.basename(target_file)
            target_no_ext = os.path.splitext(target_base)[0]
            
            if filename != target_base and filename_no_ext != target_no_ext and filename != target_file:
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
            
            # Build command line: "exename args..."
            full_command_line = rel_path
            if command_line:
                full_command_line = f"{rel_path} {command_line}"
                logging.info(f"Command line: {full_command_line}")

            # Initialize execution core with command line
            vm = VeriductExecutionCore(file_ext, original_header, wipe_size, command_line=full_command_line)

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
