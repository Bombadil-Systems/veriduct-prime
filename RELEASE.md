# Veriduct Prime v2.4 — Release Notes

**January 2026**

---

## What's New

### StealthResolver & Native API Handling

Import resolution now uses hash-based lookup instead of string references. No API names appear in memory during execution.

```python
# Before: String-based (detectable)
GetProcAddress(kernel32, "CreateFileW")

# Now: Hash-based (no strings)
resolve_by_hash("kernel32.dll", 0x7c0017a5)
```

### WINFUNCTYPE Integration

Windows API calls now use proper `ctypes.WINFUNCTYPE` declarations with correct calling conventions and type marshaling. This fixes edge cases where cdecl/stdcall mismatches caused crashes or silent corruption.

### Test Suite: 100% Pass Rate (Windows)

All Windows PE tests now pass:

| Test | Status |
|------|--------|
| StealthResolver | ✅ |
| WINFUNCTYPE | ✅ |
| PE Execution | ✅ |
| Multithreaded | ✅ |
| Network | ✅ |
| Crypto | ✅ |
| File I/O | ✅ |

### VDB Deprecation (GUI)

The VDB (Veriduct Database) storage format is being phased out. The GUI no longer exposes VDB options. SQLite chunk storage remains the default and recommended approach.

---

## Technical Changes

- **Import resolution**: Hash-based lookup via StealthResolver
- **API calling**: WINFUNCTYPE with explicit prototypes
- **Error handling**: Improved diagnostics for loader failures
- **Code cleanup**: Removed experimental VDB paths from GUI

---

## Upgrade Notes

If upgrading from v2.1-v2.3:
- No keymap format changes — existing keymaps work
- No chunk database changes — existing chunks work
- VDB users: migrate to SQLite chunk storage

---

## What's Next

- Continued ELF loader improvements
- Additional hash coverage for Windows APIs
- Performance optimizations for large binaries

---

## Links

- Repository: [github.com/bombadil-systems/veriduct-prime](https://github.com/bombadil-systems/veriduct-prime)
- Documentation: See README.md and docs/

---

*Veriduct Prime is developed by Chris @ Bombadil Systems LLC*
