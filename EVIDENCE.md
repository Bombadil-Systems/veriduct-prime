# Veriduct Evidence

**Document Purpose:** Consolidated evidence demonstrating static detection bypass across multiple AV/EDR engines.

**Researcher:** Chris Aziz, Bombadil Systems LLC  
**Date:** January 11, 2026  
**Repository:** https://github.com/Bombadil-Systems/veriduct-prime

---

## Summary

Veriduct's format destruction technique bypasses static/signature-based detection across all tested security engines. Original malware samples with high detection rates become completely undetectable when processed, then return to original detection rates when reassembled (proving byte-perfect reconstruction).

**Pattern:** `Detected → Processed → Undetected → Reassembled → Detected (hash match)`

---

## Test Results

### 1. EICAR Test File

| State | Hash (SHA256) | Detections | VT Link |
|-------|---------------|------------|---------|
| Original | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | **65/68** | [Link](https://www.virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f) |
| Processed (chunks) | `4cca0ea4e23fed38e811cc6b05489a3d021f7c13c5e62f7fbf9017600556bb23` | **0/62** | [Link](https://www.virustotal.com/gui/file/4cca0ea4e23fed38e811cc6b05489a3d021f7c13c5e62f7fbf9017600556bb23) |

**Bypass Rate:** 65 → 0 (100% of detecting engines bypassed)

---

### 2. Cobalt Strike Beacon

| State | Hash (SHA256) | Detections | VT Link |
|-------|---------------|------------|---------|
| Original | `9482ba3e12b789f3228d180ec9eeb477fae73f6a1ec2bdbdcb0b0f2a907cb045` | **53/68** | [Link](https://www.virustotal.com/gui/file/9482ba3e12b789f3228d180ec9eeb477fae73f6a1ec2bdbdcb0b0f2a907cb045) |
| Processed (chunks) | `7cf0f6ec3415af81d6fd7c7666234ab308dc0de055d6df904555095c1a23fbbb` | **0/62** | [Link](https://www.virustotal.com/gui/file/7cf0f6ec3415af81d6fd7c7666234ab308dc0de055d6df904555095c1a23fbbb) |

**Bypass Rate:** 53 → 0 (100% of detecting engines bypassed)

---

### 3. Emotet/Bobik Trojan

| State | Hash (SHA256) | Detections | VT Link |
|-------|---------------|------------|---------|
| Original | `9165bc75e1a727c886b97c5dd3bdc42ed33d22f2895e8a830b94bd27fdeec2eb` | **31/72** | [Link](https://www.virustotal.com/gui/file/9165bc75e1a727c886b97c5dd3bdc42ed33d22f2895e8a830b94bd27fdeec2eb) |
| Processed (chunks) | `eb4125879e4a4b0a3ed7f89fdf37a951762095fd27fa67a8420145296e989b70` | **0/62** | [Link](https://www.virustotal.com/gui/file/eb4125879e4a4b0a3ed7f89fdf37a951762095fd27fa67a8420145296e989b70) |

**Bypass Rate:** 31 → 0 (100% of detecting engines bypassed)

---

### 4. ValleyRAT/Farfli Backdoor

| State | Hash (SHA256) | Detections | VT Link |
|-------|---------------|------------|---------|
| Original | `d1461dea7e2ad3a3dc4366772bcdebba5185a18d6f793d0e4a27dd3d78f2f2ab` | **52/72** | [Link](https://www.virustotal.com/gui/file/d1461dea7e2ad3a3dc4366772bcdebba5185a18d6f793d0e4a27dd3d78f2f2ab) |
| Processed (chunks) | `98722b2da46437dead85c268ad5e526ccd891f24fea2f891fda995076e2fa1c2` | **0/62** | [Link](https://www.virustotal.com/gui/file/98722b2da46437dead85c268ad5e526ccd891f24fea2f891fda995076e2fa1c2) |

**Bypass Rate:** 52 → 0 (100% of detecting engines bypassed)

---

## Engines Bypassed

The following engines detected original samples but failed to detect processed chunks:

| Engine | EICAR | Cobalt Strike | Emotet | ValleyRAT |
|--------|:-----:|:-------------:|:------:|:---------:|
| Microsoft | ✓ | ✓ | ✓ | ✓ |
| Kaspersky | ✓ | ✓ | ✓ | ✓ |
| Avast/AVG | ✓ | ✓ | ✓ | ✓ |
| BitDefender | ✓ | ✓ | ✗ | ✓ |
| ESET-NOD32 | ✓ | ✓ | ✗ | ✓ |
| Sophos | ✓ | ✓ | ✗ | ✓ |
| Symantec | ✓ | ✓ | ✓ | ✓ |
| Malwarebytes | ✓ | ✓ | ✗ | ✓ |
| TrendMicro | ✓ | ✓ | ✗ | ✗ |
| CrowdStrike Falcon | ✗ | ✓ | ✓ | ✓ |
| McAfee/Trellix | ✗ | ✓ | ✓ | ✓ |
| Fortinet | ✓ | ✓ | ✓ | ✓ |
| DrWeb | ✓ | ✓ | ✗ | ✓ |
| ClamAV | ✓ | ✓ | ✗ | ✓ |
| Panda | ✓ | ✓ | ✓ | ✓ |
| K7 | ✓ | ✓ | ✗ | ✓ |
| Rising | ✓ | ✓ | ✓ | ✓ |
| Cynet | ✓ | ✓ | ✗ | ✓ |
| SentinelOne | ✓ | ✓ | ✓ | ✓ |
| Elastic | ✗ | ✓ | ✓ | ✓ |
| DeepInstinct | ✗ | ✓ | ✓ | ✓ |

✓ = Engine detected original, missed processed chunks (BYPASSED)  
✗ = Engine did not detect original sample

---

## Real Product Testing: Microsoft Defender

In addition to VirusTotal results, testing was performed against actual Microsoft Defender installations:

**Test Environment 1:**
- Windows 11 Version 24H2 (OS Build 26100.7171)
- Security Intelligence Version: 1.441.435.0
- Real-time Protection: Enabled
- Test Date: November 23, 2025

**Test Environment 2:**
- Windows 10 Version 22H2 (OS Build 19045.3803)
- Security Intelligence Version: 1.441.411.0
- Real-time Protection: Enabled
- Test Date: November 22, 2025

**Results (ANY.RUN sandbox confirmation):**
- Original eicar.com: **Detected** - "Suspicious activity"
- Processed veriduct_chunks.db: **No threats detected**
- Reassembled eicar.com: **Detected** - "Suspicious activity"
- SHA256 hash: Identical before and after (275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F)

---

## Methodology

1. Obtain known-malicious sample with high VT detection rate
2. Process through Veriduct: `python veriduct.py annihilate sample.exe output/`
3. Upload processed chunks to VirusTotal
4. Record detection count (consistently 0)
5. Reassemble: `python veriduct.py reassemble output/veriduct_key.zst restored/`
6. Verify SHA256 hash matches original
7. Upload reassembled file to VirusTotal
8. Confirm detection rate returns to original level

---

## References

- GitHub Repository: https://github.com/Bombadil-Systems/veriduct-prime
- VirusTotal Results: Links provided in tables above

---

## Contact

Chris Aziz  
Bombadil Systems LLC  
research@bombadil.systems  
https://bombadil.systems
