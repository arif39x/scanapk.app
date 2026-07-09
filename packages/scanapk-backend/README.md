<p align="center">
  <img src="asset/logo.png" alt="ScanAPK Logo" width="200">
</p>

<h1 align="center">ScanAPK</h1>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/python-3.12%2B-blue" alt="Python 3.12+"></a>
  <a href="#"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/static%20analysis-androguard-purple" alt="Androguard"></a>
  <a href="#"><img src="https://img.shields.io/badge/dynamic-Frida-cyan" alt="Frida"></a>
  <a href="#"><img src="https://img.shields.io/badge/MITM-proxy-orange" alt="MITMproxy"></a>
  <a href="#"><img src="https://img.shields.io/badge/AI%20reasoning-OpenRouter-red" alt="OpenRouter AI"></a>
  <a href="#"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey" alt="Platform"></a>
</p>

**ScanAPK** is an advanced Android malware analysis tool combining static scanning, dynamic monitoring, code similarity, and optional AI reasoning to produce comprehensive security assessments of APK/AAB files.

---

## Features

### Static Analysis

| Module | Description |
|---|---|
| **DEX Scanning** (`core/dex_scan.py`) | Extracts URLs, IPs, suspicious method calls, native library references, broadcast receivers from DEX bytecode |
| **Manifest Analysis** (`core/scan_apk.py`) | Parses `AndroidManifest.xml` for permissions, components, intents, debuggable/backup flags |
| **Permission Scoring** | 45+ dangerous permissions mapped to weight tiers (CRITICAL/HIGH/MEDIUM/LOW) |
| **YARA Rules** (`core/yara_scan.py`) | 26 Android-specific rules across 7 malware categories — scans DEX, manifest, and native libraries |
| **Signature Verification** (`core/signature_verify.py`) | Extracts X.509 certificates via androguard, validates issuer/subject/expiry, matches against 14 known signers |
| **Obfuscation Heuristics** (`core/obfuscation_heuristics.py`) | 5 heuristics — reflection ratio, string encryption weight, dynamic loading callers, DEX entropy, dead code ratio |
| **Code Similarity** (`core/code_similarity.py`) | imphash, ssdeep-style fuzzy hash, TLSH-style locality-sensitive hash for comparing APKs |
| **Hash Database** (`core/hash_db.py`) | SQLite-backed store for known-malware hashes with similarity matching and import/export |
| **Call Graph Analysis** (`core/call_graph.py`) | Builds call graph from DEX, detects dead code and suspicious call chains |
| **Tracker Detection** (`core/tools/trackers.py`) | Identifies known advertising/analytics trackers by package name against 1000+ tracker signatures |
| **AAB / Split-APK** (`core/bundle_utils.py`, `core/merge_apks.py`) | Extracts `.aab` bundles (with bundletool or direct ZIP fallback); merges split APKs for unified analysis |

### Dynamic Monitoring

| Tool | Role |
|---|---|
| **Frida** | 14 hook scripts covering Crypto, SMS, File I/O, Location, Network, Data Theft, WebView, Dynamic Loading, Device Admin, Anti-Emulator, Accessibility, Notifications, Delayed Execution |
| **MITMproxy** | Intercepts and logs HTTP/HTTPS traffic with DNS/TLS/beaconing analysis |
| **Logcat** | Real-time filtering for suspicious system events (SMS, Crypto, Device Admin, etc.) |
| **Evasion Detection** | Identifies delayed execution, dropper/two-stage loading, payload download patterns |
| **PCAP Analysis** (`core/pcap_analysis.py`) | Post-session analysis — DNS queries, TLS handshakes, connection tracking, data volume, beaconing detection, non-HTTP protocol detection |

### AI Reasoning (Optional)

- Processes collected evidence into a structured **Knowledge Graph** with typed triples (APP/RISK/FINDING/PERM/API/URL/IP/EXFIL/FRIDA/TECH)
- LLM agent (via OpenRouter) reasons about combined threats across static + dynamic domains
- Classifies malware family, identifies IOCs, provides actionable recommendations
- Can be skipped with `--no-ai`

### Risk Scoring

Deterministic multi-factor scoring engine (`core/scoring.py`):

| Factor | Max Points |
|---|---|
| Permissions | 25 |
| Suspicious APIs | 15 |
| URLs/IPs | 10 |
| PCAP findings | 20 |
| YARA matches | 35 |
| Signature issues | 30 |
| Obfuscation heuristics | 25 |

**Verdicts:** `SAFE` (0–20), `SUSPICIOUS` (21–50), `MALICIOUS` (51–80), `CRITICAL` (81–100)

---

## Installation

### Prerequisites

- Python 3.12+
- Android Emulator (for dynamic analysis)
- Frida-server (pushed automatically)
- OpenRouter API key (for AI reasoning)

### Setup

```bash
git clone https://github.com/arif39x/scanapk
cd scanapk
pip install -r requirements.txt
```

Create `.env` for AI features:

```env
OPENROUTER_API_KEY=your_api_key_here
OPENROUTER_API_KEY_BACKUP1=your_backup_key_1
OPENROUTER_API_KEY_BACKUP2=your_backup_key_2
```

### Optional Dependencies

- **yara-python** — enables YARA rule scanning (26 Android malware rules included)
- **bundletool.jar** — full AAB-to-APK conversion (tool falls back to direct ZIP extraction if absent)
- **scapy** — enables PCAP network traffic analysis in dynamic sessions

---

## Usage

### Quick Static Scan

```bash
python main.py path/to/app.apk
```

### Options

| Flag | Description |
|---|---|
| `--static` | Static analysis only — skip emulator and dynamic monitoring |
| `--observe <seconds>` | Duration for dynamic monitoring (default: 60) |
| `--no-ai` | Skip LLM reasoning phase, produce deterministic report only |
| `--import-hashes <file>` | Import known-malware hashes from JSON |
| `--export-hashes <file>` | Export known-hash database to JSON |

### AAB / Split-APK

```bash
# Single AAB
python main.py path/to/app.aab

# Split APKs (merge into single analysis)
python main.py base.apk config.arm64_v8a.apk config.en.apk

# Glob all splits
python main.py path/to/split-*.apk
```

### Workflow

1. **Static scan** — DEX analysis, YARA, signature check, obfuscation heuristics, code similarity
2. **Deployment** — Install on emulator (Android 11 / API 30), auto-grant permissions via ADB
3. **Observation** — App launched with monkey events; Frida, MITMproxy, Logcat capture behavior
4. **Scoring** — Deterministic risk score calculated from all evidence
5. **AI Analysis** — (optional) LLM agent processes knowledge graph, classifies malware, extracts IOCs
6. **Report** — JSON report saved with verdict, evidence, and recommendations

---

## Running Tests

```bash
# Quick — no sample APKs required
python -m pytest tests/ -m "not slow"

# Full suite (includes integration tests with sample APKs)
python -m pytest tests/

# With coverage
python -m pytest tests/ --cov=core --cov=report --cov-report=term-missing
```

---

## Project Structure

```
scanapk/
├── asset/logo.png
├── core/
│   ├── scan_apk.py           # Orchestrator — manifest, DEX, signature, YARA, hashing
│   ├── dex_scan.py           # DEX bytecode pattern extraction
│   ├── scoring.py            # Multi-factor deterministic risk engine
│   ├── yara_scan.py          # YARA rule compilation and matching
│   ├── signature_verify.py   # APK certificate extraction and validation
│   ├── obfuscation_heuristics.py  # Anti-analysis / packing detection
│   ├── call_graph.py         # DEX call graph construction and dead code analysis
│   ├── code_similarity.py    # imphash, ssdeep, TLSH fingerprinting
│   ├── hash_db.py            # SQLite known-malware hash database
│   ├── bundle_utils.py       # AAB extraction and conversion
│   ├── merge_apks.py         # Split APK merging
│   ├── pcap_analysis.py      # PCAP network traffic analysis
│   ├── native_analysis.py    # Native library (ELF) analysis
│   ├── knowledge_graph.py    # Evidence triple builder
│   ├── agent.py              # LLM agent with tool-calling
│   ├── ai_analysis.py        # Direct AI assessment
│   ├── models.py             # LLM model configuration
│   ├── apkdeploy.py          # Emulator deployment + monkey
│   └── tools/                # Agent toolbelt
│       ├── permissions.py    ─── strings.py
│       ├── network.py        ─── manifest.py
│       ├── native.py         ─── apis.py
│       └── trackers.py
├── monitor/
│   ├── __init__.py           # Orchestrator + technique detection
│   ├── frida_monitor.py
│   ├── logcat_monitor.py
│   ├── mitm_monitor.py
│   └── frida_hooks/          # 14 Frida hook scripts
├── report/
│   ├── __init__.py
│   └── generator.py          # JSON report builder
├── data/
│   ├── yara/android_malware.yar   # 26 YARA rules
│   ├── known_signers.json         # 14 known developer certificates
│   └── trackers.json              # 1000+ ad/analytics tracker signatures
├── tests/
│   ├── conftest.py           # Shared fixtures
│   ├── test_scoring.py       # 56 scoring unit tests
│   ├── test_dex_scan.py      # 13 DEX/regex tests
│   ├── test_permissions.py   # 17 permission weight tests
│   ├── test_knowledge_graph.py # 16 knowledge graph tests
│   ├── test_report.py        # 12 report structure tests
│   └── test_integration.py   # 11 pipeline integration tests
├── main.py                   # CLI entry point
├── requirements.txt
├── pyproject.toml
└── .env                      # API keys (gitignored)
```

---

## Sample Output

```json
{
  "app": {
    "package": "com.malicious.app",
    "version": "1.0",
    "min_sdk": 23,
    "target_sdk": 30
  },
  "assessment": {
    "risk_score": 85,
    "severity": "CRITICAL",
    "verdict": "DO_NOT_INSTALL",
    "confidence": "HIGH"
  },
  "evidence": {
    "permissions": ["READ_SMS", "RECEIVE_SMS", "BIND_ACCESSIBILITY_SERVICE"],
    "suspicious_apis": ["sendTextMessage", "getDeviceId"],
    "urls": ["https://malicious-c2.example.com/collect"],
    "yara_matches": ["Android_Spyware_SmsStealer"],
    "signature_flags": ["self_signed", "expired"],
    "obfuscation_flags": ["high_dead_code_ratio", "high_entropy"]
  },
  "ai_assessment": {
    "malware_family": "Spyware/SmsStealer",
    "key_findings": ["App requests BIND_ACCESSIBILITY_SERVICE without clear utility."],
    "recommendations": ["Do not install this application."],
    "iocs": {
      "urls": ["https://malicious-c2.example.com/collect"],
      "ips": ["192.168.1.100"]
    }
  }
}
```

---

<p align="center"><i>By Dev For Dev</i></p>
