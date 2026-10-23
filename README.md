# 🔍 ThreatLens

> **Static File Security Analyser**  
> A beginner-friendly cybersecurity dashboard built with Streamlit that inspects files using static analysis — no files are ever executed.

---

## What Does ThreatLens Do?

ThreatLens examines the raw bytes of any uploaded file and surfaces threat indicators across four analysis layers:

| Analysis Layer | What It Checks |
|---|---|
| **SHA-256 Hashing** | Generates a unique cryptographic fingerprint for every file |
| **Magic Byte Detection** | Reads the file header to identify the true file type (16 signatures) |
| **Extension Mismatch** | Flags files whose extension contradicts their detected header (common malware disguise) |
| **Entropy Analysis** | Calculates Shannon entropy — very high values suggest encryption or packing |
| **Suspicious String Scan** | Searches for patterns linked to malicious behaviour (PowerShell, downloaders, registry edits, etc.) |
| **TICE Risk Scoring** | Correlates all indicators into a transparent 0–100 risk score with a four-level classification |

---

## Threat Indicator Correlation Engine (TICE)

TICE combines multiple static signals into a single score using a weighted rule set:

| Rule | Points |
|---|---|
| File-Signature Mismatch | 40 |
| Known-Hash Match | 35 |
| Suspicious Double Extension (e.g. `invoice.pdf.exe`) | 25 |
| Multiple Suspicious Patterns (≥ 3) | 20 |
| Dangerous File Extension (`.exe`, `.ps1`, `.bat`, …) | 15 |
| Very High Entropy (> 7.2 bits/byte) | 15 |
| Suspicious Pattern Detected (1–2) | 10 |
| Elevated Entropy (6.5–7.2 bits/byte) | 8 |

**Classification thresholds:**

| Score | Classification |
|---|---|
| 0 – 19 | ✅ Low |
| 20 – 49 | ⚠️ Medium |
| 50 – 74 | 🚨 High |
| 75 – 100 | 🔴 Critical |

---

## Project Structure

```
threatlens/
    app.py              Main application (Streamlit dashboard + analysis engine)
    requirements.txt    Python dependencies
    README.md           This file
    evidence_tool/      Companion SHA-256 file integrity verification tool
        app.py
        hash_utils.py
        generate_report.py
        test_app.py
        requirements.txt
        README.md
```

---

## Requirements

- **Python 3.8 or newer** — https://www.python.org/downloads/
- **pip** (bundled with Python)

---

## Installation

### Step 1 — Clone or download the project

```bash
git clone https://github.com/YOUR_USERNAME/threatlens.git
cd threatlens
```

Or download the ZIP from GitHub and extract it.

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Run the app

```bash
streamlit run app.py
```

Your browser will open automatically at `http://localhost:8501`.  
If it doesn't, open your browser and navigate to that address manually.

---

## Features

### 📂 File Upload & Analysis
- Accepts any file type up to 200 MB
- Files are analysed in memory and **never saved to disk**
- Results displayed instantly with a colour-coded risk badge

### 📊 Entropy Meter
Visual progress bar mapped to Shannon entropy (0–8 bits/byte):

| Range | Interpretation |
|---|---|
| < 5.0 | 🟢 Normal — likely plain text or source code |
| 5.0 – 6.5 | 🟡 Elevated — possible compression |
| 6.5 – 7.2 | 🟠 High — compression or encoding |
| > 7.2 | 🔴 Very High — likely encrypted or packed |

### 🛡 TICE Dashboard
- Live counters: Files Analysed / Require Review / High-Risk / Critical
- Findings table with short SHA-256, triggered rules, score, and recommended next step
- Expandable detail view per file with full rule breakdown
- Downloadable plain-text investigation report

### 🧬 Test Case Generator
Seven pre-built simulated payloads exercise every detection rule without uploading real files. Simulated results are clearly marked 🔬 throughout the UI.

### 🧪 Sample Data Lab
Ten fictional byte payloads demonstrate the full range of detection scenarios — from a clean `readme.txt` to a `dropper.exe` with PE magic, suspicious strings, and a known-hash match.

### 📥 Report Download
- **Security Report** — covers all uploaded files scanned in the current session
- **TICE Report** — covers all TICE findings (real + simulated) with the full scoring reference

---

## Detected File Types (Magic Bytes)

Windows PE/EXE · ELF Executable · ZIP / Office Document · PDF · JPEG · PNG · GIF · RIFF (AVI/WAV) · MP4/MOV · MS Office (legacy) · GZIP · BZIP2 · XZ · 7-Zip · RAR

---

## Suspicious Pattern Detection

The string scanner flags these categories inside any file's raw bytes:

- `cmd.exe` / PowerShell invocation
- WScript / CScript engine
- Base64-encoded payload hint
- Network download (`URLDownloadToFile`, `WebClient`, `wget`, `curl`)
- Registry modification (`RegOpenKey`, `reg add`)
- Shell execution (`ShellExecute`, `CreateProcess`)
- Scheduled task creation (`schtasks`)
- Credential / password keyword
- Self-deletion pattern (`del %0`)

---

## Privacy & Security

- All processing runs locally on your machine
- Files are read as bytes in memory — never written to disk, never executed
- No network requests are made during analysis
- No database, no login, no external services

---

## Technologies

| Technology | Purpose |
|---|---|
| Python 3 | Programming language |
| Streamlit ≥ 1.35 | Web dashboard |
| hashlib | SHA-256 hashing |
| math | Shannon entropy calculation |
| pathlib | Cross-platform file path handling |

---

## Disclaimer

ThreatLens is a **heuristic tool** designed for learning and triage. Risk scores flag indicators for human review — they do not constitute proof of malicious intent. Always confirm findings with dedicated malware analysis platforms before taking action.
