#!/usr/bin/env python3
"""
Hybrid Analysis → Multi-rule pipeline v6
- Batches samples by family for better rule generation
- Filters out generic Windows/system strings
- Uses more realistic YARA conditions
- Proper Ctrl+C handling

Key improvements:
- Groups samples by family first
- Extracts common strings across family samples
- Filters unique/sample-specific paths
- More realistic matching conditions
"""
import os
import io
import json
import re
import signal
import sys
import time
import threading
import zipfile
import subprocess
from collections import defaultdict, Counter
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
import requests
import yaml
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SHUTDOWN_REQUESTED = False

def signal_handler(sig, frame):
    global SHUTDOWN_REQUESTED
    print("\n[!] Shutdown requested, finishing current task...")
    SHUTDOWN_REQUESTED = True


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# =========================
# Configuration
# =========================

API_KEY = os.environ.get('HA_API_KEY')
if not API_KEY:
    print("[!] Error: HA_API_KEY environment variable not set")
    print("    Run: export HA_API_KEY=your_key_here")
    exit(1)

BASE_URL = "https://hybrid-analysis.com/api/v2"

HEADERS = {
    "api-key": API_KEY,
    "User-Agent": "Falcon Sandbox",
    "Accept": "application/json",
}

LATEST_LIMIT = 3
MAX_WORKERS = 1

GLOBAL_REQUEST_LOCK = threading.Lock()
LAST_REQUEST_TIME = 0.0
MIN_REQUEST_INTERVAL = 10.0
MAX_RETRIES = 3
BACKOFF_BASE = 15.0

CACHE_DIR = Path("cache")
RULES_DIR = Path("rules")
YARA_DIR = RULES_DIR / "yara"
SIGMA_DIR = RULES_DIR / "sigma"
SURICATA_DIR = RULES_DIR / "suricata"
LOGS_DIR = Path("logs")

for d in [CACHE_DIR, YARA_DIR, SIGMA_DIR, SURICATA_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "google.com", "cloudflare.com",
    "github.com", "amazon.com", "apple.com", "adobe.com", "mozilla.org",
    "w3.org", "iana.org", "python.org", "java.com", "oracle.com",
    "reddit.com", "twitter.com", "facebook.com", "instagram.com",
    "linkedin.com", "dropbox.com", "zoom.us", "chocolatey.org",
    "nuget.org", "npmjs.com", "pypi.org", "rubygems.org",
}

GENERIC_WINDOWS_STRINGS = {
    "kernel32.dll", "user32.dll", "advapi32.dll", "gdi32.dll",
    "ntdll.dll", "shell32.dll", "ole32.dll", "comdlg32.dll",
    "version.dll", "winmm.dll", "ws2_32.dll", "crypt32.dll",
    "msvcrt.dll", "secur32.dll", "oleaut32.dll", "comctl32.dll",
    "Microsoft Corporation",
}

HIGH_VALUE_PATTERNS = [
    "powershell", "cmd.exe", "wscript", "cscript",
    "virtualalloc", "virtualprotect", "getprocaddress", "loadlibrary",
    "winexec", "shellexecute", "regsvr32", "schtasks", "rundll32",
    "net user", "add user", "createuser", "admin$",
    "powershell -enc", "iex", "invoke-expression", "downloadstring",
    "webclient", "bitsadmin", "certutil", "mshta",
    "reg add", "regedit", "runonce", "services",
    "mutex", "mole", "njRAT", "emotet", "trickbot", "cobalt",
    "ransom", "locky", "wannacry", "petya",
]

C2_PATTERNS = [
    r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/|$)",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+",
]

DOMAIN_RE = re.compile(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PRINTABLE_RE = re.compile(r"[ -~]{4,}")
SHA256_RE = re.compile(r"[a-f0-9]{64}")


# =========================
# HTTP helpers
# =========================

def rate_limited_get(url: str, params: dict = None, accept: str = "application/json") -> requests.Response | None:
    global LAST_REQUEST_TIME, SHUTDOWN_REQUESTED
    headers = dict(HEADERS)
    headers["Accept"] = accept

    for attempt in range(MAX_RETRIES):
        if SHUTDOWN_REQUESTED:
            return None
            
        with GLOBAL_REQUEST_LOCK:
            elapsed = time.time() - LAST_REQUEST_TIME
            if elapsed < MIN_REQUEST_INTERVAL:
                time.sleep(MIN_REQUEST_INTERVAL - elapsed)
            LAST_REQUEST_TIME = time.time()

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=60, verify=False)
            if resp.status_code in (429, 503):
                wait_time = BACKOFF_BASE * (2 ** attempt)
                print(f"[!] Rate limited, waiting {wait_time:.0f}s before retry...")
                time.sleep(wait_time)
                continue
            resp.raise_for_status()
            return resp
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                wait_time = BACKOFF_BASE * (2 ** attempt)
                print(f"[!] Request error: {e}, waiting {wait_time:.0f}s...")
                time.sleep(wait_time)
                continue
            print(f"[!] Request failed after {MAX_RETRIES} attempts: {e}")
            return None


# =========================
# API helpers
# =========================

def get_latest_samples(limit: int = LATEST_LIMIT) -> list[dict]:
    url = f"{BASE_URL}/feed/latest"
    resp = rate_limited_get(url, {"limit": limit})
    if not resp:
        return []
    try:
        data = resp.json()
        if isinstance(data, list):
            return data
        return data.get("data", [])
    except:
        return []


def filter_malicious(samples: list[dict]) -> list[dict]:
    malicious = []
    for s in samples:
        verdict = s.get("verdict", "").lower()
        threat = s.get("threat_score", 0)
        if verdict == "malicious" or threat >= 70:
            malicious.append(s)
    return malicious


def cache_get(name: str) -> Any:
    path = CACHE_DIR / name
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except:
            pass
    return None


def cache_set(name: str, data: Any) -> None:
    path = CACHE_DIR / name
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_overview(sha256: str) -> dict:
    cached = cache_get(f"ov_{sha256}")
    if cached:
        return cached
    url = f"{BASE_URL}/overview/{sha256}"
    resp = rate_limited_get(url)
    if not resp:
        return {}
    try:
        data = resp.json()
        cache_set(f"ov_{sha256}", data)
        return data
    except Exception as e:
        print(f"[!] Failed to get overview: {e}")
        return {}


def get_summary(report_id: str) -> dict:
    cached = cache_get(f"sm_{report_id}")
    if cached:
        return cached
    url = f"{BASE_URL}/report/{report_id}/summary"
    resp = rate_limited_get(url)
    if not resp:
        return {}
    try:
        data = resp.json()
        cache_set(f"sm_{report_id}", data)
        return data
    except Exception as e:
        print(f"[!] Failed to get summary: {e}")
        return {}


def get_memory_strings(report_id: str) -> list[str]:
    cached = cache_get(f"ms_{report_id}")
    if cached:
        return cached
    
    strings = []
    
    url = f"{BASE_URL}/report/{report_id}/strings"
    try:
        resp = rate_limited_get(url, accept="application/octet-stream")
        if resp:
            zip_data = resp.content
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                for name in zf.namelist():
                    if name.lower().endswith(".string"):
                        try:
                            text = zf.read(name).decode("utf-8", errors="ignore")
                            strings.extend(PRINTABLE_RE.findall(text))
                        except:
                            pass
    except:
        pass
    
    cache_set(f"ms_{report_id}", strings)
    return strings


# =========================
# IOC extraction
# =========================

def is_generic_windows(s: str) -> bool:
    lower = s.lower()
    for gen in GENERIC_WINDOWS_STRINGS:
        if gen.lower() == lower:
            return True
    if len(s) < 4:
        return True
    if s.isdigit():
        return True
    return False


def is_sample_specific(s: str) -> bool:
    if SHA256_RE.search(s):
        return True
    if len(s) > 150:
        return True
    return False


def is_high_value(s: str) -> bool:
    lower = s.lower()
    for pattern in HIGH_VALUE_PATTERNS:
        if pattern in lower:
            return True
    for pattern in C2_PATTERNS:
        if re.search(pattern, s, re.I):
            return True
    return False


def filter_strings(strings: list[str], max_count: int = 30) -> list[str]:
    filtered = []
    for s in strings:
        if len(s) < 3:
            continue
        if s.isdigit():
            continue
        if is_sample_specific(s):
            continue
        filtered.append(s)
    return list(dict.fromkeys(filtered))[:max_count]


def extract_network_iocs(summary: dict, strings: list[str]) -> tuple[list, list]:
    all_text = "\n".join(strings)
    domains = set(DOMAIN_RE.findall(all_text))
    ips = set(IP_RE.findall(all_text))
    
    for d in summary.get("domains", []):
        domains.add(d)
    for h in summary.get("hosts", []):
        ips.add(h)
    
    domains = {d for d in domains if not any(b in d.lower() for b in BENIGN_DOMAINS)}
    ips = {ip for ip in ips if not ip.startswith(("10.", "172.", "192.168", "127."))}
    
    return sorted(domains)[:15], sorted(ips)[:10]


def extract_behaviors(summary: dict) -> list[dict]:
    behaviors = []
    for sig in summary.get("signatures", [])[:10]:
        name = sig.get("name", "")
        risk = sig.get("risk", 0)
        if risk >= 50 and name:
            behaviors.append({"name": name, "risk": risk})
    return behaviors


def extract_family(sample: dict, overview: dict, summary: dict) -> str:
    family = overview.get("vx_family") or overview.get("vxf_family")
    if not family:
        family = sample.get("vxf_family") or sample.get("vx_family")
    if not family:
        family = sample.get("threat_family")
    if not family:
        tags = summary.get("classification_tags", [])
        if tags:
            family = str(tags[0]) if tags else "unknown"
    if not family:
        family = "unknown"
    return re.sub(r"[^a-zA-Z0-9._-]", "_", family)[:50]


# =========================
# YARA generation
# =========================


def is_benign_domain(domain: str) -> bool:
    d = domain.lower()
    BENIGN = {
        "example.com", "test.com", "localhost", "127.0.0.1",
        "microsoft.com", "windows.com", "google.com", "cloudflare.com",
        "github.com", "amazon.com", "apple.com", "adobe.com", "mozilla.org",
        "w3.org", "iana.org", "python.org", "java.com", "oracle.com",
        "facebook.com", "twitter.com", "instagram.com", "linkedin.com",
        "dropbox.com", "zoom.us", "chocolatey.org", "nuget.org", "npmjs.com",
        "pypi.org", "rubygems.org", "apache.org", "nginx.com", "ubuntu.com",
        "debian.org", "centos.org", "redhat.com", "fedoraproject.org",
        "contoso.com", "fabrikam.com", "adatum.com",
        "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
        "cdn.jsdelivr.net", "unpkg.com", "raw.githubusercontent.com",
        "mail.protection.outlook.com", "protection.outlook.com",
    }
    if d in BENIGN:
        return True
    for b in BENIGN:
        if b in d:
            return True
    return False

def to_hex(s: str) -> str:
    return " ".join(f"{b:02x}" for b in s.encode("utf-8", errors="ignore"))

def calculate_threshold(total_strings: int) -> str:
    if total_strings >= 10:
        return f"{max(5, total_strings * 80 // 100)} of them"
    elif total_strings >= 5:
        return f"{max(3, total_strings * 80 // 100)} of them"
    elif total_strings >= 3:
        return f"{max(2, total_strings * 80 // 100)} of them"
    else:
        return "any of them"

def generate_family_yara(family: str, samples_data: list[dict]) -> tuple[str, str] | None:
    all_domains = []
    all_hosts = []
    all_file_names = []
    all_mitre = []
    all_urls = []
    
    for sd in samples_data:
        all_domains.extend(sd.get("domains", []))
        all_hosts.extend(sd.get("hosts", []))
        summary = sd.get("summary", {})
        for f in summary.get("extracted_files", [])[:10]:
            name = f.get("name", "")
            if name and len(name) > 4:
                all_file_names.append(name)
        
        for m in sd.get("mitre", [])[:5]:
            tech = m.get("technique", "")
            if tech:
                all_mitre.append(tech)
        
        target_url = sd.get("target_url")
        if target_url:
            all_urls.append(target_url)
    
    unique_domains = [d for d in set(all_domains) if not is_benign_domain(d)]
    unique_hosts = list(set(all_hosts))
    
    name_counts = Counter(all_file_names)
    common_names = [n for n, count in name_counts.most_common(15) if count >= len(samples_data) // 2][:8]
    
    mitre_counts = Counter(all_mitre)
    common_mitre = [m for m, count in mitre_counts.most_common(5)]
    
    unique_urls = list(set(all_urls))
    
    if len(unique_urls) < 1 and len(unique_domains) < 1 and len(common_names) < 2 and len(unique_hosts) < 1:
        return None
    
    safe_family = family.replace(":", "_").replace("\\", "_").replace("/", "_")
    
    str_lines = []
    for i, d in enumerate(unique_domains[:10]):
        str_lines.append(f'        $d{i} = "{d}"')
    for i, h in enumerate(unique_hosts[:5]):
        str_lines.append(f'        $h{i} = "{h}"')
    for i, name in enumerate(common_names[:8]):
        str_lines.append(f'        $fn{i} = "{name}"')
    
    if not str_lines:
        return None
    
    condition = calculate_threshold(len(str_lines))
    
    first_sha = samples_data[0]["sha256"]
    first_seen = samples_data[0].get("first_seen", "unknown")
    threat = samples_data[0].get("threat_score", "unknown")
    
    mitre_str = ", ".join(common_mitre) if common_mitre else "none"
    target_url_str = unique_urls[0] if unique_urls else "none"
    
    rule = f"""rule {safe_family}_family
{{
    meta:
        description = "Auto-generated YARA rule for {family}"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "{len(samples_data)}"
        first_sha256 = "{first_sha}"
        first_seen = "{first_seen}"
        threat_score = "{threat}"
        mitre_techniques = "{mitre_str}"
        target_url = "{target_url_str}"

    strings:
{chr(10).join(str_lines)}

    condition:
        {condition}
}}
"""
    return rule, safe_family


def write_yara(safe_family: str, rule: str, sha256: str) -> Path:
    fam_dir = YARA_DIR / safe_family
    fam_dir.mkdir(parents=True, exist_ok=True)
    path = fam_dir / f"{sha256[:16]}.yar"
    path.write_text(rule, encoding="utf-8")
    return path


# =========================
# Sigma generation  
# =========================

def generate_sigma(family: str, signatures: list, domains: list, hosts: list, sha256: str) -> str | None:
    if not (signatures or domains or hosts):
        return None
    
    selection = []
    for sig in signatures[:10]:
        name = sig.get("name", "")
        if name:
            selection.append({"EventType": name})
    for d in domains[:8]:
        selection.append({"DestinationHostname": d})
    for ip in hosts[:5]:
        selection.append({"DestinationIp": ip})
    
    sigma = {
        "title": f"{family} malware detection",
        "id": f"{family[:8]}-{sha256[:8]}",
        "status": "experimental",
        "description": f"Detects {family} malware",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection": {"selection": selection, "condition": "selection"},
        "tags": ["malware", family],
    }
    return yaml.safe_dump(sigma, sort_keys=False)


def write_sigma(family: str, rule: str, sha256: str) -> Path:
    fam_dir = SIGMA_DIR / family
    fam_dir.mkdir(parents=True, exist_ok=True)
    path = fam_dir / f"{sha256[:16]}.yml"
    path.write_text(rule, encoding="utf-8")
    return path


# =========================
# Suricata generation
# =========================

def generate_suricata(domains: list, ips: list, sha256: str) -> str | None:
    if not (domains or ips):
        return None
    
    rules = []
    base_sid = int(sha256[:7], 16) % 10000000
    sid = 1
    
    for d in domains[:10]:
        rules.append(f'alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE {d}"; dns.query; content:"{d}"; sid:{base_sid}{sid:02d}; rev:1;)')
        sid += 1
    
    for ip in ips[:10]:
        rules.append(f'alert ip $HOME_NET any -> {ip} any (msg:"MALWARE C2 {ip}"; sid:{base_sid}{sid:02d}; rev:1;)')
        sid += 1
    
    return "\n".join(rules)


def write_suricata(family: str, rule: str, sha256: str) -> Path:
    fam_dir = SURICATA_DIR / family
    fam_dir.mkdir(parents=True, exist_ok=True)
    path = fam_dir / f"{sha256[:16]}.rules"
    path.write_text(rule, encoding="utf-8")
    return path


# =========================
# Processing
# =========================

def process_sample(sample: dict) -> dict | None:
    if SHUTDOWN_REQUESTED:
        return None
    
    sha256 = sample.get("sha256", "")
    if not sha256:
        return None
    
    try:
        overview = get_overview(sha256)
    except Exception as e:
        print(f"[!] Failed overview {sha256[:8]}: {e}")
        return None
    
    reports = overview.get("reports", [])
    if not reports:
        return None
    
    try:
        summary = get_summary(str(reports[0]))
    except:
        summary = {}
    
    family = extract_family(sample, overview, summary)
    
    domains = summary.get("domains", [])
    hosts = summary.get("hosts", [])
    signatures = summary.get("signatures", [])
    mitre = summary.get("mitre_attcks", [])
    target_url = summary.get("target_url")
    
    return {
        "sha256": sha256,
        "family": family,
        "overview": overview,
        "summary": summary,
        "domains": domains,
        "hosts": hosts,
        "signatures": signatures,
        "mitre": mitre,
        "target_url": target_url,
        "first_seen": overview.get("analysis_start_time", "unknown"),
        "threat_score": overview.get("threat_score", 0),
    }


def main():
    global SHUTDOWN_REQUESTED
    
    print(f"[*] Fetching {LATEST_LIMIT} latest samples...")
    samples = get_latest_samples(LATEST_LIMIT)
    print(f"[*] Got {len(samples)} samples from API")
    malicious = filter_malicious(samples)
    print(f"[*] Found {len(malicious)} malicious samples")
    
    max_process = min(len(malicious), 15)
    malicious = malicious[:max_process]
    print(f"[*] Processing max {max_process} samples")
    
    print("[*] Processing samples (this may take a while)...")
    sys.stdout.flush()
    
    processed = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_sample, s): s for s in malicious}
        for i, fut in enumerate(as_completed(futures)):
            if SHUTDOWN_REQUESTED:
                break
            print(f"[*] Processing {i+1}/{len(malicious)}...", end="\r")
            sys.stdout.flush()
            try:
                result = fut.result()
                if result:
                    processed.append(result)
                    print(f"[+] {result['family']}: {result['sha256'][:8]}")
            except Exception as e:
                print(f"[!] Error: {e}")
    
    if SHUTDOWN_REQUESTED:
        print("[!] Shutdown requested, saving progress...")
    
    print(f"[*] Grouping by family...")
    families = defaultdict(list)
    for p in processed:
        families[p["family"]].append(p)
    
    samples_with_iocs = sum(1 for p in processed if p.get("domains") or p.get("hosts"))
    print(f"[*] Found {len(families)} unique families, {samples_with_iocs} samples with IOCs")
    
    yara_count = 0
    sigma_count = 0
    suricata_count = 0
    
    for family, samples_data in families.items():
        if SHUTDOWN_REQUESTED:
            break
        
        if len(samples_data) < 1:
            continue
        
        sample = samples_data[0]
        sha256 = sample["sha256"]
        
        result = generate_family_yara(family, samples_data)
        if result:
            yara_rule, safe_family = result
            try:
                write_yara(safe_family, yara_rule, sha256)
                yara_count += 1
                print(f"[+] YARA: {family}")
            except Exception as e:
                print(f"[!] YARA write error: {e}")
        
        domains = sample.get("domains", [])
        hosts = sample.get("hosts", [])
        signatures = sample.get("signatures", [])
        
        sigma_rule = generate_sigma(family, signatures, domains, hosts, sha256)
        if sigma_rule:
            try:
                write_sigma(family, sigma_rule, sha256)
                sigma_count += 1
            except:
                pass
        
        suricata_rule = generate_suricata(domains, hosts, sha256)
        if suricata_rule:
            try:
                write_suricata(family, suricata_rule, sha256)
                suricata_count += 1
            except:
                pass
    
    print(f"\n[*] Done!")
    print(f"    YARA rules: {yara_count}")
    print(f"    Sigma rules: {sigma_count}")
    print(f"    Suricata rules: {suricata_count}")


if __name__ == "__main__":
    main()
