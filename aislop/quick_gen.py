#!/usr/bin/env python3
"""Quick rule generator from cached HA data"""
import json
import yaml
import re
from pathlib import Path
from collections import defaultdict, Counter

CACHE_DIR = Path("cache")
RULES_DIR = Path("rules")
YARA_DIR = RULES_DIR / "yara"
SIGMA_DIR = RULES_DIR / "sigma"
SURICATA_DIR = RULES_DIR / "suricata"

for d in [YARA_DIR, SIGMA_DIR, SURICATA_DIR]:
    d.mkdir(parents=True, exist_ok=True)

BENIGN_DOMAINS = {
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
    "cloudflare.com", "akamai.com", "fastly.com", "stackpathdns.com",
}

GENERIC_WINDOWS = {
    "kernel32.dll", "user32.dll", "advapi32.dll", "ntdll.dll",
    "shell32.dll", "ole32.dll", "msvcrt.dll", "ws2_32.dll",
    "Microsoft Corporation", "Windows",
}

def is_benign_domain(domain: str) -> bool:
    d = domain.lower()
    if d in BENIGN_DOMAINS:
        return True
    for benign in BENIGN_DOMAINS:
        if benign in d:
            return True
    return False

def is_generic_windows(s: str) -> bool:
    lower = s.lower()
    for gen in GENERIC_WINDOWS:
        if gen.lower() == lower:
            return True
    return False

def filter_strings(strings: list[str]) -> list[str]:
    """Filter strings to keep only meaningful ones"""
    filtered = []
    for s in strings:
        if len(s) < 4:
            continue
        if s.isdigit():
            continue
        if is_generic_windows(s):
            continue
        if s.isascii() and not any(c.isalnum() for c in s):
            continue
        filtered.append(s)
    return filtered

def to_hex(s: str) -> str:
    """Convert string to hex for YARA"""
    return " ".join(f"{b:02x}" for b in s.encode("utf-8", errors="ignore"))

def calculate_threshold(total_strings: int) -> str:
    """Calculate YARA condition threshold - require majority"""
    if total_strings >= 10:
        return f"{max(5, total_strings * 80 // 100)} of them"
    elif total_strings >= 5:
        return f"{max(3, total_strings * 80 // 100)} of them"
    elif total_strings >= 3:
        return f"{max(2, total_strings * 80 // 100)} of them"
    else:
        return "any of them"

def extract_family_from_summary(summary: dict) -> str:
    family = summary.get("vx_family") or summary.get("vxf_family")
    if not family:
        tags = summary.get("classification_tags", [])
        family = tags[0] if tags else "unknown"
    return family.replace(".", "_").replace(" ", "_")[:50]

def extract_file_strings(sample_sha256: str) -> list[str]:
    """Extract strings from the sample file"""
    strings = []
    str_path = CACHE_DIR / f"strings_{sample_sha256}"
    if str_path.exists():
        try:
            strings = json.loads(str_path.read_text())
            return strings
        except:
            pass
    return strings

def process_sample(sm_path: Path):
    try:
        summary = json.loads(sm_path.read_text())
    except:
        return None
    
    sha256 = summary.get("sha256", "")
    family = extract_family_from_summary(summary)
    
    domains = [d for d in summary.get("domains", []) if not is_benign_domain(d)]
    hosts = summary.get("hosts", [])
    
    file_strings = extract_file_strings(sha256)
    file_strings = filter_strings(file_strings)
    
    signatures = summary.get("signatures", [])
    sig_names = [s.get("name", "") for s in signatures if s.get("name")]
    
    extracted_files = summary.get("extracted_files", [])
    file_names = [f.get("name", "") for f in extracted_files[:5] if f.get("name")]
    
    return {
        "sha256": sha256,
        "family": family,
        "domains": domains,
        "hosts": hosts,
        "file_strings": file_strings,
        "signatures": sig_names,
        "file_names": file_names,
    }

# Get all samples
samples = []
for sm_path in CACHE_DIR.glob("sm_*"):
    sample = process_sample(sm_path)
    if sample and (sample["domains"] or sample["hosts"] or sample["signatures"]):
        samples.append(sample)
        print(f"Found: {sample['family']} - {len(sample['domains'])} domains, {len(sample['hosts'])} hosts, {len(sample['signatures'])} sigs")

print(f"Found {len(samples)} samples with IOCs")

# Group by family
families = defaultdict(list)
for s in samples:
    families[s["family"]].append(s)

print(f"Found {len(families)} families")

yara_count = 0
sigma_count = 0
suricata_count = 0

for family, samples_data in families.items():
    safe_family = family.replace(":", "_").replace("\\", "_").replace("/", "_")
    all_domains = []
    all_hosts = []
    all_file_strings = []
    all_signatures = []
    all_file_names = []
    
    for s in samples_data:
        all_domains.extend(s.get("domains", []))
        all_hosts.extend(s.get("hosts", []))
        all_file_strings.extend(s.get("file_strings", []))
        all_signatures.extend(s.get("signatures", []))
        all_file_names.extend(s.get("file_names", []))
    
    unique_domains = [d for d in set(all_domains) if not is_benign_domain(d)]
    unique_hosts = list(set(all_hosts))
    
    string_counts = Counter(all_file_strings)
    common_file_strings = [s for s, count in string_counts.most_common(20) if count >= len(samples_data) // 2]
    common_file_strings = filter_strings(common_file_strings)[:8]
    
    sig_counts = Counter(all_signatures)
    common_sigs = [s for s, count in sig_counts.most_common(10) if count >= len(samples_data) // 2][:5]
    
    name_counts = Counter(all_file_names)
    common_names = [n for n, count in name_counts.most_common(10) if count >= len(samples_data) // 2 and len(n) > 5][:5]
    
    if len(unique_domains) < 1 and len(common_file_strings) < 2 and len(common_sigs) < 2:
        continue
    
    sample = samples_data[0]
    sha256 = sample.get("sha256", "unknown")
    
    if not unique_domains and not common_file_strings and not common_sigs:
        continue
    
    # Generate YARA with ONLY real binary data (domains, IPs, file names)
    # NOT behavioral signatures - those are HA-specific and won't work in other scanners
    str_lines = []
    
    for i, d in enumerate(unique_domains[:10]):
        str_lines.append(f'        $d{i} = "{d}"')
    
    for i, h in enumerate(unique_hosts[:5]):
        str_lines.append(f'        $h{i} = "{h}"')
    
    for i, name in enumerate(common_names[:5]):
        str_lines.append(f'        $fn{i} = "{name}"')
    
    if str_lines:
        total_strings = len(str_lines)
        condition = calculate_threshold(total_strings)
        
        rule = f"""rule {safe_family}_family
{{
    meta:
        description = "Auto-generated YARA rule for {family}"
        author = "aislop"
        source = "Hybrid Analysis"
        reference = "https://www.hybrid-analysis.com/sample/{sha256}"

    strings:
{chr(10).join(str_lines)}

    condition:
        {condition}
}}
"""
        fam_dir = YARA_DIR / safe_family
        fam_dir.mkdir(parents=True, exist_ok=True)
        path = fam_dir / f"{sha256[:16]}.yar"
        path.write_text(rule)
        yara_count += 1
        print(f"[+] YARA: {family} ({total_strings} strings, requires {condition})")
    
    # Generate Sigma
    if unique_domains or unique_hosts:
        selection = []
        for d in unique_domains[:8]:
            selection.append({"DestinationHostname": d})
        for ip in unique_hosts[:5]:
            selection.append({"DestinationIp": ip})
        
        sigma = {
            "title": f"{family} malware detection",
            "id": f"{safe_family[:8]}-{sha256[:8]}",
            "status": "experimental",
            "description": f"Detects {family} malware - {len(unique_domains)} domains, {len(unique_hosts)} IPs",
            "logsource": {"product": "windows", "service": "sysmon"},
            "detection": {"selection": selection, "condition": "selection"},
            "tags": ["malware", safe_family],
        }
        
        fam_dir = SIGMA_DIR / safe_family
        fam_dir.mkdir(parents=True, exist_ok=True)
        path = fam_dir / f"{sha256[:16]}.yml"
        path.write_text(yaml.safe_dump(sigma))
        sigma_count += 1
    
    # Generate Suricata
    if unique_domains or unique_hosts:
        rules = []
        base_sid = int(sha256[:7], 16) % 10000000
        sid = 1
        
        for d in unique_domains[:10]:
            rules.append(f'alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE {d}"; dns.query; content:"{d}"; sid:{base_sid}{sid:02d}; rev:1;)')
            sid += 1
        
        for ip in unique_hosts[:10]:
            rules.append(f'alert ip $HOME_NET any -> {ip} any (msg:"MALWARE C2 {ip}"; sid:{base_sid}{sid:02d}; rev:1;)')
            sid += 1
        
        if rules:
            fam_dir = SURICATA_DIR / safe_family
            fam_dir.mkdir(parents=True, exist_ok=True)
            path = fam_dir / f"{sha256[:16]}.rules"
            path.write_text("\n".join(rules))
            suricata_count += 1

print(f"\nDone!")
print(f"    YARA rules: {yara_count}")
print(f"    Sigma rules: {sigma_count}")
print(f"    Suricata rules: {suricata_count}")
