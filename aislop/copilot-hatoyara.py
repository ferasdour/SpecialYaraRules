#!/usr/bin/env python3
"""
Hybrid Analysis → Multi-rule pipeline v4
- YARA (file-based)
- Sigma (behavior + network)
- Suricata (network)

Key points:
- YARA: file/memory strings only, hex, 80% of ($*) condition.
- Sigma: behavior artifacts + domains/IPs.
- Suricata: domains/IPs as simple alert rules.
"""
import os
import io
import json
import math
import re
import time
import threading
import zipfile
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
import requests
import yaml
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =========================
# Configuration
# =========================

API_KEY = os.environ['HA_API_KEY']
BASE_URL = "https://hybrid-analysis.com/api/v2"

HEADERS = {
    "api-key": API_KEY,
    "User-Agent": "Falcon Sandbox",
    "Accept": "application/json",
}

LATEST_LIMIT = 600
MAX_WORKERS = 1

GLOBAL_REQUEST_LOCK = threading.Lock()
LAST_REQUEST_TIME = 0.0
MIN_REQUEST_INTERVAL = 5.0  # seconds between requests
MAX_RETRIES = 5
BACKOFF_BASE = 10.0  # seconds

CACHE_DIR = Path("cache")
RULES_DIR = Path("rules")
YARA_DIR = RULES_DIR / "yara"
SIGMA_DIR = RULES_DIR / "sigma"
SURICATA_DIR = RULES_DIR / "suricata"
LOGS_DIR = Path("logs")
FAILED_LOGS_DIR = LOGS_DIR / "failed"

for d in [CACHE_DIR, YARA_DIR, SIGMA_DIR, SURICATA_DIR, FAILED_LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

SUSPICIOUS_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "upx",
    "virtualalloc",
    "virtualprotect",
    "getprocaddress",
    "loadlibrary",
    "winexec",
    "shellexecute",
    "regsvr32",
    "schtasks",
    "rundll32",
]

DOMAIN_RE = re.compile(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PRINTABLE_RE = re.compile(r"[ -~]{4,}")  # printable ASCII, length >= 4


# =========================
# HTTP helpers
# =========================

def rate_limited_get(url: str,
                     params: dict | None = None,
                     accept: str = "application/json") -> requests.Response:
    global LAST_REQUEST_TIME

    headers = dict(HEADERS)
    headers["Accept"] = accept

    for attempt in range(MAX_RETRIES):
        with GLOBAL_REQUEST_LOCK:
            now = time.time()
            elapsed = now - LAST_REQUEST_TIME
            if elapsed < MIN_REQUEST_INTERVAL:
                time.sleep(MIN_REQUEST_INTERVAL - elapsed)
            LAST_REQUEST_TIME = time.time()

        resp = requests.get(url, headers=headers, params=params, timeout=120, verify=False)

        if resp.status_code in (429, 503):
            sleep_time = BACKOFF_BASE * (2 ** attempt)
            print(f"[!] Rate limited ({resp.status_code}), backing off {sleep_time:.1f}s...")
            time.sleep(sleep_time)
            continue

        resp.raise_for_status()
        return resp

    raise RuntimeError(f"Failed to GET {url} after {MAX_RETRIES} attempts")


# =========================
# API helpers
# =========================

def get_latest_samples(limit: int = LATEST_LIMIT) -> list[dict[str, Any]]:
    url = f"{BASE_URL}/feed/latest"
    params = {"limit": limit}
    resp = rate_limited_get(url, params=params)
    data = resp.json()
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return data["data"]
    return []


def filter_malicious(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    malicious: list[dict[str, Any]] = []
    for s in samples:
        verdict = s.get("verdict") or s.get("verdicts")
        threat_score = s.get("threat_score")
        if isinstance(verdict, str) and verdict.lower() == "malicious":
            malicious.append(s)
            continue
        if isinstance(threat_score, int) and threat_score >= 70:
            malicious.append(s)
            continue
    return malicious


def cache_path(name: str) -> Path:
    return CACHE_DIR / name


def load_json_cache(name: str) -> dict[str, Any] | None:
    path = cache_path(name)
    if path.is_file():
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Failed to load cache {name}: {e}")
    return None


def save_json_cache(name: str, data: dict[str, Any]) -> None:
    path = cache_path(name)
    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[!] Failed to save cache {name}: {e}")


def load_binary_cache(name: str) -> bytes | None:
    path = cache_path(name)
    if path.is_file():
        try:
            return path.read_bytes()
        except Exception as e:
            print(f"[!] Failed to load binary cache {name}: {e}")
    return None


def save_binary_cache(name: str, data: bytes) -> None:
    path = cache_path(name)
    try:
        path.write_bytes(data)
    except Exception as e:
        print(f"[!] Failed to save binary cache {name}: {e}")


def get_overview(sha256: str) -> dict[str, Any]:
    cache_name = f"overview_{sha256}.json"
    cached = load_json_cache(cache_name)
    if cached is not None:
        return cached

    url = f"{BASE_URL}/overview/{sha256}"
    resp = rate_limited_get(url)
    data = resp.json()
    save_json_cache(cache_name, data)
    return data


def get_summary(report_id: str) -> dict[str, Any]:
    cache_name = f"summary_{report_id}.json"
    cached = load_json_cache(cache_name)
    if cached is not None:
        return cached

    url = f"{BASE_URL}/report/{report_id}/summary"
    resp = rate_limited_get(url)
    data = resp.json()
    save_json_cache(cache_name, data)
    return data


def get_memory_strings_zip(report_id: str) -> bytes:
    cache_name = f"mstrings_{report_id}.zip"
    cached = load_binary_cache(cache_name)
    if cached is not None:
        return cached

    url = f"{BASE_URL}/report/{report_id}/memory-strings"
    resp = rate_limited_get(url, accept="application/octet-stream")
    data = resp.content
    save_binary_cache(cache_name, data)
    return data


# =========================
# Memory strings parsing
# =========================

def extract_strings_from_mstring_content(content: str) -> list[str]:
    strings: list[str] = []
    for line in content.splitlines():
        for match in PRINTABLE_RE.findall(line):
            strings.append(match)
    seen: set[str] = set()
    uniq: list[str] = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def extract_all_memory_strings(zip_bytes: bytes) -> list[str]:
    all_strings: list[str] = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".mstring"):
                continue
            try:
                data = zf.read(name)
                text = data.decode("utf-8", errors="ignore")
                strs = extract_strings_from_mstring_content(text)
                all_strings.extend(strs)
            except Exception as e:
                print(f"[!] Failed to parse {name} in memory-strings ZIP: {e}")

    seen: set[str] = set()
    uniq: list[str] = []
    for s in all_strings:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


# =========================
# Feature extraction
# =========================

def is_interesting_string(s: str) -> bool:
    lower = s.lower()
    if len(s) < 4:
        return False
    if any(k in lower for k in SUSPICIOUS_KEYWORDS):
        return True
    if "http://" in lower or "https://" in lower:
        return True
    if "\\" in s or "c:\\" in lower:
        return True
    if "hkey_" in lower or "hkcu\\" in lower or "hklm\\" in lower:
        return True
    if "mutex" in lower:
        return True
    return False


def extract_interesting_strings(all_strings: list[str]) -> list[str]:
    interesting: list[str] = []
    for s in all_strings:
        if is_interesting_string(s):
            interesting.append(s)
    seen: set[str] = set()
    uniq: list[str] = []
    for s in interesting:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq[:60]


def extract_behavior_artifacts(summary: dict[str, Any]) -> list[str]:
    artifacts: list[str] = []
    sigs = summary.get("signatures", [])
    if isinstance(sigs, list):
        for sig in sigs:
            if not isinstance(sig, dict):
                continue
            desc = sig.get("description")
            if isinstance(desc, str):
                artifacts.append(desc)
            name = sig.get("name")
            if isinstance(name, str):
                artifacts.append(name)
            ident = sig.get("identifier")
            if isinstance(ident, str):
                artifacts.append(ident)

    seen: set[str] = set()
    uniq: list[str] = []
    for a in artifacts:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq[:60]


def extract_network_iocs_from_summary(summary: dict[str, Any],
                                      strings: list[str]) -> tuple[list[str], list[str]]:
    text_blob = "\n".join(strings)
    domains_in_strings = set(DOMAIN_RE.findall(text_blob))
    ips_in_strings = set(IP_RE.findall(text_blob))

    ha_domains: set[str] = set()
    ha_ips: set[str] = set()

    doms = summary.get("domains")
    if isinstance(doms, list):
        for d in doms:
            if isinstance(d, str):
                ha_domains.add(d)

    hosts = summary.get("hosts")
    if isinstance(hosts, list):
        for h in hosts:
            if isinstance(h, str):
                ha_ips.add(h)

    final_domains = domains_in_strings | ha_domains
    final_ips = ips_in_strings | ha_ips

    return sorted(final_domains), sorted(final_ips)


def extract_family_from_summary(summary: dict[str, Any]) -> str | None:
    family = summary.get("vx_family") or summary.get("vxf_family")
    if not family:
        ct = summary.get("classification_tags")
        if isinstance(ct, list) and ct:
            family = ct[0]
    if not family:
        tags = summary.get("tags")
        if isinstance(tags, list) and tags:
            family = tags[0]
    return family


# =========================
# YARA helpers
# =========================

def sanitize_yara_text_string(s: str) -> str | None:
    s = "".join(ch for ch in s if 32 <= ord(ch) <= 126)
    if not s:
        return None
    s = s.replace("\\", "\\\\").replace("\"", "\\\"")
    if len(s) > 200:
        s = s[:200]
    return s


def to_hex_bytes(s: str) -> str | None:
    b = s.encode("utf-8", errors="ignore")
    if not b:
        return None
    hex_str = b.hex()
    return " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))


def sanitize_rule_name(name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not name:
        name = "sample_rule"
    if name[0].isdigit():
        name = "_" + name
    return name


def normalize_family_name(family: str | None) -> str:
    if not family:
        return "unknown"
    f = family.strip().lower()
    if not f or f in ("none", "unknown", "generic"):
        return "unknown"
    f = re.sub(r"[^a-z0-9_]+", "_", f)
    if not f:
        return "unknown"
    return f


def validate_yara_rule_text(rule_text: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["yara", "-n", "-", "/dev/null"],
            input=rule_text.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode == 0:
            return True, proc.stderr.decode("utf-8", errors="ignore")
        else:
            return False, proc.stderr.decode("utf-8", errors="ignore")
    except FileNotFoundError:
        # If yara isn't installed, don't block generation
        return True, ""
    except Exception as e:
        return False, str(e)


# =========================
# YARA rule generator (file-only)
# =========================

def generate_yara_rule(
    sha256: str,
    family: str | None,
    threat_score: int | None,
    first_seen: str | None,
    file_strings: list[str],
) -> tuple[str | None, dict[str, str]]:
    if not file_strings:
        return None, {}

    id_to_raw: dict[str, str] = {}
    str_lines: list[str] = []

    for i, s in enumerate(file_strings):
        hx = to_hex_bytes(s)
        if not hx:
            continue
        sid = f"$s{i}"
        id_to_raw[sid] = s
        str_lines.append(f"        {sid} = {{ {hx} }}")

    if not str_lines:
        return None, {}

    total = len(id_to_raw)
    threshold = max(1, int(total * 0.8))
    condition = f"{threshold} of ($*)"

    fam = family or "unknown"
    rule_name = sanitize_rule_name(f"{fam}_{sha256[:8]}")
    threat_str = str(threat_score) if threat_score is not None else "unknown"
    first_seen_str = first_seen or "unknown"

    rule_text = f"""
rule {rule_name}
{{
    meta:
        sha256 = "{sha256}"
        family = "{fam}"
        threat_score = "{threat_str}"
        first_seen = "{first_seen_str}"
        sample_url = "https://www.hybrid-analysis.com/sample/{sha256}"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
{chr(10).join(str_lines)}

    condition:
        {condition}
}}
""".strip()

    return rule_text, id_to_raw


def write_yara_rule(family: str | None, sha256: str, rule_text: str) -> Path:
    fam = normalize_family_name(family)
    fam_dir = YARA_DIR / fam
    fam_dir.mkdir(parents=True, exist_ok=True)
    path = fam_dir / f"{sha256}.yar"
    path.write_text(rule_text + "\n", encoding="utf-8")
    return path


# =========================
# Sigma rule generator
# =========================

def generate_sigma_rule(
    sha256: str,
    family: str | None,
    behavior_artifacts: list[str],
    domains: list[str],
    ips: list[str],
) -> str | None:
    if not (behavior_artifacts or domains or ips):
        return None

    fam = family or "unknown"
    title = f"{fam} behavior detection ({sha256[:8]})"

    detection: dict[str, Any] = {
        "selection_behavior": [],
        "selection_network": [],
        "condition": "selection_behavior or selection_network",
    }

    for b in behavior_artifacts:
        detection["selection_behavior"].append({"EventData": b})

    for d in domains:
        detection["selection_network"].append({"DestinationHostname": d})

    for ip in ips:
        detection["selection_network"].append({"DestinationIp": ip})

    sigma = {
        "title": title,
        "id": sha256,
        "status": "experimental",
        "description": f"Auto-generated Sigma rule for {fam}",
        "logsource": {
            "product": "windows",
            "service": "sysmon",
        },
        "detection": detection,
    }

    return yaml.safe_dump(sigma, sort_keys=False)


def write_sigma_rule(family: str | None, sha256: str, sigma_text: str) -> Path:
    fam = normalize_family_name(family)
    fam_dir = SIGMA_DIR / fam
    fam_dir.mkdir(parents=True, exist_ok=True)
    path = fam_dir / f"{sha256}.yml"
    path.write_text(sigma_text, encoding="utf-8")
    return path


# =========================
# Suricata rule generator
# =========================

def generate_suricata_rules(
    sha256: str,
    domains: list[str],
    ips: list[str],
) -> str | None:
    if not (domains or ips):
        return None

    rules: list[str] = []
    base_sid = int(sha256[:7], 16) % 10000000  # keep sid in a sane range

    sid_counter = 1
    for d in domains:
        rules.append(
            f'alert dns any any -> any any (msg:"C2 domain {d} ({sha256[:8]})"; '
            f'dns.query; content:"{d}"; nocase; sid:{base_sid}{sid_counter:02d}; rev:1;)'
        )
        sid_counter += 1

    for ip in ips:
        rules.append(
            f'alert ip any any -> {ip} any (msg:"C2 IP {ip} ({sha256[:8]})"; '
            f'sid:{base_sid}{sid_counter:02d}; rev:1;)'
        )
        sid_counter += 1

    return "\n".join(rules)


def write_suricata_rules(family: str | None, sha256: str, suricata_text: str) -> Path:
    fam = normalize_family_name(family)
    fam_dir = SURICATA_DIR / fam
    fam_dir.mkdir(parents=True, exist_ok=True)
    path = fam_dir / f"{sha256}.rules"
    path.write_text(suricata_text + "\n", encoding="utf-8")
    return path


# =========================
# Failure logging
# =========================

def log_failed_yara(
    sha256: str,
    rule_text: str,
    err: str,
    file_strings: list[str],
) -> None:
    path = FAILED_LOGS_DIR / f"{sha256}.txt"
    try:
        with path.open("w", encoding="utf-8") as f:
            f.write(f"SHA256: {sha256}\n")
            f.write("=== YARA ERROR ===\n")
            f.write(err.strip() + "\n\n")
            f.write("=== RULE TEXT ===\n")
            f.write(rule_text + "\n\n")
            f.write("=== FILE STRINGS ===\n")
            for s in file_strings:
                f.write(repr(s) + "\n")
    except Exception as e:
        print(f"[!] Failed to write failure log for {sha256}: {e}")


# =========================
# Orchestration
# =========================

def process_sample(sample: dict[str, Any]) -> tuple[str, dict[str, Path]]:
    sha256 = (
        sample.get("sha256")
        or sample.get("sha2")
        or sample.get("sha256_hash")
        or ""
    )
    outputs: dict[str, Path] = {}

    if not sha256:
        print("[!] Sample missing sha256, skipping")
        return "", outputs

    try:
        overview = get_overview(sha256)
    except Exception as e:
        print(f"[!] Failed to get overview for {sha256}: {e}")
        return sha256, outputs

    threat_score = overview.get("threat_score")
    first_seen = overview.get("analysis_start_time") or overview.get("submitted_at")

    reports = overview.get("reports") or []
    if not reports or not isinstance(reports, list):
        print(f"[!] No reports for {sha256}, skipping")
        return sha256, outputs

    report_id = str(reports[0])

    try:
        summary = get_summary(report_id)
    except Exception as e:
        print(f"[!] Failed to get summary for {sha256} ({report_id}): {e}")
        summary = {}

    family = extract_family_from_summary(summary)

    try:
        mzip = get_memory_strings_zip(report_id)
        all_strings = extract_all_memory_strings(mzip)
    except Exception as e:
        print(f"[!] Failed to get/parse memory-strings for {sha256} ({report_id}): {e}")
        all_strings = []

    mem_strings = extract_interesting_strings(all_strings)
    behavior_artifacts = extract_behavior_artifacts(summary)
    domains, ips = extract_network_iocs_from_summary(summary, all_strings)

    # FILE STRINGS for YARA: memory strings only (for now)
    file_strings = mem_strings

    # ---------- YARA ----------
    yara_rule_text, id_to_raw = generate_yara_rule(
        sha256=sha256,
        family=family,
        threat_score=threat_score if isinstance(threat_score, int) else None,
        first_seen=str(first_seen) if first_seen else None,
        file_strings=file_strings,
    )

    if yara_rule_text:
        ok, err = validate_yara_rule_text(yara_rule_text)
        if ok:
            path = write_yara_rule(family, sha256, yara_rule_text)
            outputs["yara"] = path
            print(f"[+] YARA rule for {sha256} → {path}")
        else:
            print(f"[!] Invalid YARA for {sha256}: {err.strip()}")
            log_failed_yara(sha256, yara_rule_text, err, file_strings)

    # ---------- Sigma ----------
    sigma_text = generate_sigma_rule(
        sha256=sha256,
        family=family,
        behavior_artifacts=behavior_artifacts,
        domains=domains,
        ips=ips,
    )
    if sigma_text:
        path = write_sigma_rule(family, sha256, sigma_text)
        outputs["sigma"] = path
        print(f"[+] Sigma rule for {sha256} → {path}")

    # ---------- Suricata ----------
    suricata_text = generate_suricata_rules(
        sha256=sha256,
        domains=domains,
        ips=ips,
    )
    if suricata_text:
        path = write_suricata_rules(family, sha256, suricata_text)
        outputs["suricata"] = path
        print(f"[+] Suricata rules for {sha256} → {path}")

    if not outputs:
        print(f"[!] No rules generated for {sha256}")

    return sha256, outputs


def generate_rules_from_latest(limit: int = LATEST_LIMIT) -> None:
    samples = get_latest_samples(limit=limit)
    malicious_samples = filter_malicious(samples)
    print(f"[*] Retrieved {len(samples)} samples, {len(malicious_samples)} malicious candidates")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_sample, s): s for s in malicious_samples}
        for fut in as_completed(futures):
            sample = futures[fut]
            try:
                sha256, outputs = fut.result()
                # outputs already logged
            except Exception as e:
                sha = sample.get("sha256") or "unknown"
                print(f"[!] Error processing {sha}: {e}")


def main() -> None:
    generate_rules_from_latest(limit=LATEST_LIMIT)


if __name__ == "__main__":
    main()
