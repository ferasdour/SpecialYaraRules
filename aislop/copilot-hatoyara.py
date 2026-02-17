#!/usr/bin/env python3
"""
Single-file inline copilot-hatoyara runner.
Notes:
- Minimal, dependency-free; uses standard library only.
- Fetches HA data, builds YARA rules and Sigma/Suricata rules per family.
- Dry-run mode uses embedded sample data for safety.
"""
import argparse
import json
import os
import sys
import time
import datetime
from typing import List, Dict, Any, Set, Tuple
import urllib.request
import urllib.error
import hashlib

# Placeholder; replace in real env if needed
API_ENDPOINT_BASE = os.environ.get("HA_API_BASE", "https://www.hybrid-analysis.com/api/v2")

# Proxy support: respect HTTPS_PROXY/https_proxy environment variables if provided
PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
GLOBAL_OPENER = None
if PROXY:
    try:
        proxy_handler = urllib.request.ProxyHandler({"http": PROXY, "https": PROXY})
        GLOBAL_OPENER = urllib.request.build_opener(proxy_handler)
        print(f"[INFO] Using HTTPS_PROXY={PROXY}", file=sys.stderr)
    except Exception as e:
        print(f"[WARN] Failed to configure proxy: {e}", file=sys.stderr)

def string_to_hex_literal(s: str, max_len: int = 16) -> str:
    b = s.encode("utf-8", errors="ignore")[:max_len]
    hex_bytes = " ".join(f"{byte:02x}" for byte in b)
    return f"{{ {hex_bytes} }}"

def is_benign_string(s: str) -> bool:
    if not s:
        return True
    low = s.lower()
    benign_keywords = [
        "microsoft", "windows", "dll", "notepad", "explorer",
        "this program cannot be run in dos mode", "placeholder", "sample"
    ]
    for w in benign_keywords:
        if w in low:
            return True
    if len(low) < 3:
        return True
    return False

class HAClient:
    def __init__(self, api_key: str, dry_run: bool = False, cache_dir: str = ".cache_ha"):
        self.api_key = api_key
        self.dry_run = dry_run
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
    def fetch_families(self, limit: int = 5) -> List[str]:
        if self.dry_run:
            return ["familyA", "familyB", "familyC"][:limit]
        url = f"{API_ENDPOINT_BASE}/families"
        print(f"[DEBUG] HA URL: {url}", file=sys.stderr)
        try:
            # First try Bearer token (common pattern)
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.api_key}", "User-Agent": "copilot-hatoyara/1.0"})
            opener = globals().get("GLOBAL_OPENER")
            if opener is not None:
                with opener.open(req, timeout=15) as resp:
                    data = json.load(resp)
            else:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.load(resp)
        except Exception:
            try:
                # Fallback: API key header
                req = urllib.request.Request(url, headers={"X-API-Key": f"{self.api_key}", "Accept": "application/json", "User-Agent": "copilot-hatoyara/1.0"})
                opener = globals().get("GLOBAL_OPENER")
                if opener is not None:
                    with opener.open(req, timeout=15) as resp:
                        data = json.load(resp)
                else:
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        data = json.load(resp)
            except Exception as e:
                print(f"[WARN] failed to fetch families: {e}", file=sys.stderr)
                return []
        families = [f.get("name","unknown") for f in data.get("families", [])]
        return families[:limit]
    def fetch_samples_for_family(self, family: str, limit: int = 15) -> List[Dict[str, Any]]:
        if self.dry_run:
            sample = {
                "sha256": "deadbeef" * 4,
                "first_seen": "2025-12-01",
                "sample_strings": ["SuspiciousStringA", "ImportantFile.exe", "config.ini"],
                "file_names": ["payload.dll", "readme.txt"],
                "domains": ["example.com", "bad-domain.net"],
                "ips": ["8.8.8.8", "192.0.2.1"],
                "threat_score": 65,
                "mitre_techniques": ["TA0001", "TA0002"],
                "target_url": "http://ha.example"
            }
            return [sample]
        url = f"{API_ENDPOINT_BASE}/families/{family}/samples"
        print(f"[DEBUG] HA URL: {url}", file=sys.stderr)
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.api_key}", "User-Agent": "copilot-hatoyara/1.0"})
            opener = globals().get("GLOBAL_OPENER")
            if opener is not None:
                with opener.open(req, timeout=20) as resp:
                    data = json.load(resp)
            else:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    data = json.load(resp)
        except Exception:
            try:
                req = urllib.request.Request(url, headers={"X-API-Key": f"{self.api_key}", "Accept": "application/json", "User-Agent": "copilot-hatoyara/1.0"})
                opener = globals().get("GLOBAL_OPENER")
                if opener is not None:
                    with opener.open(req, timeout=20) as resp:
                        data = json.load(resp)
                else:
                    with urllib.request.urlopen(req, timeout=20) as resp:
                        data = json.load(resp)
            except Exception as e:
                print(f"[WARN] failed to fetch samples for {family}: {e}", file=sys.stderr)
                return []
        return data.get("samples", [])[:limit]

def deduplicate_signals_by_family(samples: List[Dict[str, Any]]) -> Dict[str, int]:
    freq: Dict[str, int] = {}
    for s in samples:
        signals = set()
        for sig in s.get("sample_strings", []) + s.get("file_names", []):
            if is_benign_string(sig):
                continue
            signals.add(sig)
        for sig in signals:
            freq[sig] = freq.get(sig, 0) + 1
    return freq

def generate_yara_for_family(family: str, samples: List[Dict[str, Any]], threshold: float = 0.7, min_signals: int = 3) -> str:
    per_sig: Dict[str, int] = deduplicate_signals_by_family(samples)
    if not per_sig:
        return ""
    total_samples = len(samples)
    sorted_signals = sorted(per_sig.items(), key=lambda kv: kv[1], reverse=True)
    chosen: List[str] = []
    for sig, count in sorted_signals:
        if count / max(1, total_samples) >= threshold or len(chosen) < min_signals:
            chosen.append(sig)
        if len(chosen) >= max(min_signals, int(len(sorted_signals) * (threshold if threshold>0 else 0.5))):
            break
    if len(chosen) < min_signals:
        chosen = [s for s, c in sorted_signals[:min_signals]]
    hex_strings = []
    for idx, s in enumerate(chosen, 1):
        hex_strings.append(f"$sig{idx} = {string_to_hex_literal(s)}")
    additional = []
    for s in set(s for samp in samples for s in samp.get("file_names", []) if not is_benign_string(s)):
        additional.append(f"$file{len(additional)+1} = {string_to_hex_literal(s)}")
    lines = []
    lines.extend(hex_strings)
    lines.extend(additional)
    header = f"rule HA_{family}_signals\n{{\n  meta:\n    description = \"Derived from samples for {family}\"\n  strings:\n"
    for line in lines:
        linestr = f"    {line}"
        header += linestr + "\n"
    header += "  condition:\n    any of them\n"
    header += f"  // provenance: sample_count={total_samples}, first_sha256={samples[0]['sha256'] if samples else '—'}, first_seen={samples[0]['first_seen'] if samples else '—'}, threat_score={samples[0]['threat_score'] if samples else '—'}, mitre_techniques={', '.join(samples[0]['mitre_techniques']) if samples and samples[0].get('mitre_techniques') else '—'}, target_url={samples[0]['target_url'] if samples else '—'}\n"
    header += "}\n"
    return header

def generate_sigma_for_family(family: str, samples: List[Dict[str, Any]]) -> str:
    domains = set()
    ips = set()
    for s in samples:
        for d in s.get("domains", []):
            domains.add(d)
        for ip in s.get("ips", []):
            ips.add(ip)
    lines = []
    if domains:
        lines.append("title: HA Family IOC - %s" % family)
        lines.append("logsource:")
        lines.append("  product: generic")
        lines.append("detection:")
        lines.append("  selection:")
        lines.append("    Domain: " + ", ".join(sorted(domains)))
        lines.append("  condition: Domain")
    if ips:
        lines.append("  DestinationIP: " + ", ".join(sorted(ips)))
    return "\n".join(lines) + "\n" if lines else ""

def generate_suricata_for_family(family: str, samples: List[Dict[str, Any]]) -> str:
    rules = []
    sid = 100000
    for d in set(d for s in samples for d in s.get("domains", [])):
        if d.strip():
            rules.append(f"alert http any any -> any any (msg:'HA IOC Domain {d}'; flow: to_server; content:\"{d}\"; nocase; sid:{sid}; rev:1)")
            sid += 1
    for ip in set(ip for s in samples for ip in s.get("ips", [])):
        if ip.strip():
            rules.append(f"alert ip any any -> {ip} any (msg:'HA IOC IP {ip}'; sid:{sid}; rev:1)")
            sid += 1
    return "\n".join(rules) + ("\n" if rules else "")

def main():
    parser = argparse.ArgumentParser(description="Inline copilot-hatoyara: HA -> YARA/Sigma/Suricata")
    parser.add_argument("--api-key", "-k", help="HA API key (or set HA_API_KEY env var)")
    parser.add_argument("--dry-run", action="store_true", help="Use embedded sample data only")
    parser.add_argument("--limit-families", type=int, default=3, help="Max families to process")
    parser.add_argument("--max-samples", type=int, default=15, help="Max samples per family")
    parser.add_argument("--output-dir", default="rules", help="Output root directory")
    parser.add_argument("--threshold", type=float, default=0.7, help="YARA signal threshold (0-1)")
    parser.add_argument("--min-signals", type=int, default=3, help="Minimum signals to include")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("HA_API_KEY", "")
    if not api_key and not args.dry_run:
        print("Error: API key required unless --dry-run is set.", file=sys.stderr)
        sys.exit(2)

    client = HAClient(api_key, dry_run=args.dry_run)
    families = client.fetch_families(limit=args.limit_families)
    if not families:
        print("No families found. Exiting.", file=sys.stderr)
        sys.exit(0)
    os.makedirs(args.output_dir, exist_ok=True)

    for family in families:
        samples = client.fetch_samples_for_family(family, limit=args.max_samples)
        if not samples:
            print(f"Skipping {family}: no samples", file=sys.stderr)
            continue
        yara = generate_yara_for_family(family, samples, threshold=args.threshold, min_signals=args.min_signals)
        if yara:
            yara_dir = os.path.join(args.output_dir, "yara")
            os.makedirs(yara_dir, exist_ok=True)
            path = os.path.join(yara_dir, f"{family}.yar")
            with open(path, "w", encoding="ascii") as f:
                f.write(yara)
        sigma = generate_sigma_for_family(family, samples)
        if sigma:
            sigma_dir = os.path.join(args.output_dir, "sigma")
            os.makedirs(sigma_dir, exist_ok=True)
            path = os.path.join(sigma_dir, f"{family}.yml")
            with open(path, "w", encoding="utf-8") as f:
                f.write(sigma)
        suri = generate_suricata_for_family(family, samples)
        if suri:
            suri_dir = os.path.join(args.output_dir, "suricata")
            os.makedirs(suri_dir, exist_ok=True)
            path = os.path.join(suri_dir, f"{family}.rules")
            with open(path, "w", encoding="utf-8") as f:
                f.write(suri)
        print(f"Wrote outputs for {family}")

if __name__ == "__main__":
    main()
