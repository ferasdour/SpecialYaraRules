#!/usr/bin/env python3
from typing import List, Tuple, Optional
import math

def to_hex(s: str) -> str:
    return " ".join(f"{b:02x}" for b in s.encode('utf-8', errors='ignore'))

def is_benign_string(s: str) -> bool:
    low = s.lower()
    if len(s) < 4:
        return True
    if any(x in low for x in ["http", "://", ".exe", ".dll"]):
        return True
    return False

def compute_threshold(n: int, pct: float = 0.6, min_strings: int = 3) -> int:
    # Use a slightly lower threshold for smaller rule fingerprints
    t = max(min_strings, int(math.ceil(n * pct)))
    return t

def generate_family_yara_from_strings(family: str, sample_strings: List[str], sample_files: List[str], domains: List[str], ips: List[str], first_sha: str, first_seen: str, threat: int, mitre_techniques: List[str]) -> Optional[Tuple[str, str]]:
    # Collect candidate strings
    cands: List[str] = []
    for s in (sample_strings or []):
        if s and not is_benign_string(s):
            cands.append(s)
    for f in (sample_files or []):
        if f and not is_benign_string(f):
            cands.append(f)
    uniq = []
    seen = set()
    for s in cands:
        if s not in seen:
            uniq.append(s); seen.add(s)
    uniq = uniq[:12]
    if len(uniq) < 3:
        return None

    str_lines = []
    for i, s in enumerate(uniq):
        str_lines.append(f'        $s{i} = "{to_hex(s)}"')

    # Dynamic threshold: if there are many candidates, use 70%; if few, use 60%
    threshold = compute_threshold(len(str_lines), 0.7 if len(str_lines) >= 6 else 0.6)
    rule = f'''rule {family}_family
{{
    meta:
        description = "Auto-generated YARA rule for {family}"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "{first_sha}"
        first_seen = "{first_seen}"
        threat_score = "{threat}"
        mitre_techniques = "{'; '.join(mitre_techniques)}"

    strings:
{chr(10).join(str_lines)}

    condition:
        {threshold} of them
}}'''
    return rule, family
