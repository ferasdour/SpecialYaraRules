rule evasive_family
{
    meta:
        description = "Auto-generated YARA rule for evasive"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "bec9fe3c3582151a8c47bb8610b64be96f5b9aea3bb6b3318aa7229854c6ab20"
        first_seen = "2026-02-16T01:58:37+00:00"
        threat_score = "100"
        mitre_techniques = "Native API; Windows Management Instrumentation; Windows Command Shell; PowerShell; Service Execution; Gather Victim Network Information; Domains; Phishing"

    strings:
        $s0 = "53 74 61 72 74 75 70 50 72 6f 66 69 6c 65 44 61 74 61 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65"
        $s1 = "78 61 74 74 72 2e 64 61 72 77 69 6e 2d 61 72 6d 36 34 2e 6e 6f 64 65"
        $s2 = "78 61 74 74 72 2e 64 61 72 77 69 6e 2d 78 36 34 2e 6e 6f 64 65"
        $s3 = "47 72 61 6e 6f 6c 61 2e 6c 6e 6b"
        $s4 = "4c 49 43 45 4e 53 45 53 2e 63 68 72 6f 6d 69 75 6d 2e 68 74 6d 6c"
        $s5 = "67 72 61 70 68 2e 73 76 67"
        $s6 = "63 72 79 70 74 33 32 2d 69 61 33 32 2e 6e 6f 64 65"
        $s7 = "63 72 79 70 74 33 32 2d 78 36 34 2e 6e 6f 64 65"
        $s8 = "69 63 6f 6e 44 65 76 54 65 6d 70 6c 61 74 65 2e 70 64 66"
        $s9 = "69 63 6f 6e 54 65 6d 70 6c 61 74 65 2e 70 64 66"
        $s10 = "76 69 64 65 6f 46 61 6c 6c 62 61 63 6b 49 63 6f 6e 2e 73 76 67"

    condition:
        8 of them
}