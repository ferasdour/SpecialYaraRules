rule evasive_family
{
    meta:
        description = "Auto-generated YARA rule for evasive"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "bdedc135923d4fa7a48a0dc850cea43818a825270c89be2b047d51c4d436e746"
        first_seen = "2026-02-16T01:42:15+00:00"
        threat_score = "100"
        mitre_techniques = "Gather Victim Network Information; Domains; Native API; At; Windows Command Shell; Phishing"

    strings:
        $s0 = "4f 57 49 6e 73 74 61 6c 6c 2e 6c 6f 67"
        $s1 = "53 65 74 74 69 6e 67 73 50 61 67 65 42 61 73 69 63 2e 78 6d 6c"
        $s2 = "6d 65 73 73 61 67 65 73 2e 6a 73 6f 6e"
        $s3 = "78 61 74 74 72 2e 64 61 72 77 69 6e 2d 61 72 6d 36 34 2e 6e 6f 64 65"
        $s4 = "78 61 74 74 72 2e 64 61 72 77 69 6e 2d 78 36 34 2e 6e 6f 64 65"
        $s5 = "47 72 61 6e 6f 6c 61 2e 6c 6e 6b"
        $s6 = "4c 49 43 45 4e 53 45 53 2e 63 68 72 6f 6d 69 75 6d 2e 68 74 6d 6c"
        $s7 = "67 72 61 70 68 2e 73 76 67"
        $s8 = "63 72 79 70 74 33 32 2d 69 61 33 32 2e 6e 6f 64 65"
        $s9 = "63 72 79 70 74 33 32 2d 78 36 34 2e 6e 6f 64 65"
        $s10 = "69 63 6f 6e 44 65 76 54 65 6d 70 6c 61 74 65 2e 70 64 66"
        $s11 = "69 63 6f 6e 54 65 6d 70 6c 61 74 65 2e 70 64 66"

    condition:
        9 of them
}