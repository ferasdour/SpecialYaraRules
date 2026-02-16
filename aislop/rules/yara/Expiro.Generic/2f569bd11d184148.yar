rule Expiro.Generic_family
{
    meta:
        description = "Auto-generated YARA rule for Expiro.Generic"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "2f569bd11d184148b2cf089241e01009456a6e200647e41ad191843fa60e35be"
        first_seen = "2026-02-16T01:52:24+00:00"
        threat_score = "100"
        mitre_techniques = "Domains; Phishing; Native API; Windows Command Shell; Inter-Process Communication"

    strings:
        $s0 = "57 69 6e 64 6f 77 73 2e 65 64 62"
        $s1 = "66 61 34 39 39 32 36 61 32 35 63 33 33 65 66 38 2e 62 69 6e"
        $s2 = "51 75 61 6c 63 6f 6d 6d 57 69 6e 64 6f 77 73 44 72 69 76 65 72 49 6e 73 74 61 6c 6c 65 72 2e 6d 73 69"
        $s3 = "73 65 74 75 70 2e 69 6e 78"

    condition:
        3 of them
}