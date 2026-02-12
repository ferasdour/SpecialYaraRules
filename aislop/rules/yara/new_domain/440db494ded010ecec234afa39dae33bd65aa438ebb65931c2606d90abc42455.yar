rule new_domain_440db494
{
    meta:
        sha256 = "440db494ded010ecec234afa39dae33bd65aa438ebb65931c2606d90abc42455"
        family = "new_domain"
        threat_score = "97"
        first_seen = "2026-02-12T00:30:09+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/440db494ded010ecec234afa39dae33bd65aa438ebb65931c2606d90abc42455"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 2f 76 62 2f 70 6f 77 65 72 73 68 65 6c 6c 73 63 61 6e 6e 65 72 2f }
        $s1 = { 52 65 66 65 72 65 72 3a 20 68 74 74 70 73 3a 2f 2f 6e 6f 63 68 65 61 74 2e 69 63 75 2f 76 62 2f 70 6f 77 65 72 73 68 65 6c 6c 73 63 61 6e 6e 65 72 2f }
        $s2 = { 47 45 54 20 2f 76 62 2f 70 6f 77 65 72 73 68 65 6c 6c 73 63 61 6e 6e 65 72 2f 20 48 54 54 50 2f 31 2e 31 }

    condition:
        2 of ($*)
}
