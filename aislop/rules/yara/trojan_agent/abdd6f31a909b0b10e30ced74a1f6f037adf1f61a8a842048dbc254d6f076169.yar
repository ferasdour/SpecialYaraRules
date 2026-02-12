rule Trojan_Agent_abdd6f31
{
    meta:
        sha256 = "abdd6f31a909b0b10e30ced74a1f6f037adf1f61a8a842048dbc254d6f076169"
        family = "Trojan.Agent"
        threat_score = "80"
        first_seen = "2026-02-12T00:58:20+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/abdd6f31a909b0b10e30ced74a1f6f037adf1f61a8a842048dbc254d6f076169"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 30 30 30 30 30 30 30 30 2d 30 30 30 30 36 35 39 32 2c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 2c 22 25 57 49 4e 44 49 52 25 5c 53 79 73 57 4f 57 36 34 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 22 2c 36 35 39 32 2c 35 31 36 38 2c 32 30 32 36 2d 32 2d 31 32 2e 30 30 3a 35 38 3a 34 36 2e 33 30 34 2c 22 22 43 3a 5c 61 62 64 64 36 66 33 31 61 39 30 39 62 30 62 31 30 65 33 30 63 65 64 37 34 61 31 66 36 66 30 33 37 61 64 66 31 66 36 31 61 38 61 38 34 32 30 34 38 64 62 63 32 35 34 64 36 66 30 37 36 31 36 39 2e 64 6c 6c 22 2c 23 31 22 }
        $s1 = { 72 75 6e 64 6c 6c 33 32 }
        $s2 = { 72 75 6e 64 6c 6c 33 32 2e 65 78 65 }

    condition:
        2 of ($*)
}
