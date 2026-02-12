rule Trojan_Sysin_e7d91812
{
    meta:
        sha256 = "e7d9181211b276a3581fe71d07908a2745a65399d3b606a7f4a6477b523e399f"
        family = "Trojan.Sysin"
        threat_score = "72"
        first_seen = "2026-02-12T00:26:23+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/e7d9181211b276a3581fe71d07908a2745a65399d3b606a7f4a6477b523e399f"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 30 30 30 30 30 30 30 30 2d 30 30 30 30 35 31 31 32 2c 50 41 49 4e 45 4c 2e 65 78 65 2c 22 43 3a 5c 50 41 49 4e 45 4c 2e 65 78 65 22 2c 35 31 31 32 2c 31 34 38 34 2c 32 30 32 36 2d 32 2d 31 32 2e 30 30 3a 32 36 3a 34 39 2e 39 39 39 2c 22 22 }
        $s1 = { 43 3a 5c 50 41 49 4e 45 4c 2e 65 78 65 }

    condition:
        1 of ($*)
}
