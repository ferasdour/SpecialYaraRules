rule Packed_Themida_64151759
{
    meta:
        sha256 = "64151759dad12f0395e7e1354cd1fad6b2b4955f39343bbf5bcc0cfde4da2331"
        family = "Packed.Themida"
        threat_score = "83"
        first_seen = "2026-02-12T00:13:26+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/64151759dad12f0395e7e1354cd1fad6b2b4955f39343bbf5bcc0cfde4da2331"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 30 30 30 30 30 30 30 30 2d 30 30 30 30 36 36 35 32 2c 56 6f 69 64 2e 65 78 65 2c 22 43 3a 5c 56 6f 69 64 2e 65 78 65 22 2c 36 36 35 32 2c 37 32 33 36 2c 32 30 32 36 2d 32 2d 31 32 2e 30 30 3a 31 34 3a 30 38 2e 38 34 33 2c 22 22 }
        $s1 = { 6a 5c 42 5a }

    condition:
        1 of ($*)
}
