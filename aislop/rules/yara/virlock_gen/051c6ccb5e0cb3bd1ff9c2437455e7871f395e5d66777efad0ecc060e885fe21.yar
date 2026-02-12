rule Virlock_Gen_051c6ccb
{
    meta:
        sha256 = "051c6ccb5e0cb3bd1ff9c2437455e7871f395e5d66777efad0ecc060e885fe21"
        family = "Virlock.Gen"
        threat_score = "100"
        first_seen = "2026-02-12T01:53:00+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/051c6ccb5e0cb3bd1ff9c2437455e7871f395e5d66777efad0ecc060e885fe21"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 30 30 30 30 30 30 30 30 2d 30 30 30 30 36 30 31 32 2c 30 35 31 63 36 63 63 62 35 65 30 63 62 33 62 64 31 66 66 39 63 32 34 33 37 34 35 35 65 37 38 37 31 66 33 39 35 65 35 64 36 36 37 37 37 65 66 61 64 30 65 63 63 30 36 30 65 38 38 35 66 65 32 31 2e 62 69 6e 2e 65 78 65 2c 22 43 3a 5c 30 35 31 63 36 63 63 62 35 65 30 63 62 33 62 64 31 66 66 39 63 32 34 33 37 34 35 35 65 37 38 37 31 66 33 39 35 65 35 64 36 36 37 37 37 65 66 61 64 30 65 63 63 30 36 30 65 38 38 35 66 65 32 31 2e 62 69 6e 2e 65 78 65 22 2c 36 30 31 32 2c 33 34 38 34 2c 32 30 32 36 2d 32 2d 31 32 2e 30 31 3a 35 33 3a 32 39 2e 30 33 33 2c 22 22 }
        $s1 = { 31 37 5b 5c 71 }
        $s2 = { 5c 60 60 2f }
        $s3 = { 5f 46 5c 37 }
        $s4 = { 41 79 55 5c 5b 39 }
        $s5 = { 68 5c 61 3c }
        $s6 = { 6e 39 5c 3b }
        $s7 = { 72 6e 5c 59 }

    condition:
        6 of ($*)
}
