rule W32_Evo_6dbb91ba
{
    meta:
        sha256 = "6dbb91baec0a7bbbf6f003cc571f8955b9a246198106fa7387e7e997c2d5410e"
        family = "W32.Evo"
        threat_score = "85"
        first_seen = "2026-02-12T01:55:39+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/6dbb91baec0a7bbbf6f003cc571f8955b9a246198106fa7387e7e997c2d5410e"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 30 30 30 30 30 30 30 30 2d 30 30 30 30 37 36 32 30 2c 53 46 44 46 53 44 48 46 47 2e 65 78 65 2c 22 43 3a 5c 53 46 44 46 53 44 48 46 47 2e 65 78 65 22 2c 37 36 32 30 2c 31 36 37 36 2c 32 30 32 36 2d 32 2d 31 32 2e 30 31 3a 35 36 3a 30 38 2e 32 39 39 2c 22 22 }
        $s1 = { 5c 24 34 56 57 68 }
        $s2 = { 5c 24 38 6a }
        $s3 = { 5c 52 65 67 69 73 74 72 79 5c 4d 61 63 68 69 6e 65 5c 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c }
        $s4 = { 5c 59 21 44 24 }
        $s5 = { 43 3a 5c 61 64 76 70 61 63 6b 2e 64 6c 6c }
        $s6 = { 43 3a 5c 75 73 65 72 33 32 2e 64 6c 6c }
        $s7 = { 66 31 5c 24 }
        $s8 = { 66 39 5c 24 }
        $s9 = { 66 72 66 5c }
        $s10 = { 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 }
        $s11 = { 4c 24 5c 6a }

    condition:
        9 of ($*)
}
