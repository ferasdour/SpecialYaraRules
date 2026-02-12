rule proximity_f74d773a
{
    meta:
        sha256 = "f74d773ab016fb90be755586c12d9f6e23d690282256d9b39817bd2355a3b791"
        family = "proximity"
        threat_score = "78"
        first_seen = "2026-02-12T00:18:09+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/f74d773ab016fb90be755586c12d9f6e23d690282256d9b39817bd2355a3b791"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 36 4b 5c 4a 78 22 }
        $s1 = { 3f 79 2a 5c 4d }
        $s2 = { 40 6a 28 71 5c 68 27 }
        $s3 = { 52 65 66 65 72 65 72 3a 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 73 6f 66 74 6f 6e 69 63 2e 63 6f 6d 2f }
        $s4 = { 4f 72 69 67 69 6e 3a 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 73 6f 66 74 6f 6e 69 63 2e 63 6f 6d }
        $s5 = { 70 39 5c 4d 6d }
        $s6 = { 47 7b 5c 78 6f }
        $s7 = { 41 60 5c 55 6f }
        $s8 = { 5f 73 77 5c }
        $s9 = { 21 6c 35 35 5c }
        $s10 = { 5a 5c 40 24 4c 2f }
        $s11 = { 41 68 30 5c 46 59 }
        $s12 = { 5c 49 28 6c }
        $s13 = { 24 51 5c 59 }
        $s14 = { 68 5c 73 47 }
        $s15 = { 72 3d 5c 27 4c 2f }
        $s16 = { 74 67 5c 5a }
        $s17 = { 5c 34 38 75 26 69 }
        $s18 = { 58 78 5c 7c }
        $s19 = { 22 25 5c 47 }
        $s20 = { 4c 48 70 4b 6e 5c 4c }
        $s21 = { 4b 78 5c 32 45 3e 26 }
        $s22 = { 5d 5c 76 6c }
        $s23 = { 5c 21 60 78 }
        $s24 = { 31 29 5c 5c }
        $s25 = { 5c 7b 6f 7b 41 }
        $s26 = { 68 5c 42 51 43 }
        $s27 = { 4e 62 72 5c 31 2d 5c }
        $s28 = { 6c 64 47 24 69 5c }
        $s29 = { 4e 5c 41 47 }
        $s30 = { 55 5f 6c 5c 27 69 6b }
        $s31 = { 28 5c 28 23 }
        $s32 = { 3d 2a 4a 6d 5c 4a 35 }
        $s33 = { 53 67 67 3b 3f 55 67 59 38 52 5c }
        $s34 = { 76 37 2e 5c 2c 67 }
        $s35 = { 7e 5c 6b 79 25 }

    condition:
        28 of ($*)
}
