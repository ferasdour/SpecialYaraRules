rule TrojanPSW_MSIL_Mercurial_ayf_b6e603ff
{
    meta:
        sha256 = "b6e603ff9c86fc70b132dfd9c4bab3476deb4ce86787d51941a2da0c84cc111e"
        family = "TrojanPSW.MSIL.Mercurial.ayf"
        threat_score = "72"
        first_seen = "2026-02-12T01:58:46+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/b6e603ff9c86fc70b132dfd9c4bab3476deb4ce86787d51941a2da0c84cc111e"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 30 30 30 30 30 30 30 30 2d 30 30 30 30 30 37 31 36 2c 57 69 69 2e 65 78 65 2c 22 43 3a 5c 57 69 69 2e 65 78 65 22 2c 37 31 36 2c 31 37 35 32 2c 32 30 32 36 2d 32 2d 31 32 2e 30 31 3a 35 39 3a 31 33 2e 34 37 37 2c 22 22 }
        $s1 = { 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 63 72 79 70 74 62 61 73 65 2e 64 6c 6c }
        $s2 = { 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 64 77 6d 61 70 69 2e 64 6c 6c }
        $s3 = { 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 44 58 47 49 44 65 62 75 67 2e 64 6c 6c }
        $s4 = { 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 72 69 63 68 65 64 32 30 2e 64 6c 6c }
        $s5 = { 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 72 73 61 65 6e 68 2e 64 6c 6c }
        $s6 = { 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 73 66 63 5f 6f 73 2e 64 6c 6c }
        $s7 = { 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 53 53 50 49 43 4c 49 2e 44 4c 4c }
        $s8 = { 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 55 58 54 68 65 6d 65 2e 64 6c 6c }
        $s9 = { 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 76 65 72 73 69 6f 6e 2e 64 6c 6c }
        $s10 = { 43 3a 5c 57 69 69 2e 65 78 65 }

    condition:
        8 of ($*)
}
