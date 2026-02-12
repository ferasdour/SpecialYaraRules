rule AGEN_1318206_f70e5ccd
{
    meta:
        sha256 = "f70e5ccd2342b8ffc713d0a9bcdee1275721ebd545b44b60df1fdf575fe24103"
        family = "AGEN.1318206"
        threat_score = "82"
        first_seen = "2026-02-12T01:54:55+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/f70e5ccd2342b8ffc713d0a9bcdee1275721ebd545b44b60df1fdf575fe24103"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 30 30 30 30 30 30 30 30 2d 30 30 30 30 37 36 36 34 2c 66 37 30 65 35 63 63 64 32 33 34 32 62 38 66 66 63 37 31 33 64 30 61 39 62 63 64 65 65 31 32 37 35 37 32 31 65 62 64 35 34 35 62 34 34 62 36 30 64 66 31 66 64 66 35 37 35 66 65 32 34 31 30 33 2e 62 69 6e 2e 65 78 65 2c 22 43 3a 5c 66 37 30 65 35 63 63 64 32 33 34 32 62 38 66 66 63 37 31 33 64 30 61 39 62 63 64 65 65 31 32 37 35 37 32 31 65 62 64 35 34 35 62 34 34 62 36 30 64 66 31 66 64 66 35 37 35 66 65 32 34 31 30 33 2e 62 69 6e 2e 65 78 65 22 2c 37 36 36 34 2c 36 38 36 34 2c 32 30 32 36 2d 32 2d 31 32 2e 30 31 3a 35 35 3a 32 32 2e 32 34 32 2c 22 22 }
        $s1 = { 5c 24 20 48 3d }

    condition:
        1 of ($*)
}
