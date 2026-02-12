rule evasive_9b99a541
{
    meta:
        sha256 = "9b99a5416d066728c54acb840b2b37d8b987f56e83f98d576c544cb3c362a856"
        family = "evasive"
        threat_score = "unknown"
        first_seen = "2026-02-12T01:31:45+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/9b99a5416d066728c54acb840b2b37d8b987f56e83f98d576c544cb3c362a856"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 30 30 30 30 30 30 30 30 2d 30 30 30 30 33 39 39 36 2c 33 36 30 53 61 66 65 2e 65 78 65 2c 22 43 3a 5c 33 36 30 53 61 66 65 2e 65 78 65 22 2c 33 39 39 36 2c 31 33 39 32 2c 32 30 32 36 2d 32 2d 31 32 2e 30 31 3a 33 32 3a 31 31 2e 35 31 34 2c 22 22 }
        $s1 = { 22 5c 33 36 30 53 61 66 65 2e 65 78 65 22 20 25 31 }
        $s2 = { 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 6e 74 64 6c 6c 2e 64 6c 6c }
        $s3 = { 43 3a 5c 33 36 30 42 61 73 65 2e 64 6c 6c }

    condition:
        3 of ($*)
}
