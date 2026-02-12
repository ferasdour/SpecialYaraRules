rule AVI_PWS_Agent_c6e75a23
{
    meta:
        sha256 = "c6e75a23e453ec38473ff4768cd1a7eced35fbfbee78e318e054f1b61d597fd2"
        family = "AVI.PWS.Agent"
        threat_score = "87"
        first_seen = "2026-02-12T03:27:01+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/c6e75a23e453ec38473ff4768cd1a7eced35fbfbee78e318e054f1b61d597fd2"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 30 30 30 30 30 30 30 30 2d 30 30 30 30 32 39 32 38 2c 63 36 65 37 35 61 32 33 65 34 35 33 65 63 33 38 34 37 33 66 66 34 37 36 38 63 64 31 61 37 65 63 65 64 33 35 66 62 66 62 65 65 37 38 65 33 31 38 65 30 35 34 66 31 62 36 31 64 35 39 37 66 64 32 2e 62 69 6e 2e 65 78 65 2c 22 43 3a 5c 63 36 65 37 35 61 32 33 65 34 35 33 65 63 33 38 34 37 33 66 66 34 37 36 38 63 64 31 61 37 65 63 65 64 33 35 66 62 66 62 65 65 37 38 65 33 31 38 65 30 35 34 66 31 62 36 31 64 35 39 37 66 64 32 2e 62 69 6e 2e 65 78 65 22 2c 32 39 32 38 2c 33 35 38 30 2c 32 30 32 36 2d 32 2d 31 32 2e 30 33 3a 32 37 3a 32 36 2e 39 35 39 2c 22 22 }
        $s1 = { 25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 5c 72 6b 4c 52 58 }
        $s2 = { 35 5c 21 24 }
        $s3 = { 3d 5c 79 25 }

    condition:
        3 of ($*)
}
