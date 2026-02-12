rule CobaltStrike_Artifact_c10331f3
{
    meta:
        sha256 = "c10331f3a75844944cf91fd8441be8001f5b94d245ff9bfb16702bcdfbb5807b"
        family = "CobaltStrike.Artifact"
        threat_score = "100"
        first_seen = "2026-02-12T01:48:02+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/c10331f3a75844944cf91fd8441be8001f5b94d245ff9bfb16702bcdfbb5807b"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 30 30 30 30 30 30 30 30 2d 30 30 30 30 34 34 35 36 2c 63 31 30 33 33 31 66 33 61 37 35 38 34 34 39 34 34 63 66 39 31 66 64 38 34 34 31 62 65 38 30 30 31 66 35 62 39 34 64 32 34 35 66 66 39 62 66 62 31 36 37 30 32 62 63 64 66 62 62 35 38 30 37 62 2e 62 69 6e 2e 65 78 65 2c 22 43 3a 5c 63 31 30 33 33 31 66 33 61 37 35 38 34 34 39 34 34 63 66 39 31 66 64 38 34 34 31 62 65 38 30 30 31 66 35 62 39 34 64 32 34 35 66 66 39 62 66 62 31 36 37 30 32 62 63 64 66 62 62 35 38 30 37 62 2e 62 69 6e 2e 65 78 65 22 2c 34 34 35 36 2c 37 36 34 38 2c 32 30 32 36 2d 32 2d 31 32 2e 30 31 3a 34 38 3a 32 38 2e 32 31 37 2c 22 22 }
        $s1 = { 5c 5c 2e 5c 70 69 70 65 5c 4d 53 53 45 2d 34 36 31 38 2d 73 65 72 76 65 72 }

    condition:
        1 of ($*)
}
