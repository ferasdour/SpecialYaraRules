rule unknown_family
{
    meta:
        description = "Auto-generated YARA rule for unknown"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "61b76b7b90ee2e91e43d2883582d45425ebf4127645290edde82168d3573c4c6"
        first_seen = "2026-02-16T01:37:52+00:00"
        threat_score = "80"
        mitre_techniques = "Native API; Windows Command Shell; Shared Modules; Windows Service; Create or Modify System Process; Digital Certificates; Inter-Process Communication; Service Execution"

    strings:
        $s0 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 32 36 2d 33 38 32 2d 37 36 31 36"
        $s1 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 34 30 2d 30 38 35 2d 37 34 33 36"
        $s2 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 34 36 2d 36 34 37 2d 37 35 35 32"
        $s3 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 34 36 2d 39 37 35 2d 37 35 35 32"
        $s4 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 34 37 2d 32 35 37 2d 37 35 35 32"
        $s5 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 34 37 2d 37 32 35 2d 37 35 35 32"
        $s6 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 35 30 2d 37 35 37 2d 37 36 31 36"
        $s7 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 35 32 2d 38 31 39 2d 39 34 38"
        $s8 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 35 32 2d 38 36 36 2d 37 36 33 32"
        $s9 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 35 34 2d 35 32 32 2d 33 38 34 38"
        $s10 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 34 2d 35 34 2d 39 32 39 2d 39 34 38"
        $s11 = "44 72 6f 70 62 6f 78 55 70 64 61 74 65 2e 6c 6f 67 2d 32 30 32 36 2d 30 32 2d 31 36 2d 30 39 2d 33 35 2d 33 32 2d 32 33 32 2d 31 33 30 30"

    condition:
        9 of them
}