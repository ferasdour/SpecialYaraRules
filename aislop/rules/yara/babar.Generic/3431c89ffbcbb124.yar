rule babar.Generic_family
{
    meta:
        description = "Auto-generated YARA rule for babar.Generic"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "3431c89ffbcbb124f08b0d0aacfd6874886a42f96fef03b208c69be51bc1488a"
        first_seen = "2026-02-16T01:44:50+00:00"
        threat_score = "100"
        mitre_techniques = "Native API; Windows Command Shell; Shared Modules; Component Object Model; Command and Scripting Interpreter"

    strings:
        $s0 = "48 41 50 55 42 57 53 30 2e 62 61 74"
        $s1 = "48 41 50 55 42 57 53 31 2e 62 61 74"
        $s2 = "53 65 46 46 32 34 2e 74 6d 70"
        $s3 = "53 70 46 45 34 38 2e 74 6d 70"
        $s4 = "74 6d 70 31 41 33 42 2e 74 6d 70"
        $s5 = "74 6d 70 31 42 39 34 2e 74 6d 70"
        $s6 = "74 6d 70 31 42 43 34 2e 74 6d 70"
        $s7 = "74 6d 70 31 42 46 34 2e 74 6d 70"
        $s8 = "74 6d 70 31 43 34 33 2e 74 6d 70"
        $s9 = "74 6d 70 31 43 37 33 2e 74 6d 70"
        $s10 = "74 6d 70 46 39 35 35 2e 74 6d 70"

    condition:
        8 of them
}