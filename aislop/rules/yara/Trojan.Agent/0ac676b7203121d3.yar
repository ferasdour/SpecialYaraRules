rule Trojan.Agent_family
{
    meta:
        description = "Auto-generated YARA rule for Trojan.Agent"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "5"
        first_sha256 = "0ac676b7203121d3bf34fdb9e7d4328c306c7dd0675bced514249293f9b55440"
        first_seen = "2026-02-15T01:31:30+00:00"
        threat_score = "100"
        mitre_techniques = "Native API, Windows Management Instrumentation, Windows Command Shell, Service Execution, PowerShell"
        target_url = "none"

    strings:
        $d0 = "batyatj6.beget.tech"
        $fn0 = "SppExtComObj.exe"

    condition:
        any of them
}
