rule Win_malicious_confidence_100__family
{
    meta:
        description = "Auto-generated YARA rule for Win_malicious_confidence_100_"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "4"
        first_sha256 = "bd69ec91d6857c5987c501f91aa37dc1cf80b79f1d24c1b680bd47d1ea935adc"
        first_seen = "2026-02-15T01:09:32+00:00"
        threat_score = "100"

    strings:
        $d0 = "batyatj6.beget.tech"
        $fn0 = "SppExtComObj.exe"

    condition:
        any of them
}
