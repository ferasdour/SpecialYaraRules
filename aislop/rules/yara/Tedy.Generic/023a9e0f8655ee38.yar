rule Tedy.Generic_family
{
    meta:
        description = "Auto-generated YARA rule for Tedy.Generic"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "023a9e0f8655ee38c53b1fcca3c746d28a531924d00c27b40f3284fc799d6ee2"
        first_seen = "2026-02-15T01:21:02+00:00"
        threat_score = "100"
        mitre_techniques = "Gather Victim Network Information, Domains, Digital Certificates, Phishing, Native API"
        target_url = "none"

    strings:
        $d0 = "parse.lxown.com"
        $h0 = "61.241.148.77"
        $fn0 = "Lx7z.dll"

    condition:
        2 of them
}
