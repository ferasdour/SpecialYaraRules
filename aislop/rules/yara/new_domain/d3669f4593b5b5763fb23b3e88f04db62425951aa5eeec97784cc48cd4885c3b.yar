rule new_domain_d3669f45
{
    meta:
        sha256 = "d3669f4593b5b5763fb23b3e88f04db62425951aa5eeec97784cc48cd4885c3b"
        family = "new_domain"
        threat_score = "75"
        first_seen = "2026-02-12T00:30:44+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/d3669f4593b5b5763fb23b3e88f04db62425951aa5eeec97784cc48cd4885c3b"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 5c 5e 59 20 53 }
        $s1 = { 70 2f 5c 51 }

    condition:
        1 of ($*)
}
