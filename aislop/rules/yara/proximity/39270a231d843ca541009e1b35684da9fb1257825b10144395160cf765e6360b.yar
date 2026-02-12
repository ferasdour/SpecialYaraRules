rule proximity_39270a23
{
    meta:
        sha256 = "39270a231d843ca541009e1b35684da9fb1257825b10144395160cf765e6360b"
        family = "proximity"
        threat_score = "97"
        first_seen = "2026-02-12T01:58:25+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/39270a231d843ca541009e1b35684da9fb1257825b10144395160cf765e6360b"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 44 68 27 54 5c 7d 5a }

    condition:
        1 of ($*)
}
