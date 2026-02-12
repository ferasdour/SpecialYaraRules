rule proximity_93628061
{
    meta:
        sha256 = "93628061df383ca7b484b163b8c7757a3bdd295b862c2fe311c80f7aab074d99"
        family = "proximity"
        threat_score = "75"
        first_seen = "2026-02-12T02:13:59+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/93628061df383ca7b484b163b8c7757a3bdd295b862c2fe311c80f7aab074d99"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 5d 47 3d 7c 47 70 5c }

    condition:
        1 of ($*)
}
