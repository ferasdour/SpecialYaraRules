rule phishing_family
{
    meta:
        description = "Auto-generated YARA rule for phishing"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "f1e57913b601aee578ef3d0829d45b890f9d7444fdb340c13386c5205e3b2d79"
        first_seen = "2026-02-15T00:56:15+00:00"
        threat_score = "79"

    strings:
        $d0 = "skinnycrawlinglax.com"
        $d1 = "cdn.storageimagedisplay.com"
        $h0 = "172.240.108.84"
        $h1 = "45.133.44.1"

    condition:
        3 of them
}
