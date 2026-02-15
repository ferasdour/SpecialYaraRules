rule evasive_family
{
    meta:
        description = "Auto-generated YARA rule for evasive"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "53d7694d8dc639bc2fb11d2aaf75193d6b7a215d80b1ac56bd12c26df72d9840"
        first_seen = "2026-02-15T01:04:22+00:00"
        threat_score = "85"

    strings:
        $fn0 = "is-DCQ40.tmp"
        $fn1 = "is-GUQ95.tmp"
        $fn2 = "is-3OSV5.tmp"
        $fn3 = "is-5SRDI.tmp"
        $fn4 = "is-99GOO.tmp"
        $fn5 = "is-9KCVT.tmp"
        $fn6 = "is-A53DU.tmp"
        $fn7 = "is-H857D.tmp"

    condition:
        6 of them
}
