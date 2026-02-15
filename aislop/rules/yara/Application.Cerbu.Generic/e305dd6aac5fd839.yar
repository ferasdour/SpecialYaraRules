rule Application.Cerbu.Generic_family
{
    meta:
        description = "Auto-generated YARA rule for Application.Cerbu.Generic"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "e305dd6aac5fd8399fd390b9a99dd0f6395689eb542bdd3016abf2b9b54cbffd"
        first_seen = "2026-02-15T00:57:41+00:00"
        threat_score = "89"

    strings:
        $d0 = "controlprice.xyz"
        $h0 = "172.67.217.46"
        $fn0 = "is-XJ0BP2K2T5.tmp"
        $fn1 = "e305dd6aac5fd8399fd390b9a99dd0f6395689eb542bdd3016abf2b9b54cbffd.bin.tmp"
        $fn2 = "unins000.dat"
        $fn3 = "_setup64.tmp"
        $fn4 = "is-QOOIOOP2RP.tmp"

    condition:
        5 of them
}
