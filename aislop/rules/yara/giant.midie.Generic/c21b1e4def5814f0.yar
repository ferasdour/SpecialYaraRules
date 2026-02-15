rule giant.midie.Generic_family
{
    meta:
        description = "Auto-generated YARA rule for giant.midie.Generic"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "c21b1e4def5814f0a3f3423ab854b1b76fb0cfb931815de8aa12e4a59b678bdc"
        first_seen = "2026-02-15T01:19:45+00:00"
        threat_score = "100"
        mitre_techniques = "Gather Victim Network Information, Native API, Inter-Process Communication, JavaScript, Windows Command Shell"
        target_url = "none"

    strings:
        $fn0 = "DW20.EXE"
        $fn1 = "DWTRIG20.EXE"
        $fn2 = "RCX4BB2.tmp"
        $fn3 = "MSOXMLED.EXE"
        $fn4 = "Oarpmany.exe"
        $fn5 = "RCX4E24.tmp"
        $fn6 = "RCX4FBB.tmp"
        $fn7 = "VSTOInstaller.exe"

    condition:
        6 of them
}
