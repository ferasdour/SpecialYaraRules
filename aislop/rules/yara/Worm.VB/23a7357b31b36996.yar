rule Worm.VB_family
{
    meta:
        description = "Auto-generated YARA rule for Worm.VB"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "23a7357b31b36996f19c012de105d99b72b1202b7a5260143356e4d806c31a81"
        first_seen = "2026-02-15T01:07:36+00:00"
        threat_score = "100"

    strings:
        $fn0 = "chrome.exe"
        $fn1 = "ACCICONS.EXE"
        $fn2 = "23a7357b31b36996f19c012de105d99b72b1202b7a5260143356e4d806c31a81.bin~4.exe"
        $fn3 = "Option.bat"

    condition:
        3 of them
}
