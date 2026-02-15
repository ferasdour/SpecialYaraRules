rule Win64_Rozena_AGeneric.BO_trojan_family
{
    meta:
        description = "Auto-generated YARA rule for Win64_Rozena_AGeneric.BO_trojan"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "19b6fea0973df58d07c2e368303a0b0d4a1e111a3d251c7419f3442ab1295ec3"
        first_seen = "2026-02-15T01:23:58+00:00"
        threat_score = "100"
        mitre_techniques = "Domains, Phishing, Native API, Windows Command Shell, Shared Modules"
        target_url = "none"

    strings:
        $d0 = "webcdns.com"
        $h0 = "104.21.30.194"
        $fn0 = "19b6fea0973df58d07c2e368303a0b0d4a1e111a3d251c7419f3442ab1295ec3.bin.exe"
        $fn1 = "msoECB4.tmp"
        $fn2 = "RCX1D0F.tmp"
        $fn3 = "19b6fea0973df58d07c2e368303a0b0d4a1e111a3d251c7419f3442ab1295ec3.bin.docx"
        $fn4 = "19b6fea0973df58d07c2e368303a0b0d4a1e111a3d251c7419f3442ab1295ec3.bin.exe%3AZone.Identifier"
        $fn5 = "~_Normal.dotm"
        $fn6 = "~_b6fea0973df58d07c2e368303a0b0d4a1e111a3d251c7419f3442ab1295ec3.bin.docx"

    condition:
        7 of them
}
