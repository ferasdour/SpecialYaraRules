rule unknown_family
{
    meta:
        description = "Auto-generated YARA rule for unknown"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "b967112eb909f04f1d94a5d748af30eea79fdcecd91499242aa7fc4fd8a36ace"
        first_seen = "2026-02-15T01:22:01+00:00"
        threat_score = "80"
        mitre_techniques = "Command and Scripting Interpreter, Shared Modules, Native API, Visual Basic, PowerShell"
        target_url = "none"

    strings:
        $fn0 = "mHJvn.exe"
        $fn1 = "CMVdbXyNna"
        $fn2 = "uPoVUaOFknXfqSEFltYD"
        $fn3 = "330a1b.msi"
        $fn4 = "hBEflnLOmrsjRJzsgWC"
        $fn5 = "ngen.log"
        $fn6 = "OnbqkHFD"
        $fn7 = "pOGRgaZuXALgHRcLQe"

    condition:
        6 of them
}
