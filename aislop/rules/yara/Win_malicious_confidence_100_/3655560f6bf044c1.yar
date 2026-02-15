rule Win_malicious_confidence_100__family
{
    meta:
        description = "Auto-generated YARA rule for Win_malicious_confidence_100_"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "2"
        first_sha256 = "3655560f6bf044c148bcd4be135bc9156c345bdc5e8cb69cb7a51290b953f575"
        first_seen = "2026-02-15T01:32:19+00:00"
        threat_score = "100"
        mitre_techniques = "Native API, Windows Command Shell, Shared Modules, Service Execution, Modify Registry"
        target_url = "none"

    strings:
        $fn0 = "_C60B9B70-B138-4eee-B5A7-4F264065B139_.exe"
        $fn1 = "_8AA2AC2D-177F-4b3e-A61D-06469C06506C_.exe"
        $fn2 = "_4F891D44-B60E-4633-A46B-A45BD409C0CD_.exe"
        $fn3 = "_5E757FCE-332F-4272-B092-AB08495BE6CB_.exe"
        $fn4 = "_C56F247F-BD1F-41a4-B6D2-92E28DCBD2F4_.exe"
        $fn5 = "_359A5493-61D9-485e-8B1C-2E2C8F25D657_.exe"
        $fn6 = "_E37D184C-FD8B-4a29-AC0D-560645C70D3D_.exe"
        $fn7 = "_9A0685F8-3B78-4f7b-B5E9-5E2136191A4E_.exe"

    condition:
        6 of them
}
