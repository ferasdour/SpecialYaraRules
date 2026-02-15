# aislop

Automated malware rule generation from Hybrid Analysis samples.

## What?

Tool that pulls malware samples from Hybrid Analysis and generates:
- YARA rules (file + memory strings)
- Sigma rules (behavioral IOCs)
- Suricata rules (network IOCs)

## Why?

Hybrid Analysis didn't have a way to bulk-export YARA rules. This fills that gap.

## How?

```bash
# Set API key
export HA_API_KEY=your_hybrid_analysis_key

# Run
python copilot-hatoyara.py
```

## Requirements

```bash
pip install requests pyyaml
```

## Output

```
rules/
├── yara/
│   └── dcrat/
│       └── <sha256>.yar
├── sigma/
│   └── dcrat/
│       └── <sha256>.yml
└── suricata/
    └── dcrat/
        └── <sha256>.rules
```


## Config

Edit these constants at the top of the script:

| Variable | Default | Description |
|----------|---------|-------------|
| `LATEST_LIMIT` | 100 | Samples to fetch |
| `MAX_WORKERS` | 4 | Thread count |
| `MIN_REQUEST_INTERVAL` | 5.0 | Rate limiting (seconds) |

## Benign Domains

The script filters out common benign domains. Edit `BENIGN_DOMAINS` set to customize.

## Tags

- Uses `tags` field in Sigma for threat family
- Includes reference URLs to Hybrid Analysis samples
- Tracks threat scores from HA verdict
