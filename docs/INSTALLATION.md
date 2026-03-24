# Installation

## Requirements

- Python 3.10 or higher
- `requests` (only hard dependency)

## PyPI (recommended)

```bash
pip install huntertrace
```

With optional enrichment features (WHOIS, graph centrality):

```bash
pip install huntertrace[full]
```

## From source

```bash
git clone https://github.com/YOUR_ORG/huntertrace
cd huntertrace-release
pip install -e ".[full]"
```

Development install (includes linting and test tools):

```bash
pip install -e ".[dev]"
```

## Verify installation

```bash
huntertrace info
```

Expected output:
```
HunterTrace v3.0.0

Package modules:
  ✓  core.pipeline
  ✓  extraction.webmail
  ...

Optional dependencies:
  ✓  installed  requests     live IP enrichment
  –  not installed  networkx     graph centrality analysis
  –  not installed  whois        WHOIS enrichment (Stage 3B)
```

## API Keys (optional)

HunterTrace works without any API keys. Keys enable additional enrichment:

| Key | Service | How to get |
|-----|---------|-----------|
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com/register) | Free tier: 1000 req/day |
| `VIRUSTOTAL_API_KEY` | [VirusTotal](https://www.virustotal.com/gui/join-us) | Free tier: 4 req/min |
| `IPINFO_TOKEN` | [ipinfo.io](https://ipinfo.io/signup) | Free tier: 50k req/month |

Set via environment variable or `.env` file in working directory:

```bash
# Environment
export ABUSEIPDB_API_KEY=your_key_here

# .env file (auto-loaded)
echo "ABUSEIPDB_API_KEY=your_key_here" >> .env
```
