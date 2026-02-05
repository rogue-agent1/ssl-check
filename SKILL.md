---
name: ssl-check
description: Check SSL/TLS certificates for websites. Shows expiry dates, issuer, protocol, cipher, and warnings for expiring certs. Use when asked to check SSL certificates, verify HTTPS, monitor cert expiry, or audit website security. Supports saved site lists for bulk checking.
---

# SSL Check

Check SSL/TLS certificates for any website. Pure Python, no dependencies.

## Quick Start

```bash
# Check one or more sites
python scripts/ssl_check.py check github.com google.com

# Verbose (SANs, serial, dates)
python scripts/ssl_check.py check github.com -v

# JSON output
python scripts/ssl_check.py check github.com --format json

# Save sites for recurring checks
python scripts/ssl_check.py add github.com google.com anthropic.com
python scripts/ssl_check.py check  # checks all saved sites

# List saved sites
python scripts/ssl_check.py list

# Remove a site
python scripts/ssl_check.py remove google.com
```

## Status Icons

- ✅ OK — cert valid, >30 days remaining
- ⚠️ WARNING — cert expires within 30 days
- 🚨 CRITICAL — cert expires within 7 days
- ❌ ERROR — invalid cert, connection failed, or DNS error

## Data

Saved sites stored in `~/.ssl-check/sites.json`.
