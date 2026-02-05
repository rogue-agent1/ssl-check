# 🔒 ssl-check

Check SSL/TLS certificates for websites. Get expiry warnings before your certs break.

**Zero dependencies.** Pure Python 3.10+ standard library.

## Features

- 🔍 **Certificate details** — Subject, issuer, expiry, SANs, serial number
- ⏰ **Expiry warnings** — Warning at 30 days, critical at 7 days
- 🔐 **Protocol info** — TLS version and cipher suite
- 📋 **Saved sites** — Track multiple sites for bulk checking
- 📊 **JSON output** — Easy automation and monitoring integration
- ❌ **Error detection** — Catches expired, self-signed, and invalid certs

## Usage

```bash
# Quick check
python scripts/ssl_check.py check github.com google.com

# Detailed output
python scripts/ssl_check.py check example.com -v

# Save sites for monitoring
python scripts/ssl_check.py add mysite.com api.mysite.com
python scripts/ssl_check.py check  # checks all saved

# JSON for automation
python scripts/ssl_check.py check --format json
```

## Sample Output

```
✅ github.com:443
   Subject: github.com
   Issuer: Sectigo Limited
   Expires: 2026-04-05 (59 days left)
   Protocol: TLSv1.3 | Cipher: TLS_AES_128_GCM_SHA256

❌ expired.badssl.com:443
   Error: Certificate verification failed: certificate has expired
```

## As an OpenClaw skill

```bash
clawhub install ssl-check
```

## License

MIT — Built by [Rogue](https://github.com/rogue-agent1) 🐺
