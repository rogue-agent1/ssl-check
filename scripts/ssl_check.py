#!/usr/bin/env python3
"""
ssl-check: Check SSL/TLS certificates for websites.
Reports expiry dates, issuer, validity, and warnings for expiring certs.
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

DATA_DIR = Path.home() / ".ssl-check"
SITES_FILE = DATA_DIR / "sites.json"


def ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_sites() -> list:
    if SITES_FILE.exists():
        return json.loads(SITES_FILE.read_text())
    return []


def save_sites(sites: list):
    SITES_FILE.write_text(json.dumps(sites, indent=2))


def check_ssl(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """Check SSL certificate for a hostname."""
    result = {
        "hostname": hostname,
        "port": port,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Parse dates
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days
                
                # Subject and issuer
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                
                # SANs
                sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
                
                # Protocol and cipher
                protocol = ssock.version()
                cipher = ssock.cipher()
                
                result.update({
                    "valid": True,
                    "subject": subject.get("commonName", ""),
                    "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "days_left": days_left,
                    "sans": sans[:10],  # Limit SANs shown
                    "san_count": len(sans),
                    "protocol": protocol,
                    "cipher": cipher[0] if cipher else None,
                    "serial": cert.get("serialNumber", ""),
                    "status": "critical" if days_left <= 7 else "warning" if days_left <= 30 else "ok",
                })
                
    except ssl.SSLCertVerificationError as e:
        result.update({"valid": False, "error": f"Certificate verification failed: {e}", "status": "error"})
    except ssl.SSLError as e:
        result.update({"valid": False, "error": f"SSL error: {e}", "status": "error"})
    except socket.timeout:
        result.update({"valid": False, "error": "Connection timed out", "status": "error"})
    except socket.gaierror as e:
        result.update({"valid": False, "error": f"DNS resolution failed: {e}", "status": "error"})
    except ConnectionRefusedError:
        result.update({"valid": False, "error": "Connection refused", "status": "error"})
    except Exception as e:
        result.update({"valid": False, "error": str(e), "status": "error"})
    
    return result


def format_result(r: dict, verbose: bool = False) -> str:
    """Format a single check result."""
    lines = []
    
    if r.get("valid"):
        status_icon = {"ok": "✅", "warning": "⚠️", "critical": "🚨"}.get(r["status"], "❓")
        lines.append(f"{status_icon} {r['hostname']}:{r['port']}")
        lines.append(f"   Subject: {r['subject']}")
        lines.append(f"   Issuer: {r['issuer']}")
        lines.append(f"   Expires: {r['not_after'][:10]} ({r['days_left']} days left)")
        lines.append(f"   Protocol: {r['protocol']} | Cipher: {r['cipher']}")
        
        if r["status"] == "critical":
            lines.append(f"   🚨 CRITICAL: Certificate expires in {r['days_left']} days!")
        elif r["status"] == "warning":
            lines.append(f"   ⚠️  WARNING: Certificate expires in {r['days_left']} days")
        
        if verbose:
            lines.append(f"   SANs ({r['san_count']}): {', '.join(r['sans'][:5])}")
            lines.append(f"   Serial: {r['serial']}")
            lines.append(f"   Valid from: {r['not_before'][:10]}")
    else:
        lines.append(f"❌ {r['hostname']}:{r['port']}")
        lines.append(f"   Error: {r.get('error', 'Unknown error')}")
    
    return "\n".join(lines)


def cmd_check(args):
    """Check one or more hostnames."""
    hostnames = args.hosts
    if not hostnames:
        # Check saved sites
        sites = load_sites()
        if not sites:
            print("No hosts specified and no saved sites. Use 'check <hostname>' or 'add <hostname>'.")
            return
        hostnames = sites
    
    results = []
    for host in hostnames:
        # Strip protocol if provided
        host = host.replace("https://", "").replace("http://", "").split("/")[0]
        port = 443
        if ":" in host:
            parts = host.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass
        
        result = check_ssl(host, port)
        results.append(result)
    
    if args.format == "json":
        print(json.dumps(results, indent=2))
        return
    
    for i, r in enumerate(results):
        if i > 0:
            print()
        print(format_result(r, args.verbose))
    
    # Summary
    if len(results) > 1:
        critical = sum(1 for r in results if r.get("status") == "critical")
        warning = sum(1 for r in results if r.get("status") == "warning")
        errors = sum(1 for r in results if r.get("status") == "error")
        ok = sum(1 for r in results if r.get("status") == "ok")
        print(f"\n📊 Summary: {ok} ok, {warning} warning, {critical} critical, {errors} errors")


def cmd_add(args):
    """Add hostnames to saved list."""
    ensure_dirs()
    sites = load_sites()
    added = []
    for host in args.hosts:
        host = host.replace("https://", "").replace("http://", "").split("/")[0]
        if host not in sites:
            sites.append(host)
            added.append(host)
    save_sites(sites)
    if added:
        print(f"✅ Added: {', '.join(added)}")
    else:
        print("All hosts already tracked.")


def cmd_remove(args):
    """Remove hostnames from saved list."""
    ensure_dirs()
    sites = load_sites()
    removed = []
    for host in args.hosts:
        host = host.replace("https://", "").replace("http://", "").split("/")[0]
        if host in sites:
            sites.remove(host)
            removed.append(host)
    save_sites(sites)
    if removed:
        print(f"✅ Removed: {', '.join(removed)}")
    else:
        print("None of those hosts were being tracked.")


def cmd_list(args):
    """List saved hostnames."""
    ensure_dirs()
    sites = load_sites()
    if not sites:
        print("No sites saved. Use 'add <hostname>' to start tracking.")
        return
    for i, s in enumerate(sites, 1):
        print(f"  {i}. {s}")


def main():
    parser = argparse.ArgumentParser(
        prog="ssl-check",
        description="Check SSL/TLS certificates for websites"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    
    # check
    p_chk = sub.add_parser("check", help="Check SSL certificates")
    p_chk.add_argument("hosts", nargs="*", help="Hostnames to check (all saved if omitted)")
    p_chk.add_argument("--format", "-f", choices=["text", "json"], default="text")
    p_chk.add_argument("--verbose", "-v", action="store_true")
    p_chk.set_defaults(func=cmd_check)
    
    # add
    p_add = sub.add_parser("add", help="Add hostnames to saved list")
    p_add.add_argument("hosts", nargs="+", help="Hostnames to add")
    p_add.set_defaults(func=cmd_add)
    
    # remove
    p_rm = sub.add_parser("remove", help="Remove hostnames from saved list")
    p_rm.add_argument("hosts", nargs="+", help="Hostnames to remove")
    p_rm.set_defaults(func=cmd_remove)
    
    # list
    p_ls = sub.add_parser("list", help="List saved hostnames")
    p_ls.set_defaults(func=cmd_list)
    
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
