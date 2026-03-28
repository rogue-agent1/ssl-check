#!/usr/bin/env python3
"""ssl_check - Check SSL/TLS certificates."""
import sys, ssl, socket, datetime
def check_cert(hostname, port=443):
    ctx=ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(),server_hostname=hostname) as s:
        s.settimeout(10); s.connect((hostname,port))
        cert=s.getpeercert()
    subject=dict(x[0] for x in cert["subject"])
    issuer=dict(x[0] for x in cert["issuer"])
    not_before=datetime.datetime.strptime(cert["notBefore"],"%b %d %H:%M:%S %Y %Z")
    not_after=datetime.datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z")
    days_left=(not_after-datetime.datetime.utcnow()).days
    sans=[v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]
    return {
        "cn":subject.get("commonName",""),"issuer":issuer.get("organizationName",""),
        "not_before":str(not_before),"not_after":str(not_after),
        "days_left":days_left,"sans":sans,"version":cert.get("version",0),
        "serial":cert.get("serialNumber","")
    }
if __name__=="__main__":
    if len(sys.argv)<2: print("Usage: ssl_check <hostname> [port]"); sys.exit(1)
    host=sys.argv[1]; port=int(sys.argv[2]) if len(sys.argv)>2 else 443
    info=check_cert(host,port)
    print(f"Host: {host}:{port}")
    print(f"  CN: {info['cn']}"); print(f"  Issuer: {info['issuer']}")
    print(f"  Valid: {info['not_before']} to {info['not_after']}")
    warn="⚠️ " if info["days_left"]<30 else "✅ "
    print(f"  {warn}Expires in {info['days_left']} days")
    print(f"  SANs: {', '.join(info['sans'][:5])}")
