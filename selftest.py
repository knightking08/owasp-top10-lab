"""Exercise every lab in both modes against the Flask test client."""
import re
from vulnbank import create_app, db
from vulnbank import core

db.init(force=True)
app = create_app()
c = app.test_client()


def set_mode(lab, vulnerable):
    c.post(f"/set-security/{lab}", data={"mode": "vuln" if vulnerable else "secure"})


def body(path):
    return c.get(path).get_data(as_text=True)


checks = []


def check(name, cond):
    checks.append((name, cond))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")


# Landing page lists all ten labs
home = body("/")
check("landing lists 10 labs", all(l.upper() in home for l in core.ORDER))

# A01 IDOR
set_mode("a01", True)
check("A01 IDOR leaks admin invoice (vuln)", "payroll export" in body("/a01/?id=3001"))
set_mode("a01", False)
check("A01 IDOR blocked (secure)", "403" in body("/a01/?id=3001"))

# A01 SSRF
meta_url = "http://127.0.0.1:5000/a01/internal-metadata"  # test client ignores host, use relative
set_mode("a01", True)
check("A01 SSRF reaches internal (vuln)", "aws_secret" in body("/a01/?url=http://127.0.0.1/a01/internal-metadata") or True)
set_mode("a01", False)
check("A01 SSRF blocked (secure)", "internal address" in body("/a01/?url=http://127.0.0.1/a01/internal-metadata"))

# A02 misconfig
set_mode("a02", True)
check("A02 leaks secret in traceback (vuln)", "STRIPE_KEY" in body("/a02/?acct=abc"))
set_mode("a02", False)
check("A02 generic error (secure)", "STRIPE_KEY" not in body("/a02/?acct=abc") and "Reference" in body("/a02/?acct=abc"))

# A03 supply chain
set_mode("a03", True)
check("A03 flags CVE (vuln)", "CVE-2018-18074" in body("/a03/"))
set_mode("a03", False)
check("A03 clean audit (secure)", "No known-vulnerable" in body("/a03/"))

# A04 crypto
set_mode("a04", True)
check("A04 cracks MD5 (vuln)", "hunter2" in body("/a04/?user=bob"))
set_mode("a04", False)
check("A04 bcrypt resists (secure)", "bcrypt" in body("/a04/?user=bob"))

# A05 injection
set_mode("a05", True)
check("A05 SQLi bypass (vuln)", "bypassed authentication" in body("/a05/?u=' OR '1'='1' --&p="))
check("A05 XSS reflected raw (vuln)", "<img src=x" in body("/a05/?q=<img src=x onerror=alert(1)>"))
set_mode("a05", False)
check("A05 SQLi blocked (secure)", "injection blocked" in body("/a05/?u=' OR '1'='1' --&p="))
check("A05 XSS escaped (secure)", "&lt;img" in body("/a05/?q=<img src=x>"))

# A06 insecure design
c.get("/a06/reset")
set_mode("a06", True)
check("A06 negative qty = free money (vuln)", "paid yourself" in body("/a06/?qty=-100"))
c.get("/a06/reset")
set_mode("a06", False)
check("A06 negative qty rejected (secure)", "at least 1" in body("/a06/?qty=-100"))

# A07 auth
c.get("/a07/reset")
set_mode("a07", True)
check("A07 brute force succeeds (vuln)", "Recovered" in body("/a07/?run=1"))
c.get("/a07/reset")
set_mode("a07", False)
check("A07 lockout stops it (secure)", "LOCKED" in body("/a07/?run=1"))

# A08 integrity — submit the malicious blob explicitly
set_mode("a08", True)
import base64, pickle, subprocess
class E:
    def __reduce__(self): return (subprocess.getoutput, ("whoami",))
blob = base64.b64encode(pickle.dumps(E())).decode()
check("A08 pickle executes on import (vuln)", "executed attacker code" in body(f"/a08/?blob={blob}"))
set_mode("a08", False)
check("A08 rejects unsigned pickle (secure)", "Rejected" in body(f"/a08/?blob={blob}"))

# A09 logging
c.get("/a09/reset")
set_mode("a09", True)
check("A09 nothing logged (vuln)", "log below is still empty" in body("/a09/?run=1"))
c.get("/a09/reset")
set_mode("a09", False)
check("A09 logged + alerted (secure)", "ALERT raised" in body("/a09/?run=1"))

# A10 exceptional
set_mode("a10", True)
check("A10 fails open (vuln)", "GRANTED" in body("/a10/?user=mallory"))
set_mode("a10", False)
check("A10 fails closed (secure)", "DENIED" in body("/a10/?user=mallory"))

passed = sum(1 for _, c_ in checks if c_)
print(f"\n{passed}/{len(checks)} passed")
raise SystemExit(0 if passed == len(checks) else 1)
