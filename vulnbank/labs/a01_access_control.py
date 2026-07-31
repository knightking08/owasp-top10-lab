"""A01:2025 Broken Access Control — IDOR + SSRF (SSRF folded into A01 in 2025)."""
import ipaddress
import socket
import urllib.parse
import urllib.request

from flask import Blueprint, request

from ..core import page, is_vuln
from .. import db

bp = Blueprint("a01", __name__, url_prefix="/a01")

# We pretend the logged-in user is Alice (id 1). The admin invoice 3001 is the
# prize you should NOT be able to read.
CURRENT_USER_ID = 1


def _idor_result():
    inv_id = request.values.get("id")
    if not inv_id:
        return ""
    conn = db.connect()
    row = conn.execute("SELECT * FROM invoices WHERE id=?", (inv_id,)).fetchone()
    conn.close()
    if not row:
        return '<div class="res bad">No such invoice.</div>'
    if is_vuln("a01"):
        # BUG: returns the invoice with no ownership check.
        owned = " (NOT yours!)" if row["owner_id"] != CURRENT_USER_ID else ""
        return (f'<div class="res bad">Invoice {row["id"]} — owner {row["owner_id"]}{owned}<br>'
                f'${row["amount"]:.2f} · {row["memo"]}</div>')
    if row["owner_id"] != CURRENT_USER_ID:
        return ('<div class="res good">403 Forbidden — this invoice belongs to another '
                'user. Access denied.</div>')
    return (f'<div class="res good">Invoice {row["id"]} (yours): '
            f'${row["amount"]:.2f} · {row["memo"]}</div>')


def _is_internal(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except Exception:
        return True  # fail closed on resolution problems


def _ssrf_result():
    url = request.values.get("url")
    if not url:
        return ""
    host = urllib.parse.urlparse(url).hostname or ""
    if not is_vuln("a01"):
        # FIX: block requests to internal / loopback / link-local addresses.
        if _is_internal(host):
            return ('<div class="res good">Request blocked — destination resolves to an '
                    'internal address. SSRF prevented.</div>')
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            body = r.read(400).decode("utf-8", "replace")
        return f'<div class="res {"bad" if is_vuln("a01") else "good"}">Fetched {url}:<pre>{body}</pre></div>'
    except Exception as e:
        return f'<div class="res">Fetch error: {e}</div>'


@bp.route("/internal-metadata")
def internal_metadata():
    # Stands in for a cloud metadata endpoint that should only be reachable
    # from inside the network — the classic SSRF target.
    return ("INTERNAL ONLY — do not expose\n"
            "aws_access_key_id=AKIA_LAB_EXAMPLE\n"
            "aws_secret_access_key=lab-secret-do-not-use\n"
            "role=vulnbank-app")


@bp.route("/", methods=["GET", "POST"])
def home():
    base = request.host_url.rstrip("/")
    body = f"""
    <div class=panel>
      <span class=tag>Signed in as alice (user id 1)</span>
      <h2>Part 1 — IDOR: read an invoice by id</h2>
      <p class=note>Your invoices are 1001 and 1002. Try changing the id to
         <code>3001</code> — the confidential admin payroll invoice.</p>
      <form class=inline method=get>
        <div><label>Invoice id</label><input name=id value="{request.values.get('id','1001')}"></div>
        <div style="flex:0"><button class=btn>View</button></div>
      </form>
      {_idor_result()}
    </div>

    <div class=panel>
      <h2>Part 2 — SSRF: import an invoice from a URL</h2>
      <p class=note>Point this at the internal-only metadata endpoint that should be
         unreachable from user input:<br>
         <code>{base}/a01/internal-metadata</code></p>
      <form class=inline method=get>
        <div><label>URL</label><input name=url value="{request.values.get('url', base + '/a01/internal-metadata')}"></div>
        <div style="flex:0"><button class=btn>Fetch</button></div>
      </form>
      {_ssrf_result()}
    </div>

    <div class=panel>
      <h2>The fix</h2>
      <p class=note><b>IDOR:</b> check that the requested object belongs to the current
         user (deny by default) — never trust an id from the URL.<br>
         <b>SSRF:</b> resolve the destination and block private / loopback / link-local
         ranges, ideally with an allow-list of permitted hosts.</p>
    </div>"""
    return page("a01", body)
