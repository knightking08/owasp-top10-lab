"""
Shared core for VulnBank: the runtime security-state registry, the OWASP
Top 10:2025 lab metadata, and the HTML layout used by every lab page.

Each lab has an in-memory security level you flip in the UI:
    vulnerable = True   -> the attack works
    vulnerable = False  -> the fix is applied and the attack is blocked

State is process-global and resets on restart. That is fine (and intended)
for a local single-user training lab.
"""
from flask import request, url_for

# OWASP Top 10:2025 -> (short title, one-line what-you-do-here)
LABS = {
    "a01": ("Broken Access Control", "IDOR + SSRF: reach data and hosts you shouldn't"),
    "a02": ("Security Misconfiguration", "Debug mode leaks secrets in a stack trace"),
    "a03": ("Software Supply Chain Failures", "Trust a dependency with a known CVE"),
    "a04": ("Cryptographic Failures", "Passwords stored with crackable MD5"),
    "a05": ("Injection", "SQL injection login bypass + reflected XSS"),
    "a06": ("Insecure Design", "Business-logic flaw: negative quantity = free money"),
    "a07": ("Authentication Failures", "No lockout: brute-force a password"),
    "a08": ("Software/Data Integrity Failures", "Insecure deserialization -> code execution"),
    "a09": ("Security Logging & Alerting Failures", "Attacks happen, nothing is recorded"),
    "a10": ("Mishandling of Exceptional Conditions", "An error makes the access check fail open"),
}
ORDER = list(LABS.keys())

# True == vulnerable. Everything starts vulnerable.
_STATE = {k: True for k in LABS}


def is_vuln(lab: str) -> bool:
    return _STATE[lab]


def set_state(lab: str, vulnerable: bool) -> None:
    if lab in _STATE:
        _STATE[lab] = vulnerable


def all_state() -> dict:
    return dict(_STATE)


CSS = """
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--ink:#e6edf3;--mut:#8b949e;
      --accent:#58a6ff;--bad:#f85149;--good:#3fb950;--warn:#e3b341}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;
  background:var(--bg);color:var(--ink)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:920px;margin:0 auto;padding:24px 18px 60px}
header.top{border-bottom:1px solid var(--line);background:#0b0f16;position:sticky;top:0;z-index:5}
header.top .wrap{padding:12px 18px;display:flex;align-items:center;gap:14px}
.brand{font-weight:700;font-size:18px}.brand span{color:var(--bad)}
.crumbs{color:var(--mut);font-size:14px}
h1{font-size:23px;margin:18px 0 4px}h2{font-size:17px;margin:26px 0 8px}
.tag{font-size:12px;color:var(--mut);letter-spacing:.03em;text-transform:uppercase}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:16px 0}
.toggle{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.pill{padding:5px 10px;border-radius:999px;font-size:12px;font-weight:700}
.pill.bad{background:#2d1416;color:var(--bad);border:1px solid #5c2327}
.pill.good{background:#0d2818;color:var(--good);border:1px solid #1f6f3f}
.btn{display:inline-block;padding:9px 14px;border:1px solid var(--line);border-radius:9px;
     background:#21262d;color:var(--ink);font-weight:600;cursor:pointer;font-size:14px}
.btn:hover{border-color:#4b5563;text-decoration:none}
.btn.on{background:#1f6feb;border-color:#1f6feb;color:#fff}
.btn.danger{background:#b62324;border-color:#b62324;color:#fff}
input,textarea,select{width:100%;padding:9px 11px;border-radius:8px;border:1px solid var(--line);
     background:#0d1117;color:var(--ink);font:inherit}
label{display:block;font-size:13px;color:var(--mut);margin:10px 0 4px}
form.inline{display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap}
form.inline>div{flex:1;min-width:180px}
pre{background:#0b0f16;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;
    font-size:13px;white-space:pre-wrap;word-break:break-word}
code{background:#0b0f16;padding:1px 5px;border-radius:5px}
.res{border-left:3px solid var(--accent);padding:10px 14px;margin:12px 0;background:#0f1622;border-radius:0 8px 8px 0}
.res.bad{border-color:var(--bad)}.res.good{border-color:var(--good)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px;margin-top:16px}
.card{display:block;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.card:hover{border-color:#4b5563;text-decoration:none}.card .id{color:var(--bad);font-weight:700;font-size:13px}
.card .t{font-weight:600;margin:3px 0}.card .d{color:var(--mut);font-size:13px}
.note{color:var(--mut);font-size:13px}.warn{color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line)}
"""


def _toggle_controls(lab: str) -> str:
    vuln = is_vuln(lab)
    pill = ('<span class="pill bad">VULNERABLE</span>' if vuln
            else '<span class="pill good">SECURE</span>')
    v_on = "on" if vuln else ""
    s_on = "" if vuln else "on"
    action = url_for("set_security", lab=lab)
    return f"""
    <div class="panel toggle">
      <div>Security level: {pill}</div>
      <form method="post" action="{action}" style="display:inline">
        <input type="hidden" name="mode" value="vuln">
        <button class="btn {v_on}">Vulnerable</button>
      </form>
      <form method="post" action="{action}" style="display:inline">
        <input type="hidden" name="mode" value="secure">
        <button class="btn {s_on}">Secure</button>
      </form>
    </div>"""


def page(lab_id: str, body: str) -> str:
    """Wrap lab content in the shared layout (nav, title, toggle)."""
    title, _ = LABS[lab_id]
    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>VulnBank — {lab_id.upper()} {title}</title><style>{CSS}</style></head><body>
<header class=top><div class=wrap>
  <a class=brand href="{url_for('index')}">Vuln<span>Bank</span></a>
  <span class=crumbs>OWASP Top 10:2025 &nbsp;›&nbsp; {lab_id.upper()} · {title}</span>
</div></header>
<div class=wrap>
  <div class=tag>{lab_id.upper()} — OWASP Top 10:2025</div>
  <h1>{title}</h1>
  {_toggle_controls(lab_id)}
  {body}
  <p class=note style="margin-top:30px"><a href="{url_for('index')}">← all labs</a></p>
</div></body></html>"""
