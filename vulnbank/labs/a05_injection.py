"""A05:2025 Injection — SQL injection (login bypass) and reflected XSS."""
import hashlib
import html

from flask import Blueprint, request

from ..core import page, is_vuln
from .. import db

bp = Blueprint("a05", __name__, url_prefix="/a05")


def _sqli_result():
    if "u" not in request.values:
        return ""
    u = request.values.get("u", "")
    p = request.values.get("p", "")
    conn = db.connect()
    if is_vuln("a05"):
        # BUG: string-concatenated SQL. Try  u = ' OR '1'='1' --
        pw = hashlib.md5(p.encode()).hexdigest()
        query = (f"SELECT username,role FROM users "
                 f"WHERE username='{u}' AND md5='{pw}'")
        try:
            row = conn.execute(query).fetchone()
        except Exception as e:
            conn.close()
            return f'<div class="res bad">SQL error: {html.escape(str(e))}<br><pre>{html.escape(query)}</pre></div>'
        conn.close()
        shown = html.escape(query)
        if row:
            return (f'<div class="res bad">Query:<pre>{shown}</pre>'
                    f'Logged in as <b>{row["username"]}</b> (role: {row["role"]}). '
                    'Injection bypassed authentication.</div>')
        return f'<div class="res">Query:<pre>{shown}</pre>No match.</div>'

    # FIX: parameterized query — the input can never change the SQL structure.
    pw = hashlib.md5(p.encode()).hexdigest()
    row = conn.execute("SELECT username,role FROM users WHERE username=? AND md5=?",
                       (u, pw)).fetchone()
    conn.close()
    if row:
        return f'<div class="res good">Logged in as {row["username"]}. (Legit credentials.)</div>'
    return ('<div class="res good">Login failed. The <code>\' OR \'1\'=\'1</code> payload is '
            'now just a literal username that doesn\'t exist — injection blocked.</div>')


def _xss_result():
    if "q" not in request.values:
        return ""
    q = request.values.get("q", "")
    if is_vuln("a05"):
        # BUG: user input reflected into HTML unescaped.
        return f'<div class="res bad">Results for: {q}<br><span class=note>(rendered raw)</span></div>'
    return (f'<div class="res good">Results for: {html.escape(q)}<br>'
            '<span class=note>(HTML-escaped — any script tag is shown as text, not executed)</span></div>')


@bp.route("/", methods=["GET", "POST"])
def home():
    body = f"""
    <div class=panel>
      <h2>Part 1 — SQL injection (auth bypass)</h2>
      <p class=note>Log in without credentials. Username:
         <code>' OR '1'='1' --</code> &nbsp;(leave password blank).</p>
      <form class=inline method=get>
        <div><label>Username</label><input name=u value="{html.escape(request.values.get('u',""))}"></div>
        <div><label>Password</label><input name=p value="{html.escape(request.values.get('p',''))}"></div>
        <div style="flex:0"><button class=btn>Log in</button></div>
      </form>
      {_sqli_result()}
    </div>
    <div class=panel>
      <h2>Part 2 — Reflected XSS</h2>
      <p class=note>Search with a payload like
         <code>&lt;img src=x onerror=alert(1)&gt;</code> and watch it run in vulnerable mode.</p>
      <form class=inline method=get>
        <div><label>Search</label><input name=q value="{html.escape(request.values.get('q',''))}"></div>
        <div style="flex:0"><button class=btn>Search</button></div>
      </form>
      {_xss_result()}
    </div>
    <div class=panel>
      <h2>The fix</h2>
      <p class=note><b>SQLi:</b> use parameterized queries / prepared statements — never
         build SQL by string concatenation.<br>
         <b>XSS:</b> context-aware output encoding (escape on render) plus a Content
         Security Policy; treat all input as untrusted.</p>
    </div>"""
    return page("a05", body)
