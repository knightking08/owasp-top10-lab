"""A02:2025 Security Misconfiguration — debug mode leaking secrets on error."""
import traceback
import uuid

from flask import Blueprint, request

from ..core import page, is_vuln

bp = Blueprint("a02", __name__, url_prefix="/a02")

# Secrets that a debug page would happily expose to any visitor.
APP_CONFIG = {
    "SECRET_KEY": "vulnbank-prod-key-8f2a9c",
    "DB_URI": "postgres://vulnbank:S3cr3tDbPass@10.0.0.5:5432/prod",
    "STRIPE_KEY": "sk_live_LAB_EXAMPLE_do_not_use",
    "DEBUG": True,
}


def _lookup(acct: str):
    # Deliberately blows up on non-numeric input.
    balances = {"100": 500.0, "200": 88.5}
    return balances[acct]  # KeyError / TypeError on bad input


def _result():
    acct = request.values.get("acct")
    if acct is None:
        return ""
    try:
        bal = _lookup(acct)
        return f'<div class="res good">Account {acct} balance: ${bal:.2f}</div>'
    except Exception:
        if is_vuln("a02"):
            # BUG: debug mode dumps the traceback AND app config to the browser.
            tb = traceback.format_exc()
            cfg = "\n".join(f"{k} = {v}" for k, v in APP_CONFIG.items())
            return ('<div class="res bad"><b>Werkzeug Debugger (DEBUG=True)</b>'
                    f'<pre>{tb}\nApplication config:\n{cfg}</pre></div>')
        # FIX: generic message, details go only to the server-side log.
        ref = uuid.uuid4().hex[:8]
        return (f'<div class="res good">Something went wrong. Reference: {ref}<br>'
                '<span class=note>(full details logged server-side only; no stack '
                'trace or config is shown to the user)</span></div>')


@bp.route("/", methods=["GET", "POST"])
def home():
    body = f"""
    <div class=panel>
      <h2>Trigger an application error</h2>
      <p class=note>Valid accounts are <code>100</code> and <code>200</code>.
         Enter something else (e.g. <code>abc</code> or <code>999</code>) to force
         an exception, then read what leaks back.</p>
      <form class=inline method=get>
        <div><label>Account number</label><input name=acct value="{request.values.get('acct','abc')}"></div>
        <div style="flex:0"><button class=btn>Check balance</button></div>
      </form>
      {_result()}
    </div>
    <div class=panel>
      <h2>The fix</h2>
      <p class=note>Ship with <code>DEBUG=False</code>, register a custom error handler
         that returns a generic message plus a correlation id, and log the real
         stack trace server-side. Never expose framework debuggers, config, or
         directory listings in production.</p>
    </div>"""
    return page("a02", body)
