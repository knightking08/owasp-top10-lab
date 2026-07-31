"""A10:2025 Mishandling of Exceptional Conditions (new in 2025) — failing open.

An entitlement check throws for accounts missing from the entitlement store. The
vulnerable handler swallows the error and defaults to *allow*; the secure handler
fails closed and handles the error cleanly.
"""
from flask import Blueprint, request

from ..core import page, is_vuln

bp = Blueprint("a10", __name__, url_prefix="/a10")

# Only these accounts exist in the entitlement service. Anything else raises.
ENTITLEMENTS = {"alice": False, "bob": True}


def _check_entitlement(user):
    # Raises KeyError for unknown users (simulating a flaky downstream service).
    return ENTITLEMENTS[user]


def _access(user):
    if is_vuln("a10"):
        try:
            allowed = _check_entitlement(user)
        except Exception:
            # BUG: on error, default to allow — the check "fails open".
            allowed = True
        return allowed, "failed open (granted on error)"
    # FIX: fail closed and surface a clean error; never grant on exception.
    try:
        allowed = _check_entitlement(user)
    except Exception:
        return False, "failed closed (denied on error, incident logged)"
    return allowed, "normal decision"


def _result():
    user = request.values.get("user")
    if not user:
        return ""
    allowed, how = _access(user)
    if allowed and is_vuln("a10") and user not in ENTITLEMENTS:
        return (f'<div class="res bad">ACCESS GRANTED to premium feature for '
                f'<b>{user}</b> — but only because the entitlement lookup errored and '
                f'the code {how}. An unknown user just walked in.</div>')
    cls = "good" if not is_vuln("a10") else ("" if allowed else "good")
    verdict = "GRANTED" if allowed else "DENIED"
    return f'<div class="res {cls}">Access {verdict} for {user} — {how}.</div>'


@bp.route("/", methods=["GET", "POST"])
def home():
    body = f"""
    <div class=panel>
      <h2>Premium-feature access check</h2>
      <p class=note>Known accounts: <code>alice</code> (no access), <code>bob</code> (access).
         Now request access as an <b>unknown</b> user like <code>mallory</code> — that
         makes the entitlement lookup throw, and you'll see how each mode handles it.</p>
      <form class=inline method=get>
        <div><label>Request access as</label><input name=user value="{request.values.get('user','mallory')}"></div>
        <div style="flex:0"><button class=btn>Check access</button></div>
      </form>
      {_result()}
    </div>
    <div class=panel>
      <h2>The fix</h2>
      <p class=note>Handle exceptional conditions explicitly and <b>fail closed</b> for
         security decisions — an error in an access check must deny, not allow. Don't
         swallow exceptions with a permissive default; catch narrowly, log the incident,
         and return a safe state.</p>
    </div>"""
    return page("a10", body)
