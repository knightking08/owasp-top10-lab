"""A09:2025 Security Logging & Alerting Failures — attacks that leave no trace."""
import time

from flask import Blueprint, request

from ..core import page, is_vuln

bp = Blueprint("a09", __name__, url_prefix="/a09")

_log = []           # list of (ts, event)
ALERT_THRESHOLD = 5


def _record(event):
    _log.append((time.strftime("%H:%M:%S"), event))


def _simulate_attack():
    if request.values.get("run") != "1":
        return ""
    # Six failed admin logins from one IP — a textbook brute-force signature.
    for _ in range(6):
        if not is_vuln("a09"):
            # FIX: security-relevant events are logged.
            _record("AUTH_FAIL user=admin ip=203.0.113.9")
    if is_vuln("a09"):
        # BUG: the failed logins happen but nothing is written and no alert fires.
        return ('<div class="res bad">6 failed admin logins occurred — and the security '
                'log below is still empty. With no logging or alerting, this brute-force '
                'attempt is invisible to defenders.</div>')
    recent_fails = sum(1 for _, e in _log if e.startswith("AUTH_FAIL"))
    alert = ""
    if recent_fails >= ALERT_THRESHOLD:
        _record(f"ALERT possible brute force: {recent_fails} auth failures")
        alert = (f'<br><b class=warn>🚨 ALERT raised: {recent_fails} auth failures '
                 'exceeded threshold — defenders notified.</b>')
    return f'<div class="res good">6 failed admin logins were logged and correlated.{alert}</div>'


def _log_view():
    if not _log:
        return '<pre>(security log is empty)</pre>'
    return "<pre>" + "\n".join(f"{ts}  {e}" for ts, e in _log[-12:]) + "</pre>"


@bp.route("/reset")
def reset():
    _log.clear()
    return home()


@bp.route("/", methods=["GET", "POST"])
def home():
    body = f"""
    <div class=panel>
      <h2>Simulate an attack, then check the logs</h2>
      <p class=note>Fire six failed admin logins, then look at the security log.
         <a href="/a09/reset">clear log</a></p>
      <form method=get><input type=hidden name=run value=1><button class=btn danger>Simulate 6 failed admin logins</button></form>
      {_simulate_attack()}
    </div>
    <div class=panel>
      <h2>Security log</h2>
      {_log_view()}
    </div>
    <div class=panel>
      <h2>The fix</h2>
      <p class=note>Log security-relevant events (auth failures, access-control denials,
         input-validation failures) with enough context to investigate, ship them to
         tamper-resistant central storage, and — crucially in the 2025 wording —
         <b>alert</b> on them. Great logs with no alerting catch nothing in time.</p>
    </div>"""
    return page("a09", body)
