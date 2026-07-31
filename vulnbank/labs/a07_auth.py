"""A07:2025 Authentication Failures — no rate limiting / lockout on login."""
import hashlib

from flask import Blueprint, request

from ..core import page, is_vuln
from .. import db

bp = Blueprint("a07", __name__, url_prefix="/a07")

# bob's real password ("hunter2") sits at position 8, past the lockout threshold,
# so secure mode locks the account before the attack ever reaches it.
WORDLIST = ["123456", "password", "iloveyou", "qwerty", "letmein",
            "monkey", "abc123", "hunter2", "dragon", "sunshine"]
MAX_ATTEMPTS = 5
_fails = {"count": 0}  # tracked only in secure mode


def _try_login(username, password):
    conn = db.connect()
    row = conn.execute("SELECT md5 FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return bool(row) and row["md5"] == hashlib.md5(password.encode()).hexdigest()


def _bruteforce():
    if request.values.get("run") != "1":
        return ""
    target = "bob"
    log = []
    for i, guess in enumerate(WORDLIST, 1):
        if not is_vuln("a07"):
            # FIX: lock the account after too many failures.
            if _fails["count"] >= MAX_ATTEMPTS:
                log.append(f"[{i}] '{guess}' → account LOCKED after {MAX_ATTEMPTS} failures")
                return ('<div class="res good"><pre>' + "\n".join(log) + '</pre>'
                        'Lockout stopped the attack before the password was reached.</div>')
        if _try_login(target, guess):
            log.append(f"[{i}] '{guess}' → SUCCESS")
            body = "\n".join(log)
            cls = "bad" if is_vuln("a07") else "good"
            return (f'<div class="res {cls}"><pre>{body}</pre>'
                    f'Recovered {target}\'s password: <b>{guess}</b></div>')
        log.append(f"[{i}] '{guess}' → fail")
        if not is_vuln("a07"):
            _fails["count"] += 1
    return '<div class="res"><pre>' + "\n".join(log) + '</pre>Password not in wordlist.</div>'


@bp.route("/reset")
def reset():
    _fails["count"] = 0
    return home()


@bp.route("/", methods=["GET", "POST"])
def home():
    body = f"""
    <div class=panel>
      <h2>Brute-force bob's login</h2>
      <p class=note>Run a 10-word password list against bob's account. In vulnerable mode
         there's no lockout, so the attack simply walks the list until it wins.
         <a href="/a07/reset">reset lockout counter</a></p>
      <form method=get><input type=hidden name=run value=1><button class=btn danger>Run brute-force</button></form>
      {_bruteforce()}
    </div>
    <div class=panel>
      <h2>The fix</h2>
      <p class=note>Rate-limit and lock accounts after repeated failures, add MFA, use
         a slow password hash, and prefer standardized auth frameworks. Detect
         credential-stuffing patterns and alert on them (see A09).</p>
    </div>"""
    return page("a07", body)
