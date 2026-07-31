"""A04:2025 Cryptographic Failures — crackable MD5 vs salted bcrypt."""
import hashlib
import time

import bcrypt
from flask import Blueprint, request

from ..core import page, is_vuln
from .. import db

bp = Blueprint("a04", __name__, url_prefix="/a04")

# A tiny "leaked" wordlist an attacker would run against stolen hashes.
WORDLIST = ["123456", "password", "hunter2", "letmein", "password123",
            "qwerty", "admin", "S3cretAdmin!", "dragon", "monkey"]


def _crack_md5(target):
    for w in WORDLIST:
        if hashlib.md5(w.encode()).hexdigest() == target:
            return w
    return None


def _result():
    username = request.values.get("user")
    if not username:
        return ""
    conn = db.connect()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row:
        return '<div class="res">No such user.</div>'

    if is_vuln("a04"):
        # BUG: unsalted MD5 — a fast hash with no salt falls to a wordlist instantly.
        t0 = time.perf_counter()
        cracked = _crack_md5(row["md5"])
        dt = (time.perf_counter() - t0) * 1000
        return (f'<div class="res bad">Stored as unsalted MD5: <code>{row["md5"]}</code><br>'
                f'Cracked in {dt:.1f} ms → password is <b>{cracked or "(not in wordlist)"}</b><br>'
                '<span class=note>No salt means identical passwords share a hash and '
                'rainbow tables apply. MD5 is far too fast for password storage.</span></div>')

    # FIX: bcrypt — salted and deliberately slow.
    t0 = time.perf_counter()
    tries = 0
    found = None
    for w in WORDLIST:
        tries += 1
        if bcrypt.checkpw(w.encode(), row["bcrypt"].encode()):
            found = w
            break
    dt = time.perf_counter() - t0
    per = dt / max(tries, 1)
    return (f'<div class="res good">Stored as bcrypt (cost 10): <code>{row["bcrypt"][:38]}…</code><br>'
            f'{tries} guesses took {dt:.2f}s ({per*1000:.0f} ms each). Even though this '
            f'demo password was in the list, the per-guess cost makes real wordlists '
            f'({per*1_000_000/60:.0f} min per million) impractical, and the per-user salt '
            'kills rainbow tables.</div>')


@bp.route("/", methods=["GET", "POST"])
def home():
    body = f"""
    <div class=panel>
      <h2>Inspect how a password is stored</h2>
      <p class=note>Pick a seeded account and see how its password hash holds up to a
         leaked-database + wordlist attack. Try <code>bob</code> or <code>admin</code>.</p>
      <form class=inline method=get>
        <div><label>Username</label><input name=user value="{request.values.get('user','bob')}"></div>
        <div style="flex:0"><button class=btn>Inspect</button></div>
      </form>
      {_result()}
    </div>
    <div class=panel>
      <h2>The fix</h2>
      <p class=note>Store passwords with a slow, salted, memory-hard KDF — bcrypt,
         scrypt, or Argon2id — never MD5/SHA-1/SHA-256. Use TLS in transit and
         authenticated encryption (AES-GCM) for data at rest.</p>
    </div>"""
    return page("a04", body)
