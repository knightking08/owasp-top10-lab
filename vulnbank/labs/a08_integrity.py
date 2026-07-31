"""A08:2025 Software or Data Integrity Failures — insecure deserialization.

The malicious payload runs a fixed, harmless command (`whoami`) purely to prove
that attacker-controlled code executes during pickle.loads(). A real payload
would run anything; this lab deliberately does not build a general command runner.
"""
import base64
import hashlib
import hmac
import json
import pickle
import subprocess

from flask import Blueprint, request

from ..core import page, is_vuln

bp = Blueprint("a08", __name__, url_prefix="/a08")

SIGNING_KEY = b"vulnbank-hmac-key"


class _Exploit:
    """Its __reduce__ makes pickle run a shell command on load."""
    def __reduce__(self):
        return (subprocess.getoutput, ("whoami",))


def _malicious_blob():
    return base64.b64encode(pickle.dumps(_Exploit())).decode()


def _benign_signed_blob():
    payload = json.dumps({"theme": "dark", "lang": "en"}).encode()
    sig = hmac.new(SIGNING_KEY, payload, hashlib.sha256).hexdigest()
    return base64.b64encode(payload).decode() + "." + sig


def _import_prefs(blob):
    raw = base64.b64decode(blob.split(".")[0])
    if is_vuln("a08"):
        # BUG: deserialize untrusted bytes with pickle -> arbitrary code execution.
        obj = pickle.loads(raw)
        return ("bad", f"pickle.loads executed attacker code. Command output: <b>{obj}</b>")
    # FIX: require an HMAC signature and parse as plain JSON (no code paths).
    if "." not in blob:
        return ("good", "Rejected: unsigned payload (no HMAC). Import refused.")
    body_b64, sig = blob.rsplit(".", 1)
    body = base64.b64decode(body_b64)
    expected = hmac.new(SIGNING_KEY, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return ("good", "Rejected: HMAC signature mismatch — payload was tampered with.")
    return ("good", f"Verified & imported preferences: {json.loads(body)}")


def _result():
    blob = request.values.get("blob")
    if not blob:
        return ""
    try:
        cls, msg = _import_prefs(blob)
    except Exception as e:
        return f'<div class="res">Import error: {e}</div>'
    return f'<div class="res {cls}">{msg}</div>'


@bp.route("/", methods=["GET", "POST"])
def home():
    suggested = _malicious_blob() if is_vuln("a08") else _benign_signed_blob()
    body = f"""
    <div class=panel>
      <h2>Import account preferences</h2>
      <p class=note>The app deserializes a base64 "preferences" blob. Below is a
         {'<b>malicious pickle</b> whose payload runs a shell command' if is_vuln('a08')
          else '<b>signed JSON</b> blob'}. Import it and see what happens.
         In secure mode, try editing the signed blob to see the HMAC reject it.</p>
      <form method=get>
        <label>Preferences blob (base64)</label>
        <textarea name=blob rows=4>{request.values.get('blob', suggested)}</textarea>
        <button class=btn style="margin-top:10px">Import</button>
      </form>
      {_result()}
    </div>
    <div class=panel>
      <h2>The fix</h2>
      <p class=note>Never deserialize untrusted input with pickle/YAML-full-load/etc.
         Use a data-only format (JSON) and verify integrity with an HMAC or digital
         signature before trusting any incoming code, update, or serialized object.</p>
    </div>"""
    return page("a08", body)
