"""VulnBank application factory."""
from flask import Flask, redirect, request, url_for

from . import core, db


def create_app():
    app = Flask(__name__)
    app.secret_key = "vulnbank-lab-not-secret"
    db.init()

    # Register one blueprint per OWASP category.
    from .labs import (a01_access_control, a02_misconfig, a03_supply_chain,
                       a04_crypto, a05_injection, a06_insecure_design,
                       a07_auth, a08_integrity, a09_logging, a10_exceptional)
    for mod in (a01_access_control, a02_misconfig, a03_supply_chain, a04_crypto,
                a05_injection, a06_insecure_design, a07_auth, a08_integrity,
                a09_logging, a10_exceptional):
        app.register_blueprint(mod.bp)

    @app.route("/")
    def index():
        cards = ""
        for lab_id in core.ORDER:
            title, desc = core.LABS[lab_id]
            state = "VULNERABLE" if core.is_vuln(lab_id) else "SECURE"
            cls = "bad" if core.is_vuln(lab_id) else "good"
            cards += (f'<a class=card href="{url_for(lab_id + ".home")}">'
                      f'<div class=id>{lab_id.upper()}</div>'
                      f'<div class=t>{title}</div>'
                      f'<div class=d>{desc}</div>'
                      f'<div style="margin-top:8px"><span class="pill {cls}">{state}</span></div></a>')
        body = f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>VulnBank — OWASP Top 10:2025 Lab</title><style>{core.CSS}</style></head><body>
<header class=top><div class=wrap><a class=brand href="/">Vuln<span>Bank</span></a>
<span class=crumbs>a deliberately-vulnerable app · OWASP Top 10:2025</span></div></header>
<div class=wrap>
  <h1>OWASP Top 10:2025 — attack &amp; defend lab</h1>
  <p class=note>Every card is a live, exploitable feature. Open one, run the attack,
     then flip it to <b>Secure</b> and watch the same attack fail. Seeded accounts:
     <code>alice / password123</code>, <code>bob / hunter2</code>,
     <code>admin / S3cretAdmin!</code></p>
  <p class=warn>⚠ Deliberately insecure. Run locally only. Never expose this to a network.</p>
  <div class=grid>{cards}</div>
</div></body></html>"""
        return body

    @app.route("/set-security/<lab>", methods=["POST"])
    def set_security(lab):
        core.set_state(lab, request.form.get("mode") == "vuln")
        return redirect(request.referrer or url_for("index"))

    return app
