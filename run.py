"""Run VulnBank — the OWASP Top 10:2025 attack & defend lab.

    python run.py

Then open http://localhost:5000 and work through the ten labs. Every lab has a
Vulnerable/Secure toggle right on its page.

Deliberately insecure by design. Run locally only; never expose to a network.
"""
from vulnbank import create_app

if __name__ == "__main__":
    app = create_app()
    print("VulnBank — OWASP Top 10:2025 lab")
    print("Open http://localhost:5000   (local use only)")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
