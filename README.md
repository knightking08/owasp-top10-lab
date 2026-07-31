# VulnBank — OWASP Top 10:2025 attack & defend lab

A single, self-contained Flask app with one deliberately-vulnerable feature for
every category in the **OWASP Top 10:2025** (the 8th edition, released for OWASP's
20th anniversary). Each lab has a live exploit you run in the browser and a
**Vulnerable / Secure toggle** on the page, so you can fire the same attack against
the broken build and the fixed build and watch the difference.

Everything runs locally with no external calls. It exists to teach the failure
modes and their mitigations — it is intentionally insecure and must never be
exposed to a network.

## Quickstart

```bash
pip install -r requirements.txt
python run.py
# open http://localhost:5000
```

Seeded accounts: `alice / password123`, `bob / hunter2`, `admin / S3cretAdmin!`

Run `python selftest.py` to exercise all ten labs in both modes automatically
(25 checks).

## The ten labs (OWASP Top 10:2025)

| ID | Category | What you exploit | The fix |
|----|----------|------------------|---------|
| **A01** | Broken Access Control | IDOR: read the admin's confidential invoice by changing an id. SSRF: reach an internal-only metadata endpoint. (SSRF was merged into A01 in 2025.) | Deny-by-default ownership checks; block private/loopback ranges + host allow-list |
| **A02** | Security Misconfiguration | Force an error and read the debug page leaking `SECRET_KEY`, DB URI and Stripe key | `DEBUG=False`, generic error + correlation id, log details server-side |
| **A03** | Software Supply Chain Failures | A manifest with a known-CVE dependency installed without hash pinning | SBOM + SCA in CI, pin versions *and* hashes, verify provenance |
| **A04** | Cryptographic Failures | Crack an unsalted MD5 password hash against a wordlist instantly | Salted, slow KDF (bcrypt/scrypt/Argon2id) |
| **A05** | Injection | SQLi login bypass (`' OR '1'='1' --`) and reflected XSS | Parameterized queries; context-aware output encoding + CSP |
| **A06** | Insecure Design | Buy `-100` gift cards → negative total refunds money to your wallet | Enforce business invariants server-side; threat-model the money flow |
| **A07** | Authentication Failures | Brute-force a login with no lockout or rate limit | Lockout/rate limiting, MFA, slow hashing, standard auth frameworks |
| **A08** | Software/Data Integrity Failures | Insecure deserialization: a malicious pickle runs a command on import | Data-only formats (JSON) + HMAC/signature verification; never unpickle untrusted input |
| **A09** | Security Logging & Alerting Failures | Six failed admin logins that leave the security log empty and raise no alert | Log security events *and* alert on thresholds (2025 emphasizes alerting) |
| **A10** | Mishandling of Exceptional Conditions | An entitlement check that throws and **fails open**, granting access on error | Fail closed on security decisions; catch narrowly, log, return a safe state |

A08's payload deliberately runs a harmless fixed command (`whoami`) only to prove
attacker-controlled code executes during `pickle.loads()`. It is not a general
command runner.

## What changed from 2021 (why the labels differ)

- SSRF (was A10:2021) is **folded into A01 Broken Access Control**
- Security Misconfiguration climbed from #5 to **#2**
- Vulnerable & Outdated Components became **A03 Software Supply Chain Failures**
  (broader scope: build systems, distribution, provenance)
- Identification & Authentication Failures → **A07 Authentication Failures**
- Security Logging & Monitoring Failures → **A09 Logging & Alerting Failures**
  (alerting, not just logging)
- **A10 Mishandling of Exceptional Conditions** is brand new for 2025

## Layout

```
owasp-top10-lab/
├── run.py                     # launches the app on :5000
├── selftest.py                # 25 automated attack/defend checks
├── requirements.txt
└── vulnbank/
    ├── __init__.py            # app factory, landing page, security toggle
    ├── core.py                # security-state registry + shared layout
    ├── db.py                  # seeded SQLite (users, invoices)
    └── labs/                  # one module per OWASP category
        ├── a01_access_control.py   ... a10_exceptional.py
```

## How the toggle works

Security level is per-lab, held in memory, and flipped from each page (or via
`POST /set-security/<lab>` with `mode=vuln|secure`). Every lab reads
`core.is_vuln("aNN")` and branches: the vulnerable path is the naive
implementation, the secure path is the mitigated one. Reading the two branches
side by side in each module is the whole point.

## Scope

Deliberately-vulnerable training material for authorized, local use only. Do not
deploy it, expose it to a network, or point its techniques at systems you don't
own and have permission to test.

## References

- OWASP Top 10:2025 — https://owasp.org/Top10/2025/
- Each category page links CWEs and prevention guidance from that index.
