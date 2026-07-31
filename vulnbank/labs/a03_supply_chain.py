"""A03:2025 Software Supply Chain Failures — trusting a dependency with a known CVE.

The audit here is a self-contained simulation against a bundled advisory list, so
the lab needs no network access. It illustrates the workflow of SCA (software
composition analysis) and integrity pinning, not a live vulnerability scanner.
"""
from flask import Blueprint

from ..core import page, is_vuln

bp = Blueprint("a03", __name__, url_prefix="/a03")

# Bundled mini advisory database (package -> vulnerable spec, id, summary).
ADVISORIES = [
    ("requests", "<2.20.0", "CVE-2018-18074", "Credential leak on redirect to a different host"),
    ("pyyaml", "<5.4", "CVE-2020-14343", "Arbitrary code execution via unsafe full_load()"),
    ("flask", "<2.2.5", "CVE-2023-30861", "Cookie parsing / caching response disclosure"),
]

VULN_MANIFEST = [("requests", "2.19.1"), ("pyyaml", "5.1"), ("flask", "3.1.0")]
SECURE_MANIFEST = [("requests", "2.32.3"), ("pyyaml", "6.0.2"), ("flask", "3.1.0")]


def _version_lt(v, bound):
    def parse(x):
        return [int(p) for p in x.split(".") if p.isdigit()]
    return parse(v) < parse(bound.lstrip("<"))


def _audit(manifest, pinned_hashes):
    findings = []
    for pkg, ver in manifest:
        for a_pkg, spec, cve, summary in ADVISORIES:
            if a_pkg == pkg and _version_lt(ver, spec):
                findings.append((pkg, ver, cve, summary))
    rows = "".join(
        f"<tr><td>{p}</td><td>{v}</td><td>{c}</td><td>{s}</td></tr>"
        for p, v, c, s in findings)
    hash_note = ("hashes pinned ✓" if pinned_hashes
                 else "no hash pinning — a tampered package would install silently")
    if findings:
        return (f'<div class="res bad"><b>{len(findings)} vulnerable dependencies</b> '
                f'· {hash_note}<table><tr><th>Package</th><th>Version</th><th>Advisory</th>'
                f'<th>Summary</th></tr>{rows}</table></div>')
    return f'<div class="res good">No known-vulnerable dependencies · {hash_note}</div>'


@bp.route("/")
def home():
    vuln = is_vuln("a03")
    manifest = VULN_MANIFEST if vuln else SECURE_MANIFEST
    listing = "\n".join(f"{p}=={v}" for p, v in manifest)
    audit_html = _audit(manifest, pinned_hashes=not vuln)
    body = f"""
    <div class=panel>
      <h2>Current dependency manifest</h2>
      <pre>{listing}{'' if vuln else '  # + --require-hashes'}</pre>
      <p class=note>{'Versions are stale and installed without hash verification.'
                    if vuln else 'Versions are current and installed with pinned hashes.'}</p>
    </div>
    <div class=panel>
      <h2>Composition analysis</h2>
      {audit_html}
    </div>
    <div class=panel>
      <h2>The fix</h2>
      <p class=note>Track dependencies in an SBOM, run SCA in CI to catch known CVEs,
         pin versions <i>and</i> hashes (<code>pip install --require-hashes</code>),
         and verify signatures/provenance so a compromised or typosquatted package
         can't slip in. Toggle to <b>Secure</b> to see the audited, hash-pinned build.</p>
    </div>"""
    return page("a03", body)
