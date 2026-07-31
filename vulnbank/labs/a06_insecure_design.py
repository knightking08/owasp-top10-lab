"""A06:2025 Insecure Design — a checkout that trusts client-supplied quantity."""
from flask import Blueprint, request

from ..core import page, is_vuln

bp = Blueprint("a06", __name__, url_prefix="/a06")

UNIT_PRICE = 20.00
START_BALANCE = 100.00
_balance = {"amount": START_BALANCE}  # in-memory wallet for the demo


def _result():
    if "qty" not in request.values:
        return ""
    raw = request.values.get("qty", "")
    try:
        qty = int(raw)
    except ValueError:
        return '<div class="res">Quantity must be a whole number.</div>'

    if is_vuln("a06"):
        # BUG: the design never constrains quantity. A negative quantity yields a
        # negative total, which the checkout "refunds" straight into your wallet.
        total = qty * UNIT_PRICE
        _balance["amount"] -= total  # subtracting a negative = free money
        note = ("Negative total refunded to your wallet — you just paid yourself."
                if total < 0 else "Charged.")
        cls = "bad" if total < 0 else ""
        return (f'<div class="res {cls}">Quantity {qty} × ${UNIT_PRICE:.2f} = '
                f'${total:.2f}. Wallet now <b>${_balance["amount"]:.2f}</b>. {note}</div>')

    # FIX: enforce the invariant server-side; recompute price, never trust the client.
    if qty < 1:
        return ('<div class="res good">Rejected: quantity must be at least 1. '
                'The invariant is enforced on the server, so negative-quantity abuse '
                'is impossible.</div>')
    total = qty * UNIT_PRICE
    if total > _balance["amount"]:
        return f'<div class="res good">Rejected: insufficient funds for ${total:.2f}.</div>'
    _balance["amount"] -= total
    return f'<div class="res good">Charged ${total:.2f}. Wallet now ${_balance["amount"]:.2f}.</div>'


@bp.route("/reset")
def reset():
    _balance["amount"] = START_BALANCE
    return home()


@bp.route("/", methods=["GET", "POST"])
def home():
    body = f"""
    <div class=panel>
      <h2>Buy gift cards (${UNIT_PRICE:.2f} each)</h2>
      <p class=note>Wallet balance: <b>${_balance["amount"]:.2f}</b>. Now try buying
         <code>-100</code> gift cards. <a href="/a06/reset">reset wallet</a></p>
      <form class=inline method=get>
        <div><label>Quantity</label><input name=qty value="{request.values.get('qty','-100')}"></div>
        <div style="flex:0"><button class=btn>Checkout</button></div>
      </form>
      {_result()}
    </div>
    <div class=panel>
      <h2>The fix</h2>
      <p class=note>Insecure design isn't a missing patch — it's a missing control. Model
         the abuse case during design and enforce business invariants server-side:
         quantity ≥ 1, prices computed from trusted data, funds checked before charging.
         Threat-model the money flows before writing the endpoint.</p>
    </div>"""
    return page("a06", body)
