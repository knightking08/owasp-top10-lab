# A09:2025 — Security Logging & Monitoring Failures

## The vulnerability

Security logging and monitoring failures cover the case where an application does not record security-relevant events, records them without enough context to investigate, or records them but never *alerts* on them. The 2025 wording puts weight on the alerting half: logs that no one acts on in time catch nothing. An attack that leaves no trace — and triggers no notification — is effectively invisible to defenders, which lets an intrusion continue undetected for far longer than it otherwise would.

This lab demonstrates the failure with a textbook brute-force signature: six failed administrator logins from a single IP address.

## The attack

Open the A09 lab and click **Simulate 6 failed admin logins**. The lab fires six `AUTH_FAIL user=admin` events from IP `203.0.113.9` — the classic shape of a credential brute-force attempt against a privileged account.

In **vulnerable mode**, those six failures happen, but nothing is written to the security log and no alert fires. The log panel below the button stays empty. From a defender's point of view, the attack never happened: there is no record to review, no signal to correlate, and no notification to respond to. An attacker could keep guessing indefinitely and no one would know.

## Why it happens

In vulnerable mode the code path that would record each failed login is skipped entirely. The failed authentications occur inside the application, but the branch that calls the log-writing routine only runs in secure mode. Because nothing is recorded, the downstream alerting logic — which counts recent auth failures and raises an alert once they cross a threshold — never has any data to act on. The result is a security event that is real but leaves no trace and produces no warning.

## The fix
ABC 123
In **secure mode** the same six failed logins are handled correctly:

1. **Each security-relevant event is logged.** Every failed admin login is recorded with context — the event type, the targeted user, and the source IP — so an investigator can reconstruct what happened.
2. **The events are correlated and alerted on.** The lab counts recent authentication failures, and once they cross the alert threshold it raises an explicit alert ("possible brute force") so defenders are notified while the attack is still in progress, not after the fact.

The general remediation, following the OWASP guidance:

- Log security-relevant events — authentication failures, access-control denials, and input-validation failures — with enough context to investigate.
- Ship those logs to tamper-resistant, centralized storage so an attacker who compromises one host cannot quietly erase their trail.
- **Alert** on suspicious patterns. Excellent logs with no alerting still leave defenders blind in the moment; detection has to be timely to matter.

## Try it yourself

- Toggle the lab to **secure** mode and run the simulation again. This time the six failures are logged, correlated, and — once past the threshold — an alert is raised.
- Use the **clear log** link to reset between runs and watch the difference between the two modes side by side.

The contrast is the whole point: identical attacker behavior is invisible in one mode and loudly flagged in the other. The only thing that changed is whether the application bothered to log and alert.