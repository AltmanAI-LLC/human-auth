# HumanAuth

**A cryptographic protocol proving a human — not just a credential — authorized an action.**

Built by **AltmanAI**, a project of **Altman Family Group LLC**.

Most authentication proves *a key was presented*. HumanAuth goes one step
further: every consequential action produces a signed, timestamped,
human-readable **consent receipt**, chained into a tamper-evident audit log.
Replaying an old approval, reusing a login to authorize a wire transfer, or
quietly editing the log after the fact — all cryptographically detected.

```
Identity (Ed25519 keypair)
      │
      ▼
Challenge (single-use, time-boxed, action-scoped nonce)
      │
      ▼
HumanAssertion (signed: who + what action + when)
      │
      ▼
HumanAuthVerifier ──► Session (standard / step-up) ──► AuditChain (hash-chained, tamper-evident)
```

## Why

- **Passkey-grade crypto** — Ed25519 signatures, no passwords, no shared secrets.
- **Step-up for irreversible actions** — a login from an hour ago should
  never be enough to authorize spending money. Step-up tokens are
  short-lived and scoped to *one specific action*.
- **Anti-replay by construction** — every challenge is single-use; reuse is
  rejected, not just discouraged.
- **Tamper-evident audit trail** — every registration, login, approval, and
  rejection is hash-chained. `verifier.audit.verify()` tells you exactly
  where tampering happened, if it did.
- **Plain-language receipts** — "Blake Altman authorized: wire $5,000 to
  Acme LLC" — not an opaque JSON blob. Explainability is a UX requirement
  here, the same philosophy as our companion repo
  [`human-first-ai`](https://github.com/altmanAI/human-first-ai).

## Quickstart

```bash
pip install -e ".[dev]"
python -m human_auth.demo
pytest
```

## Example

```python
from human_auth import HumanAuthVerifier, HumanIdentity, HumanAssertion

verifier = HumanAuthVerifier()

# Registration (once, per device)
blake = HumanIdentity.generate("Blake Altman")
verifier.register(blake.public_key_hex(), blake.display_name)

# Ordinary login
challenge = verifier.issue_challenge(blake.public_key_hex(), action="authenticate")
assertion = HumanAssertion.create(blake, action="authenticate", nonce=challenge.nonce)
session = verifier.authenticate(assertion)

# Irreversible action -> step-up re-auth, scoped to that one action
action = "wire $5,000 to Acme LLC"
challenge = verifier.issue_challenge(blake.public_key_hex(), action=action)
assertion = HumanAssertion.create(blake, action=action, nonce=challenge.nonce)
step_up_token = verifier.step_up(assertion)

assert verifier.authorize(step_up_token.token_id, action) is True
assert verifier.authorize(step_up_token.token_id, "delete all data") is False

print(verifier.audit.render())
```

## Status

Early, intentionally minimal reference implementation — a clean protocol
others can adopt, harden, or challenge. Not yet audited for production use.
See [`docs/SPEC.md`](docs/SPEC.md) for the full protocol spec and threat model.

## Contributing

Issues and PRs welcome, especially ones that make the protocol more
resistant to real attacks or the audit trail more genuinely readable by
non-engineers. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and our
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

MIT — see [`LICENSE`](LICENSE).
