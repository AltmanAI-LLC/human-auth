# Contributing

Thanks for considering a contribution to HumanAuth.

## Ground rule

Every PR should be evaluated against one question: **does this make it
harder to forge, replay, or quietly misattribute a human's approval — or
does it just add features?** This project optimizes for trust and
auditability first, convenience second.

## Getting started

```bash
git clone https://github.com/altmanAI/human-auth.git
cd human-auth
pip install -e ".[dev]"
pytest -q
python -m human_auth.demo
```

## What we're looking for

- Real transport bindings (WebAuthn/FIDO2 device integration, hardware key
  support) implementing the same `Identity` / `Challenge` / `Assertion`
  shape.
- Persistent `ChallengeStore`, `SessionManager`, and `AuditChain` backends
  (Redis, Postgres, an actual append-only ledger) implementing the same
  interfaces as the in-memory reference versions.
- Stronger threat-model coverage: additional tests for edge cases in replay,
  expiry, or forgery resistance.
- Clearer, more human-readable audit/receipt rendering.

## What we're not looking for

- Anything that makes a step-up token reusable across actions, or extends
  its default lifetime "for convenience" — that defeats the point.
- Silent audit-log mutation paths (edits, deletes) of any kind. Append-only
  is a hard invariant, not a suggestion.
- Complexity for its own sake. If a change can't be explained in a sentence,
  simplify it before it's merged.

## Pull requests

1. Fork and branch from `main`.
2. Add or update tests for any behavior change — especially anything
   touching signature verification, replay protection, or the audit chain.
3. Keep PRs focused — one idea per PR.
4. Describe *why* in the PR description, not just *what*.
