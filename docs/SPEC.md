# HumanAuth Protocol Spec (v0.1)

## Problem statement

Most auth proves *a credential was presented*. It does not prove *a human
deliberately approved this specific consequential action, right now*, and it
rarely leaves behind a receipt that a non-technical person — or an auditor,
or a court — can actually read and trust.

HumanAuth closes that gap with three primitives:

1. **Identity** — an Ed25519 keypair bound to a human's device. Only the
   public key ever touches the server.
2. **Challenge/Assertion** — a single-use, time-boxed, action-scoped
   challenge-response exchange (conceptually a lightweight sibling of
   WebAuthn/FIDO2), producing a **HumanAssertion**: a signed statement of
   *who*, *what action*, and *when*.
3. **Audit Chain** — every registration, login, step-up, and rejection is
   appended to a hash-chained log. Tampering with any past entry breaks every
   hash after it — `AuditChain.verify()` finds the exact break point.

## Threat model

HumanAuth is designed to resist:

- **Replay attacks** — every challenge nonce is single-use; `ChallengeStore`
  rejects reuse (`AuthError`).
- **Stale approvals** — challenges expire (`challenge_ttl_seconds`, default
  60s); step-up sessions expire fast (default 120s) since they gate
  irreversible actions.
- **Forged/corrupted signatures** — every assertion is verified with
  Ed25519; a single bit flip anywhere in the signed payload invalidates it.
- **Action substitution** — a challenge issued for "authenticate" cannot be
  reused to authorize "wire $5,000 to Acme LLC"; the action string is part of
  the signed payload and is checked on verification.
- **Silent audit tampering** — the hash chain makes any retroactive edit to
  the log immediately detectable.

HumanAuth does **not** by itself solve:
- Private key custody on the human's device (use platform secure enclaves /
  hardware keys in a real deployment — this reference implementation keeps
  keys in-process for clarity and testing).
- Network transport security (use TLS; that's infrastructure, not protocol).
- Identity proofing ("is this human who they claim to be in the real
  world?") — HumanAuth proves *consistency* of a registered identity across
  time, not real-world KYC.

## Two authorization levels

| Level | TTL (default) | Use for |
|---|---|---|
| `STANDARD` | 1 hour | Reading data, navigation, anything reversible |
| `STEP_UP` | 2 minutes, single action | Spending money, deleting data, publishing publicly — anything irreversible |

An application decides which actions require `step_up()` re-authentication.
The protocol's job is to guarantee that when it says a human approved
`"wire $5,000 to Acme LLC"`, that's exactly and only what happened.

## Why this belongs next to `human-first-ai`

`human-first-ai`'s Values Engine decides whether an *AI system's* action
needs a human checkpoint. HumanAuth is the primitive that makes that
checkpoint cryptographically real and auditable, instead of just a
print statement or a UI toast. The two are meant to compose: an
`ALLOW_WITH_CHECKPOINT` decision from the Values Engine is exactly the moment
to call `HumanAuthVerifier.step_up()`.
