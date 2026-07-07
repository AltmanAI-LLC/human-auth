"""Run with: python -m human_auth.demo

Walks through: registration, ordinary login, an irreversible action that
requires step-up re-authentication, a rejected replay attack, and finally
prints the tamper-evident audit chain.
"""

from human_auth import HumanAssertion, HumanAuthVerifier, HumanIdentity, AuthError


def main():
    verifier = HumanAuthVerifier()

    print("=== Registering Blake's device identity ===")
    blake = HumanIdentity.generate("Blake Altman")
    verifier.register(blake.public_key_hex(), blake.display_name)
    print(f"Registered. Public key: {blake.public_key_hex()[:16]}...")

    print("\n=== Ordinary login ===")
    challenge = verifier.issue_challenge(blake.public_key_hex(), action="authenticate")
    assertion = HumanAssertion.create(blake, action="authenticate", nonce=challenge.nonce)
    session = verifier.authenticate(assertion)
    print(f"Logged in. Standard session token: {session.token_id[:16]}...")

    print("\n=== Irreversible action: requires step-up ===")
    action = "wire $5,000 to Acme LLC"
    step_up_challenge = verifier.issue_challenge(blake.public_key_hex(), action=action)
    step_up_assertion = HumanAssertion.create(blake, action=action, nonce=step_up_challenge.nonce)
    step_up_token = verifier.step_up(step_up_assertion)
    print(f"Step-up granted for exactly one action: '{action}'")
    print(f"  Authorizes this action? {verifier.authorize(step_up_token.token_id, action)}")
    print(f"  Authorizes a different action? {verifier.authorize(step_up_token.token_id, 'delete all data')}")

    print("\n=== Replay attack (reusing the login assertion) ===")
    try:
        verifier.verify_assertion(assertion)
    except AuthError as e:
        print(f"Rejected as expected: {e}")

    print("\n=== Transparency / Audit Chain ===")
    print(verifier.audit.render())
    intact, broken_at = verifier.audit.verify()
    print(f"\nChain intact: {intact}")


if __name__ == "__main__":
    main()
