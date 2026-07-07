import time

import pytest

from human_auth import HumanAssertion, HumanAuthVerifier, HumanIdentity, AuthError


def _register(verifier: HumanAuthVerifier, name: str) -> HumanIdentity:
    identity = HumanIdentity.generate(name)
    verifier.register(identity.public_key_hex(), name)
    return identity


def test_registration_is_idempotent_rejects_duplicates():
    verifier = HumanAuthVerifier()
    identity = _register(verifier, "Blake")
    with pytest.raises(AuthError):
        verifier.register(identity.public_key_hex(), "Blake")


def test_full_login_flow_succeeds():
    verifier = HumanAuthVerifier()
    identity = _register(verifier, "Blake")

    challenge = verifier.issue_challenge(identity.public_key_hex(), action="authenticate")
    assertion = HumanAssertion.create(identity, action="authenticate", nonce=challenge.nonce)

    token = verifier.authenticate(assertion)
    assert token.subject == identity.public_key_hex()
    assert verifier.authorize(token.token_id, "read profile") is True


def test_replayed_assertion_is_rejected():
    verifier = HumanAuthVerifier()
    identity = _register(verifier, "Blake")

    challenge = verifier.issue_challenge(identity.public_key_hex(), action="authenticate")
    assertion = HumanAssertion.create(identity, action="authenticate", nonce=challenge.nonce)

    verifier.authenticate(assertion)
    with pytest.raises(AuthError):
        verifier.verify_assertion(assertion)  # same nonce again -> replay


def test_forged_signature_is_rejected():
    verifier = HumanAuthVerifier()
    identity = _register(verifier, "Blake")
    impostor = HumanIdentity.generate("Impostor")

    challenge = verifier.issue_challenge(identity.public_key_hex(), action="authenticate")
    # impostor signs, but claims to be `identity`'s public key
    forged = HumanAssertion.create(impostor, action="authenticate", nonce=challenge.nonce)
    forged.subject = identity.public_key_hex()  # tamper with the claimed subject

    with pytest.raises(AuthError):
        verifier.verify_assertion(forged)


def test_expired_challenge_is_rejected():
    verifier = HumanAuthVerifier(challenge_ttl_seconds=0.01)
    identity = _register(verifier, "Blake")

    challenge = verifier.issue_challenge(identity.public_key_hex(), action="authenticate")
    time.sleep(0.05)
    assertion = HumanAssertion.create(identity, action="authenticate", nonce=challenge.nonce)

    with pytest.raises(AuthError):
        verifier.verify_assertion(assertion)


def test_action_mismatch_is_rejected():
    verifier = HumanAuthVerifier()
    identity = _register(verifier, "Blake")

    challenge = verifier.issue_challenge(identity.public_key_hex(), action="wire $5,000 to Acme LLC")
    assertion = HumanAssertion.create(identity, action="something else entirely", nonce=challenge.nonce)

    with pytest.raises(AuthError):
        verifier.verify_assertion(assertion)


def test_step_up_token_only_authorizes_its_own_action():
    verifier = HumanAuthVerifier()
    identity = _register(verifier, "Blake")

    action = "wire $5,000 to Acme LLC"
    challenge = verifier.issue_challenge(identity.public_key_hex(), action=action)
    assertion = HumanAssertion.create(identity, action=action, nonce=challenge.nonce)

    token = verifier.step_up(assertion)
    assert verifier.authorize(token.token_id, action) is True
    assert verifier.authorize(token.token_id, "delete all data") is False


def test_standard_session_does_not_authorize_step_up_actions_implicitly():
    """A standard login session is fine for reversible/informational things,
    but the design intent is that irreversible actions go through step_up()
    explicitly at the call site — authorize() itself is permissive for
    STANDARD tokens by design, so this test documents that boundary."""
    verifier = HumanAuthVerifier()
    identity = _register(verifier, "Blake")

    challenge = verifier.issue_challenge(identity.public_key_hex(), action="authenticate")
    assertion = HumanAssertion.create(identity, action="authenticate", nonce=challenge.nonce)
    token = verifier.authenticate(assertion)

    # Standard tokens authorize by policy at the application layer; HumanAuth's
    # job is to make sure a *fresh, specific* human assertion exists whenever
    # the app chooses to require step_up() for a given action.
    assert verifier.authorize(token.token_id, "read profile") is True


def test_audit_chain_is_tamper_evident():
    verifier = HumanAuthVerifier()
    identity = _register(verifier, "Blake")
    challenge = verifier.issue_challenge(identity.public_key_hex(), action="authenticate")
    assertion = HumanAssertion.create(identity, action="authenticate", nonce=challenge.nonce)
    verifier.authenticate(assertion)

    intact, broken_at = verifier.audit.verify()
    assert intact is True
    assert broken_at is None

    # tamper with an entry directly
    verifier.audit._entries[0].summary = "Registered new human identity: NOT Blake."
    intact, broken_at = verifier.audit.verify()
    assert intact is False
    assert broken_at == 0
