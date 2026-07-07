import time

import pytest

from human_auth import Challenge, ChallengeStore, HumanAssertion, HumanIdentity


def test_challenge_message_bytes_are_deterministic():
    c = Challenge(nonce="abc", issued_at=0, expires_at=100, subject="pub", action="do thing")
    assert c.message_bytes() == b"abc|pub|do thing"


def test_challenge_store_rejects_unknown_nonce():
    store = ChallengeStore()
    with pytest.raises(KeyError):
        store.consume("does-not-exist")


def test_challenge_store_rejects_double_consume():
    store = ChallengeStore()
    challenge = store.issue(subject="pub", action="authenticate")
    store.consume(challenge.nonce)
    with pytest.raises(KeyError):
        store.consume(challenge.nonce)


def test_challenge_expiry():
    store = ChallengeStore(ttl_seconds=0.01)
    challenge = store.issue(subject="pub")
    time.sleep(0.05)
    assert challenge.is_expired() is True


def test_assertion_round_trip_is_valid():
    identity = HumanIdentity.generate("Blake")
    assertion = HumanAssertion.create(identity, action="authenticate", nonce="somenonce")
    assert assertion.is_valid() is True


def test_assertion_tampered_action_is_invalid():
    identity = HumanIdentity.generate("Blake")
    assertion = HumanAssertion.create(identity, action="authenticate", nonce="somenonce")
    assertion.action = "wire $999,999 to attacker"  # tamper after signing
    assert assertion.is_valid() is False


def test_identity_export_import_round_trip():
    identity = HumanIdentity.generate("Blake")
    exported = identity.export_private_key_hex()
    restored = HumanIdentity.from_private_key_hex("Blake", exported)
    assert restored.public_key_hex() == identity.public_key_hex()
