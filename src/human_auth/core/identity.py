"""HumanIdentity — an Ed25519 keypair bound to a human, not a service account.

Design goals:
- Private keys never leave the human's device in a real deployment (this
  reference implementation keeps everything in-process for clarity/testing).
- Public keys are the only thing the server ever needs to store.
- Every identity carries a plain-language `display_name` because audit logs
  and consent receipts should be readable by a person, not just a machine.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


@dataclass
class HumanIdentity:
    """A human's registered signing identity.

    Create one with `HumanIdentity.generate(display_name)`. Share only the
    output of `.public_key_hex()` with a verifying server — never the private
    key material.
    """

    display_name: str
    _private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, display_name: str) -> "HumanIdentity":
        return cls(display_name=display_name, _private_key=Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def public_key_hex(self) -> str:
        raw = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw.hex()

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def export_private_key_hex(self) -> str:
        """For demo/test persistence only. A real client never exports this."""
        raw = self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return raw.hex()

    @classmethod
    def from_private_key_hex(cls, display_name: str, private_key_hex: str) -> "HumanIdentity":
        raw = bytes.fromhex(private_key_hex)
        return cls(display_name=display_name, _private_key=Ed25519PrivateKey.from_private_bytes(raw))


def public_key_from_hex(public_key_hex: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))


def verify_signature(public_key_hex: str, message: bytes, signature: bytes) -> bool:
    try:
        public_key_from_hex(public_key_hex).verify(signature, message)
        return True
    except InvalidSignature:
        return False
