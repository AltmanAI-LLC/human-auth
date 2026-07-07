"""HumanAssertion — a signed, human-readable receipt proving *this specific
human* authorized *this specific action* at *this specific time*.

This is the piece that goes beyond ordinary authentication. Logging in proves
someone with the right key showed up. A HumanAssertion proves they explicitly
saw and approved a described action — the cryptographic equivalent of a
signature on a paper consent form, and the anchor for HumanAuth's audit chain.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .identity import HumanIdentity, verify_signature


@dataclass
class HumanAssertion:
    subject: str        # public_key_hex of the human who signed
    action: str          # plain-language description, e.g. "wire $5,000 to Acme LLC"
    nonce: str           # the challenge nonce this assertion answers
    timestamp: float
    signature: bytes

    def message_bytes(self) -> bytes:
        return f"{self.nonce}|{self.subject}|{self.action}|{self.timestamp}".encode()

    def is_valid(self) -> bool:
        return verify_signature(self.subject, self.message_bytes(), self.signature)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "action": self.action,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "signature": self.signature.hex(),
        }

    @classmethod
    def create(cls, identity: HumanIdentity, action: str, nonce: str) -> "HumanAssertion":
        """Build and sign a fresh assertion. `nonce` must match a live, unconsumed
        Challenge that was issued with the same `action` string."""
        subject = identity.public_key_hex()
        timestamp = time.time()
        # sign the exact same layout is_valid()/message_bytes() will re-derive
        payload = f"{nonce}|{subject}|{action}|{timestamp}".encode()
        signature = identity.sign(payload)
        return cls(subject=subject, action=action, nonce=nonce, timestamp=timestamp, signature=signature)
