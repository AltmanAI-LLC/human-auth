"""Challenge issuance and anti-replay tracking.

A Challenge is a random, single-use, time-boxed nonce the server hands the
human's device before it will accept a signature. Replaying an old signed
challenge, or a stale one, must always fail — that's the whole point.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass


@dataclass
class Challenge:
    nonce: str
    issued_at: float
    expires_at: float
    subject: str  # public_key_hex of the identity this challenge was issued to
    action: str = "authenticate"  # plain-language description of what's being authorized

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) > self.expires_at

    def message_bytes(self) -> bytes:
        """The exact bytes a human's device must sign to answer this challenge."""
        return f"{self.nonce}|{self.subject}|{self.action}".encode()


class ChallengeStore:
    """In-memory challenge issuance + single-use enforcement.

    Swap for Redis/DB in production — the interface is intentionally tiny.
    """

    def __init__(self, ttl_seconds: float = 60.0):
        self.ttl_seconds = ttl_seconds
        self._issued: dict[str, Challenge] = {}
        self._consumed: set[str] = set()

    def issue(self, subject: str, action: str = "authenticate") -> Challenge:
        nonce = os.urandom(16).hex()
        now = time.time()
        challenge = Challenge(
            nonce=nonce,
            issued_at=now,
            expires_at=now + self.ttl_seconds,
            subject=subject,
            action=action,
        )
        self._issued[nonce] = challenge
        return challenge

    def consume(self, nonce: str) -> Challenge:
        """Fetch and invalidate a challenge. Raises KeyError if unknown or already used."""
        if nonce in self._consumed:
            raise KeyError(f"Challenge '{nonce}' was already used (replay rejected).")
        if nonce not in self._issued:
            raise KeyError(f"Challenge '{nonce}' is unknown.")
        challenge = self._issued.pop(nonce)
        self._consumed.add(nonce)
        return challenge
