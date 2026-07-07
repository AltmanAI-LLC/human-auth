"""Short-lived, scoped session tokens issued after a successful HumanAuth
challenge/response — and step-up re-authentication for irreversible actions.

Ordinary auth gets you a `standard` session: fine for reading data, browsing,
anything reversible. Anything irreversible (spending money, deleting data,
publishing publicly) requires a fresh `step_up` assertion, tied to a
description of the specific action — a session token from an hour ago should
never be enough to authorize a wire transfer.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from enum import Enum


class SessionLevel(Enum):
    STANDARD = "standard"
    STEP_UP = "step_up"


@dataclass
class SessionToken:
    token_id: str
    subject: str  # public_key_hex of the authenticated human
    level: SessionLevel
    issued_at: float
    expires_at: float
    action: str | None = None  # set only for STEP_UP tokens — the exact action it authorizes

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) > self.expires_at

    def authorizes(self, action: str) -> bool:
        """STANDARD tokens authorize any reversible/informational action.
        STEP_UP tokens authorize only the single action they were minted for."""
        if self.is_expired():
            return False
        if self.level == SessionLevel.STANDARD:
            return True
        return self.action == action


class SessionManager:
    def __init__(self, standard_ttl: float = 3600.0, step_up_ttl: float = 120.0):
        self.standard_ttl = standard_ttl
        self.step_up_ttl = step_up_ttl
        self._tokens: dict[str, SessionToken] = {}

    def issue_standard(self, subject: str) -> SessionToken:
        return self._issue(subject, SessionLevel.STANDARD, self.standard_ttl, action=None)

    def issue_step_up(self, subject: str, action: str) -> SessionToken:
        return self._issue(subject, SessionLevel.STEP_UP, self.step_up_ttl, action=action)

    def _issue(self, subject: str, level: SessionLevel, ttl: float, action: str | None) -> SessionToken:
        now = time.time()
        token = SessionToken(
            token_id=os.urandom(16).hex(),
            subject=subject,
            level=level,
            issued_at=now,
            expires_at=now + ttl,
            action=action,
        )
        self._tokens[token.token_id] = token
        return token

    def get(self, token_id: str) -> SessionToken | None:
        return self._tokens.get(token_id)

    def revoke(self, token_id: str) -> bool:
        return self._tokens.pop(token_id, None) is not None
