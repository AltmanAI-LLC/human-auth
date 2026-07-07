"""HumanAuth — a cryptographic protocol for proving a *human* authorized an action.

Built by AltmanAI, a project of Altman Family Group LLC.

HumanAuth is not "just another login system." Passwords and even passkeys prove
*a credential* was presented. HumanAuth additionally produces a signed,
tamper-evident, human-readable receipt for every consequential action — the
same "human-first" philosophy as the companion `human-first-ai` repo, applied
to authentication and authorization instead of orchestration.
"""

__version__ = "0.1.0"

from .core.identity import HumanIdentity
from .core.challenge import Challenge, ChallengeStore
from .core.assertion import HumanAssertion
from .session.tokens import SessionToken, SessionManager
from .verifier import HumanAuthVerifier, AuthError

__all__ = [
    "HumanIdentity",
    "Challenge",
    "ChallengeStore",
    "HumanAssertion",
    "SessionToken",
    "SessionManager",
    "HumanAuthVerifier",
    "AuthError",
]
