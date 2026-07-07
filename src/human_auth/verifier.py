"""HumanAuthVerifier — wires Challenge -> Assertion -> AuditChain -> Session
into a single, reference server-side flow.

This is the load-bearing piece: register a human, issue challenges, verify
signed assertions, refuse replays/expiries/forgeries, mint sessions, and log
every step in a tamper-evident, human-readable audit chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .audit.chain import AuditChain
from .core.assertion import HumanAssertion
from .core.challenge import Challenge, ChallengeStore
from .session.tokens import SessionManager, SessionToken


class AuthError(Exception):
    """Raised for any failed authentication/authorization attempt.
    The message is always plain-language and safe to log/show."""


@dataclass
class RegisteredHuman:
    public_key_hex: str
    display_name: str


class HumanAuthVerifier:
    def __init__(
        self,
        challenge_ttl_seconds: float = 60.0,
        standard_session_ttl: float = 3600.0,
        step_up_session_ttl: float = 120.0,
    ):
        self.challenges = ChallengeStore(ttl_seconds=challenge_ttl_seconds)
        self.sessions = SessionManager(standard_ttl=standard_session_ttl, step_up_ttl=step_up_session_ttl)
        self.audit = AuditChain()
        self._registry: dict[str, RegisteredHuman] = {}

    # -- registration --------------------------------------------------

    def register(self, public_key_hex: str, display_name: str) -> RegisteredHuman:
        if public_key_hex in self._registry:
            raise AuthError(f"'{display_name}' is already registered.")
        human = RegisteredHuman(public_key_hex=public_key_hex, display_name=display_name)
        self._registry[public_key_hex] = human
        self.audit.append(
            summary=f"Registered new human identity: {display_name}.",
            data={"public_key": public_key_hex},
        )
        return human

    def _require_registered(self, public_key_hex: str) -> RegisteredHuman:
        human = self._registry.get(public_key_hex)
        if human is None:
            raise AuthError("Unknown identity — not registered.")
        return human

    # -- challenge/response ---------------------------------------------

    def issue_challenge(self, public_key_hex: str, action: str = "authenticate") -> Challenge:
        self._require_registered(public_key_hex)
        return self.challenges.issue(subject=public_key_hex, action=action)

    def verify_assertion(self, assertion: HumanAssertion) -> Challenge:
        """Verify a signed assertion against its challenge. Returns the consumed
        Challenge on success. Raises AuthError on any failure and logs the
        outcome (success or failure) to the audit chain either way."""
        human = self._require_registered(assertion.subject)

        try:
            challenge = self.challenges.consume(assertion.nonce)
        except KeyError as exc:
            self.audit.append(
                summary=f"Rejected assertion from {human.display_name}: {exc}",
                data={"subject": assertion.subject, "action": assertion.action},
            )
            raise AuthError(str(exc)) from exc

        if challenge.subject != assertion.subject:
            self.audit.append(
                summary=f"Rejected assertion from {human.display_name}: subject mismatch.",
                data={"subject": assertion.subject},
            )
            raise AuthError("Assertion subject does not match the challenge it answers.")

        if challenge.action != assertion.action:
            self.audit.append(
                summary=(
                    f"Rejected assertion from {human.display_name}: action mismatch "
                    f"(challenge was for '{challenge.action}', assertion claims '{assertion.action}')."
                ),
                data={"subject": assertion.subject},
            )
            raise AuthError("Assertion action does not match the challenge it answers.")

        if challenge.is_expired():
            self.audit.append(
                summary=f"Rejected assertion from {human.display_name}: challenge expired.",
                data={"subject": assertion.subject, "action": assertion.action},
            )
            raise AuthError("Challenge has expired — request a fresh one.")

        if not assertion.is_valid():
            self.audit.append(
                summary=f"Rejected assertion from {human.display_name}: invalid signature.",
                data={"subject": assertion.subject, "action": assertion.action},
            )
            raise AuthError("Signature verification failed — forged or corrupted assertion.")

        self.audit.append(
            summary=f"{human.display_name} authorized: {assertion.action}.",
            data={"subject": assertion.subject, "action": assertion.action, "nonce": assertion.nonce},
        )
        return challenge

    # -- sessions --------------------------------------------------------

    def authenticate(self, assertion: HumanAssertion) -> SessionToken:
        """Full login flow: verify the assertion, mint a standard session."""
        self.verify_assertion(assertion)
        token = self.sessions.issue_standard(assertion.subject)
        human = self._require_registered(assertion.subject)
        self.audit.append(
            summary=f"{human.display_name} started a new session.",
            data={"subject": assertion.subject, "token_id": token.token_id},
        )
        return token

    def step_up(self, assertion: HumanAssertion) -> SessionToken:
        """Step-up flow for irreversible actions: verify the assertion (which
        must be for the specific action), mint a short-lived, action-scoped
        session token that authorizes ONLY that action."""
        self.verify_assertion(assertion)
        token = self.sessions.issue_step_up(assertion.subject, action=assertion.action)
        human = self._require_registered(assertion.subject)
        self.audit.append(
            summary=f"{human.display_name} step-up authorized: {assertion.action}.",
            data={"subject": assertion.subject, "token_id": token.token_id, "action": assertion.action},
        )
        return token

    def authorize(self, token_id: str, action: str) -> bool:
        """Check whether an existing session token authorizes a given action."""
        token = self.sessions.get(token_id)
        if token is None:
            return False
        return token.authorizes(action)
