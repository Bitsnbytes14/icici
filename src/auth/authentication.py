"""Authentication service.

Represents password-only authentication (baseline) versus
password + simulated MFA (protected). No real credentials, hashing, or
network calls are involved anywhere in this module.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.auth.mfa import MFA
from src.models.user import User


@dataclass
class AuthResult:
    success: bool
    reason: str


class Authenticator:
    def __init__(self, mfa_required: bool):
        self.mfa_required = mfa_required

    def authenticate(self, user: User) -> AuthResult:
        # A password may be accepted either because the adversarial model
        # assumes it was compromised, or because a benign vendor supplied its
        # own valid credentials.  Neither case represents real credential
        # verification.
        password_ok = user.credential_compromised or user.has_valid_password
        user.password_verified = password_ok
        if not password_ok:
            return AuthResult(False, "INVALID_CREDENTIALS")

        if not self.mfa_required:
            user.mfa_verified = True
            return AuthResult(True, "OK")

        mfa_ok = MFA.verify(user)
        user.mfa_verified = mfa_ok
        if not mfa_ok:
            return AuthResult(False, "MFA_FAILED")

        return AuthResult(True, "OK")
