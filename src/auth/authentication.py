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
        # The simulation begins AFTER credential compromise, so a
        # "correct password" check is simply the compromised flag.
        password_ok = user.credential_compromised
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
