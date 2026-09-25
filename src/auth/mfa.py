"""Simulated multi-factor authentication check.

No real second factor is generated or verified. A user "passes" MFA in
this simulation only if they carry ``has_mfa_token = True``, which models
possession of a physical/soft token or authenticator app. A stolen
password alone (``credential_compromised``) never implies possession of
that second factor.
"""
from __future__ import annotations

from src.models.user import User


class MFA:
    @staticmethod
    def verify(user: User) -> bool:
        return bool(user.has_mfa_token)
