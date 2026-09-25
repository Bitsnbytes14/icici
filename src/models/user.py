"""User / identity model for the simulation.

Represents the simulated third-party vendor identity (and any other
account) that moves through the access-control pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AccountStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ISOLATED = "ISOLATED"


@dataclass
class User:
    username: str
    role: str

    # Represents the outcome of "assume credentials have been compromised".
    # No real credential theft is implemented anywhere in this codebase.
    credential_compromised: bool = False

    # A benign vendor can also present its own valid password.  Keeping this
    # distinct from ``credential_compromised`` lets normal-session trials use
    # the same authentication pipeline without implying a compromise.
    has_valid_password: bool = False

    # Whether the attacker also possesses a valid second factor for this
    # identity. A phished/leaked password does not imply MFA possession,
    # which is the entire point of the MFA control.
    has_mfa_token: bool = False

    password_verified: bool = False
    mfa_verified: bool = False

    status: AccountStatus = AccountStatus.ACTIVE

    @property
    def is_isolated(self) -> bool:
        return self.status == AccountStatus.ISOLATED

    def isolate(self) -> None:
        self.status = AccountStatus.ISOLATED
