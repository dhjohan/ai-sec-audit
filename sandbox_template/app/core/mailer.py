"""Sandbox outbound-mail stub.

The password-reset flow delivers its token through ``send_reset_email``. Tests
read the in-memory ``outbox`` so they never depend on the token format.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OutboundEmail:
    to: str
    token: str


outbox: list[OutboundEmail] = []


def send_reset_email(email: str, token: str) -> None:
    """Record a password-reset message in the sandbox outbox."""
    outbox.append(OutboundEmail(to=email, token=token))
