"""The transport binding of draft 13.3.1: the extension that carries a transport
profile declaration (draft 21, Appendix A.2) and the transport profiles a contract
can name."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from hop_top_pact.core.types import JSONObject

__all__ = [
    "EXTENSION_TRANSPORT_PROFILE",
    "TRANSPORT_HTTPS",
    "TRANSPORT_STDIO_IPC",
    "transport_of",
]

EXTENSION_TRANSPORT_PROFILE: Final = "pact-transport-profile-v1"
"""The first-party extension whose value is a TransportDeclaration (Appendix A.3)."""
TRANSPORT_HTTPS: Final = "https"
"""The HTTPS baseline of draft 13, which has no declaration."""
TRANSPORT_STDIO_IPC: Final = "stdio-ipc"
"""The local IPC and stdio profile of draft 13.3."""


def transport_of(extensions: JSONObject | None) -> str:
    """The transport the extensions name (draft 13.3.1): the transport_profile of the
    TransportDeclaration they carry under EXTENSION_TRANSPORT_PROFILE, or
    TRANSPORT_HTTPS when they carry none. A declaration without a string
    transport_profile names no transport: the result is empty, which no channel
    matches."""
    if extensions is None or EXTENSION_TRANSPORT_PROFILE not in extensions:
        return TRANSPORT_HTTPS
    declaration = extensions[EXTENSION_TRANSPORT_PROFILE]
    if not isinstance(declaration, Mapping):
        return ""
    profile = declaration.get("transport_profile")
    return profile if isinstance(profile, str) else ""
