"""Minimal TOTP implementation used by the SSO service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: bytes, at: int | None = None, step: int = 30, digits: int = 6) -> str:
    return hotp(secret, int((at or time.time()) // step), digits)


#: (secret, counter, code) tuples of already-accepted codes. A code is
#: single-use: accepting it records it here and any later presentation is
#: rejected even if it is still within its valid time window.
_used_codes: set[tuple[bytes, int, str]] = set()


def reset_replay_cache() -> None:
    """Clear consumed-code state. Intended for tests and service restarts."""
    _used_codes.clear()


def verify(secret: bytes, code: str, at: int | None = None, step: int = 30) -> bool:
    """Check a code against the current step and the previous one.

    A successfully matched code is recorded and cannot be accepted again,
    closing the code-replay attack within the ±1 step acceptance window.
    """
    now = int((at or time.time()) // step)
    for counter in (now - 1, now):
        candidate = hotp(secret, counter)
        if hmac.compare_digest(candidate, code):
            key = (secret, counter, code)
            if key in _used_codes:
                return False
            _used_codes.add(key)
            return True
    return False
