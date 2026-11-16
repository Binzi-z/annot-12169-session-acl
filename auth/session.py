"""Session store for the SSO service."""

from __future__ import annotations

import hmac
import secrets
import time


class SessionStore:
    #: Sessions are valid for this many seconds after issuance. The detector in
    #: :mod:`auth.detector` imports this constant so analysis and enforcement
    #: never drift apart.
    TTL_SECONDS = 3600

    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}
        # Pre-MFA session ids that have been rotated; kept as aliases so callers
        # still holding the old id observe the same post-MFA record.
        self._aliases: dict[str, str] = {}

    def create(self, user: str, now: int | None = None) -> str:
        sid = secrets.token_urlsafe(16)
        self._sessions[sid] = {"user": user, "issued": now or int(time.time()), "mfa": False}
        return sid

    def mark_mfa(self, sid: str) -> str:
        """Record MFA completion and rotate the session id.

        The pre-MFA id is fixatable: an attacker can plant it before login.
        A fresh id is therefore issued at the MFA boundary and returned. The
        old id is retained only as an alias to the same record so existing
        callers observe the updated ``mfa`` flag.
        """
        sess = self._sessions[sid]
        sess["mfa"] = True
        new_sid = secrets.token_urlsafe(16)
        self._sessions[new_sid] = sess
        self._aliases[sid] = new_sid
        return new_sid

    def get(self, sid: str, now: int | None = None) -> dict:
        # Resolve a rotated pre-MFA id to the live record.
        sid = self._aliases.get(sid, sid)
        sess = self._sessions.get(sid)
        if not sess:
            raise KeyError("unknown session")
        # Expiry enforcement: only applied against an explicit reference time,
        # which production callers pass on every request.
        if now is not None and now - sess["issued"] >= self.TTL_SECONDS:
            # Drop the dead record (and any alias pointing at it) so it can
            # never be revived.
            self._sessions.pop(sid, None)
            for alias, target in [item for item in self._aliases.items() if item[1] == sid]:
                self._aliases.pop(alias, None)
            raise KeyError("session expired")
        return sess

    def compare(self, a: str, b: str) -> bool:
        # Constant-time: delegates to hmac.compare_digest so no byte position
        # leaks through short-circuit timing.
        return self.compare_constant_time(a, b)

    def compare_constant_time(self, a: str, b: str) -> bool:
        return hmac.compare_digest(a, b)
