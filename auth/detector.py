"""Access-sequence detector for the two audit findings.

Audit findings:
  1. Expired sessions remain usable (session expiry is never enforced).
  2. Authorization checks only look at the role and never verify resource
     ownership, so any authenticated user can reach another user's resources.

The detector replays a sequence of :class:`AccessEvent` objects against a
session/resource model and reports the first violation on each event, with the
exact evidence that triggered it. It is a pure analysis tool: it does not
modify :mod:`auth.session` and has no dependency on the runtime clock.

Violion classes:
  * ``expired_session``      — unknown id, or session past its TTL at access time
  * ``privilege_escalation`` — authenticated, but the resource belongs to
                               another user and the role has no cross-tenant grant
  * ``replayed_otp``         — an already-consumed TOTP code is presented again
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Sessions older than this many seconds are considered expired. Kept in sync
#: with ``SessionStore.TTL_SECONDS`` so detector and enforcement agree.
DEFAULT_TTL_SECONDS = 3600

#: Roles that may access resources regardless of ownership (break-glass admin).
GLOBAL_ROLES = frozenset({"admin"})


@dataclass(frozen=True)
class SessionInfo:
    """A session as known to the detector's model."""

    user: str
    role: str
    issued_at: int
    mfa: bool = False


@dataclass(frozen=True)
class Resource:
    """A protected resource; ``owner`` is the identity that owns it."""

    resource_id: str
    owner: str


@dataclass(frozen=True)
class AccessEvent:
    """One entry in an access sequence.

    ``otp_code`` is set only on login/MFA events that present a TOTP code;
    presenting a code already seen earlier in the sequence is a replay.
    """

    seq: int
    at: int
    sid: str | None
    resource_id: str | None = None
    action: str = "read"
    otp_code: str | None = None


@dataclass(frozen=True)
class Violation:
    event_seq: int
    kind: str
    reason: str
    evidence: dict


@dataclass
class AccessModel:
    """The state against which a sequence is replayed."""

    sessions: dict[str, SessionInfo]
    resources: dict[str, Resource]
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    global_roles: frozenset = GLOBAL_ROLES
    _consumed_otp: set[str] = field(default_factory=set)

    def detect(self, events: list[AccessEvent]) -> list[Violation]:
        """Return one :class:`Violation` per offending event (empty == clean)."""
        findings: list[Violation] = []
        for ev in events:
            v = self._check_event(ev)
            if v is not None:
                findings.append(v)
        return findings

    # -- internals ---------------------------------------------------------

    def _check_event(self, ev: AccessEvent) -> Violation | None:
        # Replay check first: a reused OTP is invalid even if the session that
        # presents it would otherwise be fine.
        if ev.otp_code is not None:
            if ev.otp_code in self._consumed_otp:
                return Violation(
                    ev.seq,
                    "replayed_otp",
                    "TOTP code was already consumed earlier in the sequence",
                    {"otp_code": ev.otp_code, "first_seen_at": self._first_seen[ev.otp_code]},
                )
            self._consumed_otp.add(ev.otp_code)
            self._first_seen.setdefault(ev.otp_code, ev.at)

        # Finding 1: unknown or expired session.
        if ev.sid is None:
            return Violation(
                ev.seq,
                "expired_session",
                "no session presented",
                {"sid": None, "at": ev.at},
            )
        sess = self.sessions.get(ev.sid)
        if sess is None:
            return Violation(
                ev.seq,
                "expired_session",
                "session id is unknown (rotated, revoked or never issued)",
                {"sid": ev.sid, "at": ev.at},
            )
        age = ev.at - sess.issued_at
        if age >= self.ttl_seconds:
            return Violation(
                ev.seq,
                "expired_session",
                f"session age {age}s exceeds TTL {self.ttl_seconds}s",
                {
                    "sid": ev.sid,
                    "user": sess.user,
                    "issued_at": sess.issued_at,
                    "access_at": ev.at,
                    "ttl_seconds": self.ttl_seconds,
                },
            )

        # Finding 2: role-only authorization ignores resource ownership.
        if ev.resource_id is not None:
            res = self.resources.get(ev.resource_id)
            if res is None:
                return Violation(
                    ev.seq,
                    "privilege_escalation",
                    "resource does not exist",
                    {"resource_id": ev.resource_id},
                )
            if sess.user != res.owner and sess.role not in self.global_roles:
                return Violation(
                    ev.seq,
                    "privilege_escalation",
                    f"role '{sess.role}' does not grant access to another user's resource",
                    {
                        "sid": ev.sid,
                        "actor": sess.user,
                        "role": sess.role,
                        "resource_id": res.resource_id,
                        "owner": res.owner,
                    },
                )
        return None

    def __post_init__(self) -> None:
        # Track when each consumed code was first seen for the evidence dict.
        self._first_seen: dict[str, int] = {}
