"""End-to-end demonstration of the access-sequence detector.

Run:  python -m scripts.demo_detector

Each scenario feeds an access sequence to AccessModel.detect() and prints the
verdict with evidence. Attack scenarios must produce exactly the expected
violation; legitimate scenarios must produce none (zero false positives).
"""

from __future__ import annotations

from auth.detector import AccessEvent, AccessModel, Resource, SessionInfo
from auth.session import SessionStore

# A model with two tenants, one shared resource each, and a break-glass admin.
def build_model() -> AccessModel:
    return AccessModel(
        sessions={
            "s-alice": SessionInfo(user="alice", role="user", issued_at=1000),
            "s-bob": SessionInfo(user="bob", role="user", issued_at=1000),
            "s-admin": SessionInfo(user="root", role="admin", issued_at=1000),
        },
        resources={
            "doc-alice": Resource("doc-alice", owner="alice"),
            "doc-bob": Resource("doc-bob", owner="bob"),
        },
        ttl_seconds=SessionStore.TTL_SECONDS,
    )


def show(title: str, findings, expected: int) -> bool:
    ok = len(findings) == expected
    print(f"\n=== {title} ===")
    if not findings:
        print("  verdict: ALLOW (no violation)")
    for f in findings:
        print(f"  verdict: DENY [{f.kind}] seq={f.event_seq}")
        print(f"    reason:   {f.reason}")
        print(f"    evidence: {f.evidence}")
    print(f"  expected {expected} violation(s): {'PASS' if ok else 'FAIL'}")
    return ok


def main() -> None:
    results: list[bool] = []

    # 1. Expired session: same id reused beyond the TTL (audit finding #1).
    m = build_model()
    findings = m.detect([
        AccessEvent(seq=1, at=1000, sid="s-alice", resource_id="doc-alice"),
        AccessEvent(seq=2, at=1000 + SessionStore.TTL_SECONDS, sid="s-alice",
                    resource_id="doc-alice"),
    ])
    results.append(show("expired session reused after TTL", findings, 1))

    # 2. Privilege escalation: bob's valid, unexpired session opens alice's
    #    resource. Role-only checks would allow this; ownership check denies.
    m = build_model()
    findings = m.detect([
        AccessEvent(seq=1, at=1100, sid="s-bob", resource_id="doc-alice"),
    ])
    results.append(show("cross-tenant access (ownership bypass)", findings, 1))

    # 3. Rotated/unknown id: after MFA rotation the fixated pre-MFA id is no
    #    longer a live session in the model -> denied as unknown session.
    m = build_model()
    findings = m.detect([
        AccessEvent(seq=1, at=1100, sid="fixated-old-id", resource_id="doc-alice"),
    ])
    results.append(show("fixated/rotated session id", findings, 1))

    # 4. Replayed TOTP: same code presented twice in one sequence.
    m = build_model()
    findings = m.detect([
        AccessEvent(seq=1, at=1100, sid="s-alice", otp_code="921300"),
        AccessEvent(seq=2, at=1110, sid="s-alice", otp_code="921300"),
    ])
    results.append(show("TOTP code replay", findings, 1))

    # 5. Legitimate traffic — must stay clean (zero false positives):
    #    owner access, admin cross-tenant access, access just before TTL,
    #    and a fresh OTP code on the second login event.
    m = build_model()
    findings = m.detect([
        AccessEvent(seq=1, at=1000, sid="s-alice", resource_id="doc-alice"),
        AccessEvent(seq=2, at=1000 + SessionStore.TTL_SECONDS - 1,
                    sid="s-alice", resource_id="doc-alice"),
        AccessEvent(seq=3, at=1200, sid="s-bob", resource_id="doc-bob"),
        AccessEvent(seq=4, at=1300, sid="s-admin", resource_id="doc-alice"),
        AccessEvent(seq=5, at=1400, sid="s-bob", otp_code="111111"),
        AccessEvent(seq=6, at=1410, sid="s-bob", otp_code="222222"),
    ])
    results.append(show("legitimate mixed traffic (zero false positives)", findings, 0))

    print("\n" + ("ALL SCENARIOS PASS" if all(results) else "SOME SCENARIOS FAILED"))
    raise SystemExit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
