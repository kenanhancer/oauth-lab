"""DeviceCode entity — state machine for the device authorization flow.

Scenario: device flow (RFC 8628). No HTTP, no DB — pure domain test.

Location: `tests/unit/device_flow/` — folder carries the scenario.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.device_code import DeviceCode
from oauth_lab.domain.model.scope import Scope, ScopeSet

_NOW = datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


def _make_code(
    *,
    expires_in: timedelta = timedelta(minutes=30),
    interval: int = 5,
    last_polled_at: datetime | None = None,
    user_sub: str | None = None,
    denied: bool = False,
) -> DeviceCode:
    return DeviceCode(
        device_code="opaque-device-code",
        user_code="BCDF-GHJK",
        client_id=ClientId("demo-device"),
        scope=ScopeSet(frozenset({Scope("read")})),
        issued_at=_NOW,
        expires_at=_NOW + expires_in,
        interval=interval,
        last_polled_at=last_polled_at,
        user_sub=user_sub,
        denied=denied,
    )


class TestDeviceCodeStateMachine:
    def test_pending_by_default(self) -> None:
        code = _make_code()
        assert code.is_pending()
        assert not code.is_approved()
        assert not code.is_denied()

    def test_approve_sets_user_sub(self) -> None:
        code = _make_code()
        approved = code.approve("user-alice")
        assert approved.is_approved()
        assert approved.user_sub == "user-alice"
        # original is immutable
        assert code.user_sub is None

    def test_deny_clears_user_sub(self) -> None:
        code = _make_code(user_sub="user-alice")                 # previously approved
        denied = code.deny()
        assert denied.is_denied()
        assert denied.user_sub is None
        assert not denied.is_approved()

    def test_is_expired(self) -> None:
        code = _make_code(expires_in=timedelta(seconds=10))
        assert not code.is_expired(_NOW)
        assert code.is_expired(_NOW + timedelta(seconds=11))

    def test_can_poll_at_no_previous_poll(self) -> None:
        code = _make_code()
        assert code.can_poll_at(_NOW)

    def test_can_poll_at_within_interval_is_false(self) -> None:
        code = _make_code(interval=5, last_polled_at=_NOW)
        # 3 seconds later — still within interval
        assert not code.can_poll_at(_NOW + timedelta(seconds=3))

    def test_can_poll_at_after_interval_is_true(self) -> None:
        code = _make_code(interval=5, last_polled_at=_NOW)
        # 5 seconds later — interval elapsed exactly
        assert code.can_poll_at(_NOW + timedelta(seconds=5))
        assert code.can_poll_at(_NOW + timedelta(seconds=6))

    def test_mark_polled_updates_timestamp(self) -> None:
        code = _make_code()
        polled = code.mark_polled(_NOW + timedelta(seconds=1))
        assert polled.last_polled_at == _NOW + timedelta(seconds=1)
        assert code.last_polled_at is None                       # immutable
