"""Pytest fixtures shared across the suite.

The replay cache in :mod:`auth.totp` is intentionally process-global, so two
independent tests that happen to present the same (secret, counter, code)
would otherwise interfere with each other. Reset it before every test.
"""

import pytest

from auth.totp import reset_replay_cache


@pytest.fixture(autouse=True)
def _reset_totp_replay_cache():
    reset_replay_cache()
    yield
    reset_replay_cache()
