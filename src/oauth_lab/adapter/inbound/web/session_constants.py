"""Shared constants for the browser (web) inbound adapters.

The session cookie is an adapter-level concern (the application layer
sees only the signed payload via `SessionSigner`), but its *name* must
be identical across the controllers that read or set it — so it lives
here instead of in any one controller module.
"""

from __future__ import annotations

SESSION_COOKIE_NAME = "oauth_lab_session"
