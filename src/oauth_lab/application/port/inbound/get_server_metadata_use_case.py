"""Inbound port — authorization-server discovery metadata.

Two documents, one source of truth:

- `oauth_metadata()` — RFC 8414 Authorization Server Metadata
  (`/.well-known/oauth-authorization-server`).
- `openid_metadata()` — OIDC Discovery 1.0
  (`/.well-known/openid-configuration`), a superset of the former.

Returned as plain dicts because the documents are open-ended JSON by
design (RFC 8414 §2 allows arbitrary extension members). Sync — the
metadata is assembled from in-memory capability introspection, no I/O.
"""

from __future__ import annotations

from typing import Protocol


class GetServerMetadataUseCase(Protocol):
    def oauth_metadata(self) -> dict[str, object]:
        """RFC 8414 §2 metadata document."""
        ...

    def openid_metadata(self) -> dict[str, object]:
        """OIDC Discovery 1.0 §3 metadata document (RFC 8414 superset)."""
        ...
