"""ScopeValidator — pure domain service.

Pure logic, no I/O. The use case asks: "given what the client requested and
what the client is allowed, what should I actually grant?"
"""

from __future__ import annotations

from oauth_lab.domain.model.errors import InvalidScope
from oauth_lab.domain.model.scope import ScopeSet


class ScopeValidator:
    def grantable(self, requested: ScopeSet, allowed: ScopeSet) -> ScopeSet:
        """Return the subset of `requested` that is allowed.

        Per RFC 6749 §3.3, if the client requests a scope not in the allowed
        set, the AS may either grant a subset, omit unauthorized scopes, or
        fail. We choose to fail closed: any unauthorized scope is an
        `invalid_scope` error. This is the safest default.

        If the client requested no scope, fall back to the full allowed set
        (RFC 6749 §3.3 paragraph 4).
        """
        if requested.is_empty():
            return allowed
        if not requested.is_subset_of(allowed):
            unauthorized = ScopeSet(requested.scopes - allowed.scopes)
            raise InvalidScope(f"scope not allowed for client: {unauthorized.to_str()}")
        return requested
