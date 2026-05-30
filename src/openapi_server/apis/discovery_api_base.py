# coding: utf-8

from typing import ClassVar, Dict, List, Tuple  # noqa: F401

from openapi_server.models.discovery_document import DiscoveryDocument


class BaseDiscoveryApi:
    subclasses: ClassVar[Tuple] = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        BaseDiscoveryApi.subclasses = BaseDiscoveryApi.subclasses + (cls,)
    async def authorization_server_metadata(
        self,
    ) -> DiscoveryDocument:
        """Equivalent to the OIDC discovery document for plain OAuth 2.0 servers that do not implement OpenID Connect. The response shape is a strict subset of the OIDC discovery document. """
        ...


    async def openid_configuration(
        self,
    ) -> DiscoveryDocument:
        """Standardized discovery endpoint published by every OpenID Connect provider. The response describes all endpoints, supported flows, scopes, claims, signing algorithms, and capabilities.  This is the **only path that is truly standardized across OIDC providers** — all other endpoint URLs are vendor-defined and must be read from this document. """
        ...
