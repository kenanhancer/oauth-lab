# coding: utf-8

from typing import ClassVar, Dict, List, Tuple  # noqa: F401

from openapi_server.models.jwks import JWKS


class BaseJWKSApi:
    subclasses: ClassVar[Tuple] = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        BaseJWKSApi.subclasses = BaseJWKSApi.subclasses + (cls,)
    async def jwks(
        self,
    ) -> JWKS:
        """Returns the public keys used by this issuer to sign tokens (and encrypt requests, when applicable). Clients fetch this to verify JWT signatures locally. The actual path is announced by &#x60;jwks_uri&#x60; in the discovery document. """
        ...
