# coding: utf-8

from typing import Dict, List  # noqa: F401
import importlib
import pkgutil

from openapi_server.apis.discovery_api_base import BaseDiscoveryApi
import openapi_server.impl

from fastapi import (  # noqa: F401
    APIRouter,
    Body,
    Cookie,
    Depends,
    Form,
    Header,
    HTTPException,
    Path,
    Query,
    Response,
    Security,
    status,
)

from openapi_server.models.extra_models import TokenModel  # noqa: F401
from openapi_server.models.discovery_document import DiscoveryDocument


router = APIRouter()

ns_pkg = openapi_server.impl
for _, name, _ in pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + "."):
    importlib.import_module(name)


@router.get(
    "/.well-known/oauth-authorization-server",
    responses={
        200: {"model": DiscoveryDocument, "description": "Authorization server metadata"},
    },
    tags=["Discovery"],
    summary="OAuth 2.0 authorization-server metadata (RFC 8414)",
    response_model_by_alias=True,
)
async def authorization_server_metadata(
) -> DiscoveryDocument:
    """Equivalent to the OIDC discovery document for plain OAuth 2.0 servers that do not implement OpenID Connect. The response shape is a strict subset of the OIDC discovery document. """
    if not BaseDiscoveryApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BaseDiscoveryApi.subclasses[0]().authorization_server_metadata()


@router.get(
    "/.well-known/openid-configuration",
    responses={
        200: {"model": DiscoveryDocument, "description": "Provider metadata"},
    },
    tags=["Discovery"],
    summary="OIDC discovery metadata",
    response_model_by_alias=True,
)
async def openid_configuration(
) -> DiscoveryDocument:
    """Standardized discovery endpoint published by every OpenID Connect provider. The response describes all endpoints, supported flows, scopes, claims, signing algorithms, and capabilities.  This is the **only path that is truly standardized across OIDC providers** — all other endpoint URLs are vendor-defined and must be read from this document. """
    if not BaseDiscoveryApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BaseDiscoveryApi.subclasses[0]().openid_configuration()
