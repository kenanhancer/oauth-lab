# coding: utf-8

from typing import Dict, List  # noqa: F401
import importlib
import pkgutil

from openapi_server.apis.jwks_api_base import BaseJWKSApi
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
from openapi_server.models.jwks import JWKS


router = APIRouter()

ns_pkg = openapi_server.impl
for _, name, _ in pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + "."):
    importlib.import_module(name)


@router.get(
    "/jwks",
    responses={
        200: {"model": JWKS, "description": "JSON Web Key Set"},
    },
    tags=["JWKS"],
    summary="JSON Web Key Set",
    response_model_by_alias=True,
)
async def jwks(
) -> JWKS:
    """Returns the public keys used by this issuer to sign tokens (and encrypt requests, when applicable). Clients fetch this to verify JWT signatures locally. The actual path is announced by &#x60;jwks_uri&#x60; in the discovery document. """
    if not BaseJWKSApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BaseJWKSApi.subclasses[0]().jwks()
