# coding: utf-8

from typing import List

from fastapi import Depends, Security  # noqa: F401
from fastapi.openapi.models import OAuthFlowImplicit, OAuthFlows  # noqa: F401
from fastapi.security import (  # noqa: F401
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
    OAuth2,
    OAuth2AuthorizationCodeBearer,
    OAuth2PasswordBearer,
    SecurityScopes,
)
from fastapi.security.api_key import APIKeyCookie, APIKeyHeader, APIKeyQuery  # noqa: F401

from openapi_server.models.extra_models import TokenModel


bearer_auth = HTTPBearer()


def get_token_bearerAuth(credentials: HTTPAuthorizationCredentials = Depends(bearer_auth)) -> TokenModel:
    """
    Check and retrieve authentication information from custom bearer token.

    :param credentials Credentials provided by Authorization header
    :type credentials: HTTPAuthorizationCredentials
    :return: Decoded token information or None if token is invalid
    :rtype: TokenModel | None
    """

    ...


def get_token_dpop(
    token_api_key_header: str = Security(
        APIKeyHeader(name="Authorization", auto_error=False)
    ),
) -> TokenModel:
    """
    Check and retrieve authentication information from api_key.

    :param token_api_key_header API key provided by Authorization[Authorization] header
    
    
    :type token_api_key_header: str
    :return: Information attached to provided api_key or None if api_key is invalid or does not allow access to called API
    :rtype: TokenModel | None
    """

    ...


basic_auth = HTTPBasic()


def get_token_clientSecretBasic(
    credentials: HTTPBasicCredentials = Depends(basic_auth)
) -> TokenModel:
    """
    Check and retrieve authentication information from basic auth.

    :param credentials Credentials provided by Authorization header
    :type credentials: HTTPBasicCredentials
    :rtype: TokenModel | None
    """

    ...


def get_token_clientSecretPost(
    token_api_key_header: str = Security(
        APIKeyHeader(name="X-OAuth-Client-Secret-Post", auto_error=False)
    ),
) -> TokenModel:
    """
    Check and retrieve authentication information from api_key.

    :param token_api_key_header API key provided by Authorization[X-OAuth-Client-Secret-Post] header
    
    
    :type token_api_key_header: str
    :return: Information attached to provided api_key or None if api_key is invalid or does not allow access to called API
    :rtype: TokenModel | None
    """

    ...


def get_token_clientAssertion(
    token_api_key_header: str = Security(
        APIKeyHeader(name="X-OAuth-Client-Assertion", auto_error=False)
    ),
) -> TokenModel:
    """
    Check and retrieve authentication information from api_key.

    :param token_api_key_header API key provided by Authorization[X-OAuth-Client-Assertion] header
    
    
    :type token_api_key_header: str
    :return: Information attached to provided api_key or None if api_key is invalid or does not allow access to called API
    :rtype: TokenModel | None
    """

    ...


def get_token_none(
    token_api_key_header: str = Security(
        APIKeyHeader(name="X-No-Authentication", auto_error=False)
    ),
) -> TokenModel:
    """
    Check and retrieve authentication information from api_key.

    :param token_api_key_header API key provided by Authorization[X-No-Authentication] header
    
    
    :type token_api_key_header: str
    :return: Information attached to provided api_key or None if api_key is invalid or does not allow access to called API
    :rtype: TokenModel | None
    """

    ...



def get_token_oauth2(
    security_scopes: SecurityScopes, token: str = Depends(oauth2_)
) -> TokenModel:
    """
    Validate and decode token.

    :param token Token provided by Authorization header
    :type token: str
    :return: Decoded token information or None if token is invalid
    :rtype: TokenModel | None
    """

    ...


def validate_scope_oauth2(
    required_scopes: SecurityScopes, token_scopes: List[str]
) -> bool:
    """
    Validate required scopes are included in token scope

    :param required_scopes Required scope to access called API
    :type required_scopes: List[str]
    :param token_scopes Scope present in token
    :type token_scopes: List[str]
    :return: True if access to called API is allowed
    :rtype: bool
    """

    return False

oauth2_code = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://as.example.com/authorize",
    tokenUrl="https://as.example.com/token",
    refreshUrl="https://as.example.com/token",
    scopes={
        "openid": "OIDC — issue an ID token",
        "profile": "OIDC — basic profile claims",
        "email": "OIDC — e-mail and verification",
        "offline_access": "Issue a refresh token",
    }
)


def get_token_oauth2(
    security_scopes: SecurityScopes, token: str = Depends(oauth2_code)
) -> TokenModel:
    """
    Validate and decode token.

    :param token Token provided by Authorization header
    :type token: str
    :return: Decoded token information or None if token is invalid
    :rtype: TokenModel | None
    """

    ...


def validate_scope_oauth2(
    required_scopes: SecurityScopes, token_scopes: List[str]
) -> bool:
    """
    Validate required scopes are included in token scope

    :param required_scopes Required scope to access called API
    :type required_scopes: List[str]
    :param token_scopes Scope present in token
    :type token_scopes: List[str]
    :return: True if access to called API is allowed
    :rtype: bool
    """

    return False

