"""Machine-to-machine Amazon Cognito OAuth2 client credentials and token validation."""

__version__ = "0.1.5"

from m2m_cognito.client import CognitoM2MClient, TokenResponse
from m2m_cognito.exceptions import (
    CognitoTokenRequestError,
    InsufficientScopeError,
    M2MCognitoError,
    TokenValidationError,
)
from m2m_cognito.validator import CognitoAccessTokenValidator, ValidatedAccessToken

__all__ = [
    "CognitoAccessTokenValidator",
    "CognitoM2MClient",
    "CognitoTokenRequestError",
    "InsufficientScopeError",
    "M2MCognitoError",
    "TokenResponse",
    "TokenValidationError",
    "ValidatedAccessToken",
]
