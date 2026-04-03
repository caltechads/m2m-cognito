"""Exceptions raised by :mod:`m2m_cognito`."""


class M2MCognitoError(Exception):
    """Base exception for all ``m2m_cognito`` errors."""


class CognitoTokenRequestError(M2MCognitoError):
    """Raised when the Cognito OAuth2 token endpoint returns an error or an invalid payload.

    Keyword Args:
        status_code: HTTP status from the token response, if available.
        error_code: OAuth2 ``error`` field from a JSON body, if present.
        error_description: OAuth2 ``error_description`` field, if present.
        response_body: Raw response body text for diagnostics (avoid logging secrets).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: str | None = None,
        error_description: str | None = None,
        response_body: str | None = None,
    ) -> None:
        """Store HTTP and OAuth2 error details when available.

        Args:
            message: Human-readable summary.

        Keyword Args:
            status_code: HTTP status from the token response, if available.
            error_code: OAuth2 ``error`` field from a JSON body, if present.
            error_description: OAuth2 ``error_description`` field, if present.
            response_body: Raw response body text for diagnostics (avoid logging secrets).
        """
        super().__init__(message)
        #: HTTP status code from the token endpoint response, if known.
        self.status_code = status_code
        #: OAuth2 ``error`` code from the response body, if parsed.
        self.error_code = error_code
        #: OAuth2 ``error_description`` from the response body, if parsed.
        self.error_description = error_description
        #: Raw response body for debugging (may be non-JSON).
        self.response_body = response_body


class TokenValidationError(M2MCognitoError):
    """Raised when an access token fails structural, cryptographic, or policy checks."""


class InsufficientScopeError(TokenValidationError):
    """Raised when the token is valid but does not include required OAuth2 scopes."""

    def __init__(
        self,
        message: str,
        *,
        token_scopes: frozenset[str],
        required_scopes: frozenset[str],
    ) -> None:
        """Attach scope sets for debugging or policy messaging.

        Args:
            message: Human-readable error text.
            token_scopes: Scopes present on the token.
            required_scopes: Scopes required by validator configuration.
        """
        super().__init__(message)
        #: Scopes present on the validated token.
        self.token_scopes = token_scopes
        #: Scopes that were required by the validator configuration.
        self.required_scopes = required_scopes
