"""OAuth2 client-credentials client for Amazon Cognito hosted UI / token endpoint."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import requests

from m2m_cognito.exceptions import CognitoTokenRequestError

#: Default timeout (seconds) for token endpoint HTTP calls.
_DEFAULT_TIMEOUT_S = 30.0


def _normalize_scopes(scopes: str | Sequence[str]) -> str:
    if isinstance(scopes, str):
        return " ".join(part for part in scopes.split() if part)
    return " ".join(str(s).strip() for s in scopes if str(s).strip())


@dataclass(frozen=True)
class TokenResponse:
    """Successful response from the Cognito client-credentials grant.

    Attributes:
        access_token: Bearer access token string.
        expires_in: Lifetime in seconds, if returned by the server.
        token_type: Token type (typically ``Bearer``).
        raw: Full parsed JSON object for forward compatibility.
    """

    access_token: str
    expires_in: int | None
    token_type: str | None
    raw: dict[str, Any]


class CognitoM2MClient:
    """Fetches access tokens using the OAuth2 client_credentials grant against Cognito."""

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        """Configure the token client.

        Args:
            token_url: Full URL of the Cognito ``/oauth2/token`` endpoint.
            client_id: App client identifier.
            client_secret: App client secret.
        """
        #: Full URL of the Cognito ``/oauth2/token`` endpoint.
        self.token_url = token_url
        #: App client identifier.
        self.client_id = client_id
        #: App client secret.
        self.client_secret = client_secret

    def fetch_token(
        self,
        *,
        scopes: str | Sequence[str],
        timeout: float | tuple[float, float] = _DEFAULT_TIMEOUT_S,
    ) -> TokenResponse:
        """Request an access token for the given OAuth2 scopes.

        Args:
            scopes: Space-separated scope string, or a sequence of scope strings
                (joined per RFC 6749 client credentials).
            timeout: ``requests`` timeout (seconds or ``(connect, read)`` tuple).

        Returns:
            Parsed :class:`TokenResponse` when the token endpoint succeeds.

        Raises:
            CognitoTokenRequestError: If the HTTP request fails, the status is not
                success, the body is not valid JSON, required fields are missing, or
                the JSON contains OAuth2 ``error`` / ``error_description``.
        """
        scope_str = _normalize_scopes(scopes)
        if not scope_str:
            raise CognitoTokenRequestError(
                "At least one non-empty scope is required for fetch_token.",
            )

        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": scope_str,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        try:
            response = requests.post(
                self.token_url,
                data=data,
                headers=headers,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            raise CognitoTokenRequestError(
                f"Token request failed: {exc}",
            ) from exc

        body_text = response.text
        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise CognitoTokenRequestError(
                "Token response was not valid JSON.",
                status_code=response.status_code,
                response_body=body_text,
            ) from exc

        if not isinstance(payload, dict):
            raise CognitoTokenRequestError(
                "Token response JSON was not an object.",
                status_code=response.status_code,
                response_body=body_text,
            )

        if response.status_code >= 400:
            raise CognitoTokenRequestError(
                "Token endpoint returned an error response.",
                status_code=response.status_code,
                error_code=str(payload.get("error")) if payload.get("error") else None,
                error_description=(
                    str(payload.get("error_description"))
                    if payload.get("error_description")
                    else None
                ),
                response_body=body_text,
            )

        if "error" in payload:
            raise CognitoTokenRequestError(
                "Token response contained an OAuth2 error field.",
                status_code=response.status_code,
                error_code=str(payload.get("error")) if payload.get("error") else None,
                error_description=(
                    str(payload.get("error_description"))
                    if payload.get("error_description")
                    else None
                ),
                response_body=body_text,
            )

        access_token = payload.get("access_token")
        if not access_token or not isinstance(access_token, str):
            raise CognitoTokenRequestError(
                "Token response missing string access_token.",
                status_code=response.status_code,
                response_body=body_text,
            )

        expires_in = payload.get("expires_in")
        expires_int: int | None
        if expires_in is None:
            expires_int = None
        elif isinstance(expires_in, int):
            expires_int = expires_in
        elif isinstance(expires_in, float) and expires_in.is_integer():
            expires_int = int(expires_in)
        else:
            raise CognitoTokenRequestError(
                "Token response expires_in was not an integer.",
                status_code=response.status_code,
                response_body=body_text,
            )

        token_type = payload.get("token_type")
        token_type_str = str(token_type) if token_type is not None else None

        return TokenResponse(
            access_token=access_token,
            expires_in=expires_int,
            token_type=token_type_str,
            raw=payload,
        )
