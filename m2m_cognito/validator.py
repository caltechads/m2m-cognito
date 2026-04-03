"""Validate Cognito-issued JWT access tokens using the pool JWKS."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from typing import Any, Literal

import jwt  # pyright: ignore[reportMissingImports]
from jwt import PyJWKClient  # pyright: ignore[reportMissingImports]

from m2m_cognito.exceptions import InsufficientScopeError, TokenValidationError

ScopeMatch = Literal["all", "any"]


@dataclass(frozen=True)
class ValidatedAccessToken:
    """Result of a successful access token validation.

    Attributes:
        client_id: OAuth2 client identifier from the token (Cognito ``client_id`` claim).
        scopes: OAuth2 scopes granted on the token (from the space-separated ``scope`` claim).
        claims: Full decoded JWT claims.
    """

    client_id: str
    scopes: frozenset[str]
    claims: dict[str, Any]


class CognitoAccessTokenValidator:
    """Verifies RS256 access tokens issued by an Amazon Cognito user pool."""

    def __init__(
        self,
        *,
        region: str,
        user_pool_id: str,
        allowed_client_ids: Collection[str] | None = None,
        required_scopes: Collection[str] = (),
        scope_match: ScopeMatch = "all",
        audience: str | None = None,
    ) -> None:
        """Build issuer and JWKS URLs for the pool and configure validation policy.

        Args:
            region: AWS region of the user pool (for example ``us-west-2``).
            user_pool_id: Cognito user pool ID.
            allowed_client_ids: If set, only tokens whose ``client_id`` is in this
                collection are accepted. If ``None``, any ``client_id`` is allowed
                after cryptographic checks (weaker; prefer an explicit allowlist in
                production).
            required_scopes: Scopes that must be satisfied when non-empty; see
                ``scope_match``.
            scope_match: ``all`` requires every scope in ``required_scopes``; ``any``
                requires at least one overlap with ``required_scopes``.
            audience: If set, JWT ``aud`` is verified. If ``None``, audience is not
                checked (common for some Cognito M2M access tokens).

        Raises:
            ValueError: If ``scope_match`` is not ``all`` or ``any``.
        """
        #: AWS region hosting the user pool (e.g. ``us-west-2``).
        self.region = region
        #: Cognito user pool ID.
        self.user_pool_id = user_pool_id
        #: If set, only tokens whose ``client_id`` is in this collection are accepted.
        self.allowed_client_ids = (
            frozenset(allowed_client_ids) if allowed_client_ids is not None else None
        )
        #: Scopes that must be present when non-empty; see :attr:`scope_match`.
        self.required_scopes = frozenset(required_scopes)
        #: Whether :attr:`required_scopes` uses ``all`` or ``any`` semantics.
        self.scope_match: ScopeMatch = scope_match
        #: When set, JWT ``aud`` is verified; when ``None``, audience is not checked.
        self.audience = audience

        #: Expected JWT issuer URL for the user pool.
        self.issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
        #: JWKS document URL for signature verification.
        self.jwks_url = f"{self.issuer}/.well-known/jwks.json"
        self._jwks_client = PyJWKClient(self.jwks_url)

        if self.scope_match not in ("all", "any"):
            raise ValueError("scope_match must be 'all' or 'any'.")

    def validate(self, token: str) -> ValidatedAccessToken:
        """Decode and validate a Cognito access token.

        Args:
            token: Raw JWT string (no ``Bearer`` prefix).

        Returns:
            :class:`ValidatedAccessToken` with client id, scopes, and claims.

        Raises:
            TokenValidationError: If the token is invalid, expired, wrong type, fails
                issuer/signature checks, or the client is not allowed.
            InsufficientScopeError: If :attr:`required_scopes` is non-empty and the
                token does not satisfy the configured scope policy.
        """
        jwks_client = self._jwks_client
        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
        except jwt.PyJWTError as exc:
            raise TokenValidationError(
                f"Could not resolve signing key for token: {exc}",
            ) from exc

        decode_kwargs: dict[str, Any] = {
            "algorithms": ["RS256"],
            "issuer": self.issuer,
            "options": {
                "require": ["exp", "iat", "iss", "token_use"],
                "verify_aud": self.audience is not None,
            },
        }
        if self.audience is not None:
            decode_kwargs["audience"] = self.audience

        try:
            claims = jwt.decode(token, signing_key.key, **decode_kwargs)
        except jwt.PyJWTError as exc:
            raise TokenValidationError(f"Invalid access token: {exc}") from exc

        if not isinstance(claims, dict):
            raise TokenValidationError("Decoded token claims were not a mapping.")

        if claims.get("token_use") != "access":
            raise TokenValidationError("Token is not an access token.")

        client_id = claims.get("client_id")
        if not client_id or not isinstance(client_id, str):
            raise TokenValidationError("Token missing string client_id claim.")

        if (
            self.allowed_client_ids is not None
            and client_id not in self.allowed_client_ids
        ):
            raise TokenValidationError("Token client_id is not allowed.")

        scope_claim = claims.get("scope") or ""
        if not isinstance(scope_claim, str):
            raise TokenValidationError("Token scope claim was not a string.")
        scopes = frozenset(scope_claim.split())

        if self.required_scopes:
            if self.scope_match == "all":
                missing = self.required_scopes - scopes
                if missing:
                    raise InsufficientScopeError(
                        "Token is missing one or more required scopes.",
                        token_scopes=scopes,
                        required_scopes=self.required_scopes,
                    )
            else:
                if not (self.required_scopes & scopes):
                    raise InsufficientScopeError(
                        "Token did not include any of the required scopes.",
                        token_scopes=scopes,
                        required_scopes=self.required_scopes,
                    )

        return ValidatedAccessToken(client_id=client_id, scopes=scopes, claims=claims)
