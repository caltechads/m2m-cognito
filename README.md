# m2m-cognito

**m2m-cognito** is a small Python library for machine-to-machine flows against [Amazon Cognito](https://docs.aws.amazon.com/cognito/): on the caller side it performs OAuth2 **client credentials** requests to Cognito’s token endpoint and returns a structured token response; on the API/resource-server side it validates Cognito-issued **JWT access tokens** with the pool’s JWKS, optional client allowlists, and configurable scope checks. The public surface is two main types—`CognitoM2MClient` and `CognitoAccessTokenValidator`—plus result dataclasses and exceptions.

## Requirements

- **Python:** 3.10 or newer (`requires-python >=3.10`).
- **Dependencies:** `pyjwt[crypto]>=2.12.1`, `requests>=2.33.1`.

## Installation

From [PyPI](https://pypi.org/project/m2m-cognito/):

```bash
pip install m2m-cognito
```

```bash
uv add m2m-cognito
```

From a local checkout of this repository (editable install):

```bash
pip install -e .
```

```bash
uv add --editable .
```

The **import package** name is `m2m_cognito` (underscore); the **distribution** name on PyPI is `m2m-cognito` (hyphen).

## Usage

### Obtain an access token (client credentials)

Configure `CognitoM2MClient` with your Cognito app client’s **token URL**, **client ID**, and **client secret**. Call `fetch_token` with one or more OAuth2 scopes (string or sequence). On success you get a `TokenResponse` with `access_token`, optional `expires_in` and `token_type`, and `raw` (the full parsed JSON for forward compatibility).

```python
from m2m_cognito import CognitoM2MClient

client = CognitoM2MClient(
    token_url="https://your-auth-domain.example.com/oauth2/token",
    client_id="7a8b9c0d1e2f3g4h5i6j7k8",
    client_secret="your-client-secret",
)
response = client.fetch_token(scopes=["api.example.com/read", "api.example.com/write"])
bearer = response.access_token
```

### Validate an access token (API side)

Build a `CognitoAccessTokenValidator` from the user pool’s **AWS region** and **user pool ID**. Optionally restrict **allowed client IDs**, require **scopes** with `scope_match` of `"all"` (every required scope present) or `"any"` (at least one overlap), and set **audience** if your tokens include `aud` and you want it verified. Pass the raw JWT string (no `Bearer ` prefix) to `validate`. On success you get `ValidatedAccessToken` with `client_id`, `scopes` (as a `frozenset`), and full `claims`.

```python
from m2m_cognito import CognitoAccessTokenValidator

validator = CognitoAccessTokenValidator(
    region="us-west-2",
    user_pool_id="us-west-2_AbCdEfGhI",
    allowed_client_ids={"7a8b9c0d1e2f3g4h5i6j7k8", "another-app-client-id"},
    required_scopes={"api.example.com/read"},
    scope_match="all",
    audience=None,  # omit or set to verify JWT aud
)
validated = validator.validate(jwt_string_from_authorization_header)
subject_client = validated.client_id
```

## Process Flow

### Overview

At the top level, AWS Cognito has a user pool. Within that user pool, are resource servers, corresponding to API servers, and Application clients, which are the systems that will connect to the APIs.

### Setup

To begin to use Cognito for API authentication and authorization you must first create the required resources:

 * User pool
    * Resource server within the user pool. The resource server will have:
        * A human name (`My API`)
        * An identifier (`my_api`)
        * Custom scopes (or permissions - read, write) these scopes are referred to by joining the resource server identifier with the scope name, ie. `my_api/read`
    * Application client. These clients will have:
        * A client ID
        * A client secret
        * Allowed scopes

### Flow

To connect to a resource server or API, a client will first connect to Cognito using its client id and client secret and obtain a temporary token. By default, this token will last for 1 hour.

This token will be sent as an authentication Bearer token to the server. That server will then validate that token with Cognito. If valid, the response will include the client id, and the valid scopes for the session. The server will then provide the corresponding data to the client.

## Error handling

All library-specific errors subclass **`M2MCognitoError`**. Typical cases:

| Exception | When it usually occurs |
|-----------|-------------------------|
| **`M2MCognitoError`** | Base type; catch this if you want a single handler for any library error. |
| **`CognitoTokenRequestError`** | Token HTTP request failed, non-success status, invalid JSON, missing `access_token`, OAuth2 `error` / `error_description` in the body, or empty scopes passed to `fetch_token`. Optional attributes: `status_code`, `error_code`, `error_description`, `response_body` (useful for logging—avoid echoing secrets). |
| **`TokenValidationError`** | JWT cannot be verified (signature, issuer, expiry, required claims), wrong `token_use`, missing `client_id`, `client_id` not in `allowed_client_ids`, or malformed `scope` claim. Also the base class for scope failures below. |
| **`InsufficientScopeError`** | Cryptographically valid token, but `required_scopes` is non-empty and the token’s scopes do not satisfy `scope_match` (`all` vs `any`). Exposes `token_scopes` and `required_scopes` for messaging or metrics. |

Prefer catching the specific types where you branch on behavior; use `M2MCognitoError` only for broad “Cognito/M2M layer failed” handling.

## Configuration hints

- **Token URL:** If you use a Cognito **hosted UI domain** (custom or Amazon-provided), the client-credentials token endpoint is typically
  `https://<your-domain>/oauth2/token`
  (same host as the hosted UI, path `/oauth2/token`). See [Using the resource server with the hosted UI and OAuth 2.0](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html) and related Cognito OAuth2 documentation.
- **Issuer and JWKS:** For a user pool in `region` with id `user_pool_id`, Cognito’s issuer is
  `https://cognito-idp.<region>.amazonaws.com/<user_pool_id>`
  and the JWKS URL is
  `<issuer>/.well-known/jwks.json`.
  `CognitoAccessTokenValidator` builds these automatically from `region` and `user_pool_id`.
