#!/usr/bin/env python

import os
import sys

from dotenv import load_dotenv

from m2m_cognito import CognitoAccessTokenValidator


def validate(bearer: str):
    AWS_REGION = os.getenv("COGNITO_AWS_REGION")
    USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
    APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
    REQUIRED_SCOPE = os.getenv("COGNITO_REQUIRED_SCOPE")

    validator = CognitoAccessTokenValidator(
        region=AWS_REGION,
        user_pool_id=USER_POOL_ID,
        allowed_client_ids=[APP_CLIENT_ID],
        required_scopes=[REQUIRED_SCOPE],
    )

    claims = validator.validate(bearer)
    print(claims)
    print(claims.client_id)


if __name__ == "__main__":
    load_dotenv()

    if len(sys.argv) > 1:
        bearer = sys.argv[1]
    else:
        print("Usage: python validate_bearer_token.py <bearer_token>")
        sys.exit(1)

    validate(bearer)
