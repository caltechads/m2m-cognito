#!/usr/bin/env python

import os
import sys

from dotenv import load_dotenv

from m2m_cognito import CognitoM2MClient

load_dotenv()

TOKEN_URL = os.getenv("COGNITO_TOKEN_URL")
CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")
SCOPES = os.getenv("COGNITO_REQUIRED_SCOPE").split(",")


def main():
    client = CognitoM2MClient(
        token_url=TOKEN_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )
    response = client.fetch_token(scopes=SCOPES)
    bearer = response.access_token

    print(bearer)


if __name__ == "__main__":
    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python test_client.py")
        print()
        print("Fetches a Cognito M2M access token using .env settings.")
        print()
        print("Options:")
        print("  -h, --help    Show this help message and exit")
        print()
        print("To test token validation, run:")
        print("export BEARER_TOKEN=$(python test_client.py) && echo $BEARER_TOKEN")
        print()
        print("Then validate the token with:")
        print("python validate_bearer_token.py $BEARER_TOKEN")
        print()
        print("Create a .env file by copying .env.example and filling in the values.")
        sys.exit(0)
    main()
