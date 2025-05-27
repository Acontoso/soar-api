import requests
from flask import current_app, jsonify, g
import flask
import jwt
import jwt.algorithms

#Auth is done at the API gateway. Since its a proxy integration to lambda where lambda function handles routing, there needs to be scope checks configured... Done at later date
#Below code works and successfully validates the token
COGNITO_ID = "ap-southeast-2_jL1tizlq8"

def get_jwk(kid) -> str:
    """Fetch the JWKs and return the matching key by kid"""
    jwks_url = f"https://cognito-idp.ap-southeast-2.amazonaws.com/{COGNITO_ID}/.well-known/jwks.json"
    response = requests.get(jwks_url)
    response.raise_for_status()
    jwks = response.json()
    for key in jwks["keys"]:
        if key["kid"] == kid:
            return key
    raise ValueError("Unable to find the appropriate key")

def verify_jwt(request: flask.Request):
    """Verify the JWT token using the appropriate public key from Cognito"""
    token = request.headers.get("Authorization")
    if not token:
        current_app.logger.error(f"[-] Authorization token is missing")
        response = jsonify({"error": "JWT token is missing or invalid"})
        response.status_code = 401
        return response
    token = token.replace("Bearer ", "")
    try:
        unverified_header = jwt.get_unverified_header(token)
        if unverified_header is None or "kid" not in unverified_header:
            raise ValueError("Token does not contain a valid header")
        kid = unverified_header["kid"]
        key = get_jwk(kid)
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        # Decode and verify the JWT
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=f"https://cognito-idp.ap-southeast-2.amazonaws.com/{COGNITO_ID}",
        )
        g.token = payload
        current_app.logger.info(f"[+] Authorization token is valid, proceeding with request")
        g.client_id = payload.get("client_id")
    except jwt.ExpiredSignatureError:
        response = jsonify({"error": "JWT token is expired"})
        response.status_code = 401
        return response
    except Exception as error:
        response = jsonify({"error": "JWT token is missing or invalid"})
        current_app.logger.error(f"{str(error)}")
        response.status_code = 401
        return response


def verify_scopes(decoded_token: str, required_scopes: list):
    """Verify if the decoded JWT contains the required scopes."""
    token_scopes = decoded_token.get("scope", "").split(" ")
    # Check if token contains the required scopes
    return all(scope in token_scopes for scope in required_scopes)
