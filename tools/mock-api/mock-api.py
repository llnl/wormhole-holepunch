#!/usr/bin/env python3

import base64
import flask
import json
import logging
from flask import request, jsonify, Response
from urllib.parse import unquote

app = flask.Flask(__name__)
app.config["DEBUG"] = True

# This signature (and header a well) are currently irrelevant. Feel free to modify and add
# test tokens as required.
all_tokens = {
    "c520c08c-0325-48c4-8bd1-57bde8c7c382.foo": {
        "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl9pZCI6ImM1MjBjMDhjLTAzMjUtNDhjNC04YmQxLTU3YmRlOGM3YzM4MiIsInN1YiI6ImZvbyIsImdyb3VwcyI6WyJwcm9qZWN0MSIsInByb2plY3QyIl0sImR1aWQiOiIxMjM0NTY3ODkiLCJleHAiOjI2MzU2NDk4NTIuNTU2NjgzfQ.placeholder",
    },
    "5baad242-8651-4fdc-ada4-bf10bce72f92.bar": {
        "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl9pZCI6IjViYWFkMjQyLTg2NTEtNGZkYy1hZGE0LWJmMTBiY2U3MmY5MiIsInN1YiI6ImJhciIsImdyb3VwcyI6WyJwcm9qZWN0MSJdLCJkdWlkIjoiOTg3NjU0MzIxIiwiZXhwIjoyNjM1NjQ5ODkzLjM1NTA1M30.placeholder",
    },
    "6f1dd5eb-d058-433f-89b7-1f87980b1d0d.sub": {
        "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl9pZCI6IjZmMWRkNWViLWQwNTgtNDMzZi04OWI3LTFmODc5ODBiMWQwZCIsInN1YiI6ImZvbyIsImR1aWQiOiIxMjM0NTY3ODkiLCJncm91cHMiOlsicHJvamVjdDEiLCJwcm9qZWN0MiJdLCJwYXJlbnRfaWQiOiJjNTIwYzA4Yy0wMzI1LTQ4YzQtOGJkMS01N2JkZThjN2MzODIiLCJleHRlcm5hbF9pZCI6ImQyZTk1YjYyLTdhNjgtNDU3YS04MWZiLWY5YmQyYjdmYzI3MSIsImV4cCI6MjYzNTY0OTg1Mn0.placeholder",
    },
}

router_config = [
  {
    "id": "b603d885-dcfb-4055-8169-bfc4487a6259",
    "src": "http://localhost:3128/whoami",
    "dst": "http://mock-api:9001",
    "community_id": "d2e95b62-7a68-457a-81fb-f9bd2b7fc271",
    "rules": {
        "version": "0.0.1",
        "disallowed": {
            "users": ["bar"]
        },
        "allowed": {
            "groups": ["project1"]
        }
    }
  },  {
    "id": "8484d0eb-5adc-4ef1-81a9-597beb3fcc24",
    "src": "http://localhost:3128/rewrite",
    "dst": "http://mock-api:9001",
    "prefix_rewrite": "/whoami",
    "rules": {
        "version": "0.0.1",
        "disallowed": {
            "users": ["bar"]
        },
        "allowed": {
            "groups": ["project1"]
        }
    }
  }, {
    "id": "a975b144-8d6d-4ab5-8cfd-110fd44fd670",
    "src": "http://localhost:3128",
    "dst": "http://mock-socket:9002",
    "rules": {
        "version": "0.0.1",
        "disallowed": {
            "users": ["bar"]
        },
        "allowed": {
            "groups": ["project1"]
        }
    }
  }
]

@app.route('/_health', methods=['GET'])
def api_health():
    return jsonify({})

@app.route('/token-service/token/jwt', methods=['GET'])
def api_token_service():
    token = request.headers.get('x-token')
    if token is None:
        return Response("404 Not Found", 404)

    try:
        resp = all_tokens[token]
    except KeyError:
        return Response("404 Not Found", 404)

    return jsonify(resp)

def b64url_decode(data: str) -> bytes:
    data += "=" * (-len(data) % 4)  # fix padding
    return base64.urlsafe_b64decode(data.encode("utf-8"))

def parse_jwt(token: str) -> dict:
    parts = token.split(".")
    
    header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    signature = parts[2] if len(parts) > 2 else None

    return {"header": header, "payload": payload, "signature": signature}


@app.route('/token-service/token/oauth', methods=['GET'])
def api_oauth_exchange():
    token = request.headers.get("x-auth-request-access-token")
    if not token:
        return Response("Not Found", status=404)

    # Parse (do not validate) JWT and check email claim
    parsed = parse_jwt(token)
    email = parsed["payload"].get("email")
    if email != "foo@example.com":
        return Response("Unauthorized", status=401)

    # Still return the hardcoded response
    resp = all_tokens["c520c08c-0325-48c4-8bd1-57bde8c7c382.foo"]

    return jsonify(resp)

@app.route('/route-registry/routes', methods=['GET'])
def api_route_service():
    return jsonify(router_config)

@app.route("/token-service/mfa/jwt", methods=['GET'])
def mfa_jwt_service():
    next_url = request.args.get('next')
    cookie_value = request.cookies.get('known_sign_in')    
    if cookie_value:
        return jsonify(all_tokens['foo'])

    return Response("404 Not Found", 404)

@app.route("/token-service/admin/token/<id>", methods=["POST"])
def subtoken(id):
    request_data = request.get_json()
    app.logger.info(request_data)

    if id == "foo":
        return jsonify({"token": "6f1dd5eb-d058-433f-89b7-1f87980b1d0d.sub"})

    return ("Internal Server Error", 500)


@app.route('/whoami', methods=['GET'])
def whoami():
    headers = dict(request.headers)
    return jsonify(headers)

app.run(host='0.0.0.0', port=9001)
