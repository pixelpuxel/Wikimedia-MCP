"""End-to-end private-wiki check; creates and then deletes one temporary page."""
import base64
import hashlib
import html
import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

BASE = os.environ["WIKI_PUBLIC_URL"].rstrip("/")
RESOURCE = BASE + "/mcp"
USERNAME = os.environ.get("WIKI_USERNAME", "WikiMCP")
PASSWORD = Path("/run/secrets/wiki_password").read_text().strip()
TITLE = "MCP-Session-Test-" + secrets.token_hex(8)
CONTENT = "Temporary MCP session regression check."
issued = []

with httpx.Client(base_url=BASE, timeout=60, follow_redirects=False) as client:
    def authorize(scope):
        registration = client.post("/oauth/register", json={
            "client_name": "Private wiki session test",
            "redirect_uris": ["http://localhost/callback"],
        })
        registration.raise_for_status()
        client_id = registration.json()["client_id"]
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        state = secrets.token_urlsafe(16)
        consent = client.get("/oauth/authorize", params={
            "client_id": client_id, "redirect_uri": "http://localhost/callback",
            "response_type": "code", "code_challenge": challenge,
            "code_challenge_method": "S256", "scope": scope,
            "resource": RESOURCE, "state": state,
        })
        consent.raise_for_status()
        request_id = html.unescape(re.search(r'name="request_id" value="([^"]+)"', consent.text).group(1))
        approval = client.post("/oauth/authorize", data={
            "request_id": request_id, "username": USERNAME,
            "password": PASSWORD, "decision": "allow",
        })
        assert approval.status_code == 303, "Consent failed"
        location = urlparse(approval.headers["location"])
        assert (location.scheme, location.netloc, location.path) == ("http", "localhost", "/callback")
        query = parse_qs(location.query)
        assert query["state"] == [state] and len(query["code"]) == 1
        data = {
            "grant_type": "authorization_code", "client_id": client_id,
            "code": query["code"][0], "redirect_uri": "http://localhost/callback",
            "code_verifier": verifier, "resource": RESOURCE,
        }
        result = client.post("/oauth/token", data=data)
        result.raise_for_status()
        tokens = result.json()
        issued.append((client_id, tokens))
        assert tokens["resource"] == RESOURCE
        assert client.post("/oauth/token", data=data).status_code == 400
        return tokens["access_token"]

    def rpc(token, method, params):
        response = client.post("/mcp", headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json, text/event-stream",
        }, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        response.raise_for_status()
        body = response.json()
        assert "error" not in body, "MCP protocol error"
        return body["result"]

    def call(token, name, arguments):
        return rpc(token, "tools/call", {"name": name, "arguments": arguments})

    token = None
    created = False
    try:
        assert client.post("/mcp", json={}).status_code == 401
        anonymous = client.get("/api.php", params={
            "action": "query", "titles": "Hauptseite", "format": "json",
        }).json()
        assert anonymous["error"]["code"] == "readapidenied"
        token = authorize("wiki:read wiki:write wiki:admin")
        rpc(token, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "session-regression", "version": "1"},
        })
        assert rpc(token, "tools/list", {})["tools"]
        assert not call(token, "get_my_permissions", {}).get("isError")
        result = call(token, "create_page", {"title": TITLE, "content": CONTENT})
        assert not result.get("isError"), "Page creation failed"
        created = True
        result = call(token, "get_page", {"title": TITLE})
        assert not result.get("isError") and CONTENT in str(result), "Reading failed"
        read_token = authorize("wiki:read")
        denied = call(read_token, "append_to_page", {"title": TITLE, "content": "MUST NOT BE WRITTEN"})
        assert denied.get("isError"), "Write scope was not enforced"
        print("PASS: public OAuth flow, MCP initialization, create/read, missing-scope denial, anonymous denial")
    finally:
        try:
            if created:
                result = call(token, "delete_page", {"title": TITLE, "reason": "Remove temporary session regression test"})
                assert not result.get("isError"), "Test-page cleanup failed"
                missing = call(token, "get_page", {"title": TITLE})
                payload = missing.get("structuredContent")
                if payload is None:
                    payload = json.loads(missing["content"][0]["text"])
                assert not missing.get("isError") and payload.get("exists") is False, "Test page still exists"
                print("PASS: temporary test page deleted; absence verified")
        finally:
            for client_id, tokens in issued:
                for key in ("access_token", "refresh_token"):
                    response = client.post("/oauth/revoke", data={"client_id": client_id, "token": tokens[key]})
                    response.raise_for_status()
                response = client.post("/mcp", headers={"Authorization": "Bearer " + tokens["access_token"]}, json={})
                assert response.status_code == 401
            print("PASS: test tokens revoked")
