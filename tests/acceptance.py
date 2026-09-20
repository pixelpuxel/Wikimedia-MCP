import base64
import hashlib
import html
import json
import os
import re
import urllib.parse

import httpx

BASE = os.getenv("MCP_BASE", "http://127.0.0.1:8090")
RESOURCE = os.getenv("WIKI_PUBLIC_URL", "https://wiki.example.org").rstrip("/") + "/mcp"
USERNAME = os.getenv("WIKI_USERNAME", "WikiMCP")


password = os.getenv("WIKI_PASSWORD")
if not password:
    with open("/run/secrets/wiki_password", encoding="utf-8") as secret_file:
        password = secret_file.read().strip()

with httpx.Client(follow_redirects=False) as client:
    registration = client.post(
        BASE + "/oauth/register",
        json={"client_name": "Deployment acceptance", "redirect_uris": ["http://localhost/callback"]},
    )
    registration.raise_for_status()
    client_id = registration.json()["client_id"]
    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    authorization = client.get(
        BASE + "/oauth/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": "http://localhost/callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "wiki:read wiki:write wiki:admin",
            "resource": RESOURCE,
            "state": "acceptance",
        },
    )
    authorization.raise_for_status()
    request_id = html.unescape(re.search(r'name="request_id" value="([^"]+)"', authorization.text).group(1))
    approval = client.post(
        BASE + "/oauth/authorize",
        data={"request_id": request_id, "username": USERNAME, "password": password, "decision": "allow"},
    )
    assert approval.status_code == 303, approval.text
    code = urllib.parse.parse_qs(urllib.parse.urlparse(approval.headers["location"]).query)["code"][0]
    tokens = client.post(
        BASE + "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": "http://localhost/callback",
            "code_verifier": verifier,
            "resource": RESOURCE,
        },
    )
    tokens.raise_for_status()
    access = tokens.json()["access_token"]
    headers = {
        "Authorization": "Bearer " + access,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }

    def rpc(method, params=None, request_id=1):
        body = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            body["params"] = params
        response = client.post(BASE + "/mcp", headers=headers, json=body)
        response.raise_for_status()
        return response.json()

    initialized = rpc(
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "deployment-acceptance", "version": "1"}},
    )
    tools = rpc("tools/list", {}, 2)["result"]["tools"]
    permissions = rpc("tools/call", {"name": "get_my_permissions", "arguments": {}}, 3)
    written = rpc(
        "tools/call",
        {"name": "append_to_page", "arguments": {"title": "MCP-Systemtest", "content": "\n\nÖffentlicher OAuth-/MCP-Abnahmetest erfolgreich.", "summary": "Öffentlicher MCP-Abnahmetest"}},
        4,
    )
    page = rpc("tools/call", {"name": "get_page", "arguments": {"title": "MCP-Systemtest"}}, 5)
    print(
        json.dumps(
            {
                "protocol": initialized["result"]["protocolVersion"],
                "server": initialized["result"]["serverInfo"],
                "tool_count": len(tools),
                "tool_names": [tool["name"] for tool in tools],
                "permissions_ok": not permissions.get("error") and not permissions.get("result", {}).get("isError"),
                "write_ok": not written.get("error") and not written.get("result", {}).get("isError"),
                "read_ok": not page.get("error") and not page.get("result", {}).get("isError"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
