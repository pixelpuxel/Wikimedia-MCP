"""Public OAuth/MCP file-management check; removes its temporary page and file."""
import base64
import hashlib
import html
import json
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

BASE = os.environ["WIKI_PUBLIC_URL"].rstrip("/")
RESOURCE = BASE + "/mcp"
ACTOR = os.environ.get("WIKI_USERNAME", "WikiMCP")
USERNAME = os.environ.get("WIKI_AUTH_USERNAME", ACTOR)
PASSWORD = Path(os.environ.get("WIKI_AUTH_PASSWORD_FILE", "/run/secrets/wiki_password")).read_text().strip()
SUFFIX = secrets.token_hex(8)
PAGE_TITLE = "MCP-Dateitest-" + SUFFIX
FILE_NAME = "MCP-Dateitest-" + SUFFIX + ".png"
READ_ONLY_FILE_NAME = "MCP-Dateitest-readonly-" + SUFFIX + ".png"
PNG_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
issued = []


with httpx.Client(base_url=BASE, timeout=90, follow_redirects=False) as client:
    def authorize(scope):
        registration = client.post("/oauth/register", json={
            "client_name": "File management acceptance",
            "redirect_uris": ["http://localhost/callback"],
        })
        registration.raise_for_status()
        client_id = registration.json()["client_id"]
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        state = secrets.token_urlsafe(16)
        consent = client.get("/oauth/authorize", params={
            "client_id": client_id,
            "redirect_uri": "http://localhost/callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": scope,
            "resource": RESOURCE,
            "state": state,
        })
        consent.raise_for_status()
        request_id = html.unescape(re.search(r'name="request_id" value="([^"]+)"', consent.text).group(1))
        approval = client.post("/oauth/authorize", data={
            "request_id": request_id,
            "username": USERNAME,
            "password": PASSWORD,
            "decision": "allow",
        })
        assert approval.status_code == 303
        location = urlparse(approval.headers["location"])
        query = parse_qs(location.query)
        assert query["state"] == [state]
        result = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": query["code"][0],
            "redirect_uri": "http://localhost/callback",
            "code_verifier": verifier,
            "resource": RESOURCE,
        })
        result.raise_for_status()
        tokens = result.json()
        issued.append((client_id, tokens))
        return tokens["access_token"]

    def rpc(token, method, params):
        response = client.post("/mcp", headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json, text/event-stream",
        }, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        response.raise_for_status()
        body = response.json()
        assert "error" not in body, body
        return body["result"]

    def call(token, name, arguments):
        return rpc(token, "tools/call", {"name": name, "arguments": arguments})

    def structured(result):
        if result.get("structuredContent") is not None:
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])

    token = None
    page_created = False
    file_uploaded = False
    try:
        token = authorize("wiki:read wiki:write wiki:admin")
        tools = rpc(token, "tools/list", {})["tools"]
        names = {tool["name"] for tool in tools}
        assert {"list_files", "get_file", "upload_file", "embed_file_on_page", "delete_file"} <= names

        uploaded = call(token, "upload_file", {
            "filename": FILE_NAME,
            "content_base64": PNG_BASE64,
            "comment": "Temporärer Dateiverwaltungstest",
        })
        assert not uploaded.get("isError"), uploaded
        file_uploaded = True

        file_info = structured(call(token, "get_file", {"filename": FILE_NAME}))
        assert file_info["exists"] and file_info["user"] == ACTOR

        created = structured(call(token, "create_page", {
            "title": PAGE_TITLE,
            "content": "Temporäre Seite für den Dateiverwaltungstest.",
        }))
        page_created = True
        embedded = call(token, "embed_file_on_page", {
            "page_title": PAGE_TITLE,
            "filename": FILE_NAME,
            "expected_revision_id": created["revision_id"],
            "caption": "Temporäres Testbild",
            "alt_text": "Ein Pixel",
            "width": 100,
        })
        assert not embedded.get("isError"), embedded

        time.sleep(3)
        file_info = structured(call(token, "get_file", {"filename": FILE_NAME}))
        assert any(item["title"] == PAGE_TITLE for item in file_info["used_on"])
        refused = call(token, "delete_file", {"filename": FILE_NAME, "reason": "Must be refused while in use"})
        assert refused.get("isError"), "Used file deletion was not refused"

        read_token = authorize("wiki:read")
        denied = call(read_token, "upload_file", {
            "filename": READ_ONLY_FILE_NAME,
            "content_base64": PNG_BASE64,
        })
        assert denied.get("isError"), "Read-only token uploaded a file"
        assert structured(call(token, "get_file", {"filename": READ_ONLY_FILE_NAME}))["exists"] is False
        print("PASS: upload, metadata, MCP attribution, embedding, usage protection and scope denial")
    finally:
        try:
            if page_created:
                deleted_page = call(token, "delete_page", {"title": PAGE_TITLE, "reason": "Temporären Dateiverwaltungstest entfernen"})
                assert not deleted_page.get("isError"), deleted_page
                page_created = False
            if file_uploaded:
                deleted_file = call(token, "delete_file", {"filename": FILE_NAME, "reason": "Temporären Dateiverwaltungstest entfernen"})
                assert not deleted_file.get("isError"), deleted_file
                file_uploaded = False
            if token:
                assert structured(call(token, "get_file", {"filename": FILE_NAME}))["exists"] is False
                page = structured(call(token, "get_page", {"title": PAGE_TITLE}))
                assert page["exists"] is False
                print("PASS: temporary page and file deleted; absence verified")
        finally:
            for client_id, tokens in issued:
                for key in ("access_token", "refresh_token"):
                    response = client.post("/oauth/revoke", data={"client_id": client_id, "token": tokens[key]})
                    response.raise_for_status()
            print("PASS: test tokens revoked")
