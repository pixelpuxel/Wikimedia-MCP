import base64
import datetime as dt
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl, Field
from starlette.routing import Route as StarletteRoute
from starlette.types import ASGIApp, Receive, Scope, Send


WIKI_API = os.getenv("WIKI_INTERNAL_API_URL", "http://wiki/api.php")
PUBLIC_URL = os.getenv("WIKI_PUBLIC_URL", "https://wiki.example.org").rstrip("/")
ISSUER = os.getenv("OAUTH_ISSUER", PUBLIC_URL).rstrip("/")
RESOURCE = ISSUER + "/mcp"
WIKI_USERNAME = os.getenv("WIKI_USERNAME", "WikiMCP")
WIKI_AUTH_USERNAME = os.getenv("WIKI_AUTH_USERNAME", WIKI_USERNAME)
STATE_DB = Path("/state/oauth.sqlite3")
ACCESS_SECONDS = 600
REFRESH_DAYS = 30
SCOPES = {
    "wiki:read": "Wiki-Seiten, Metadaten und Versionshistorien lesen",
    "wiki:write": "Wiki-Seiten erstellen und bearbeiten",
    "wiki:admin": "Seiten verschieben und löschen",
}
DEFAULT_SCOPE = "wiki:read wiki:write wiki:admin"
DB_LOCK = threading.Lock()
FAILED_LOGINS: dict[str, tuple[int, dt.datetime]] = {}


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_after(**kwargs) -> str:
    return (now() + dt.timedelta(**kwargs)).isoformat()


def read_secret(name: str) -> str:
    return Path("/run/secrets", name).read_text(encoding="utf-8").strip()


def digest(value: str) -> str:
    key = read_secret("oauth_signing_secret").encode()
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(STATE_DB, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    STATE_DB.parent.mkdir(parents=True, exist_ok=True)
    with DB_LOCK, db() as connection:
        connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS oauth_clients (
              client_id TEXT PRIMARY KEY, client_name TEXT NOT NULL,
              redirect_uris TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_requests (
              id_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
              state TEXT, code_challenge TEXT NOT NULL, scope TEXT NOT NULL,
              resource TEXT NOT NULL, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS auth_codes (
              code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
              username TEXT NOT NULL, code_challenge TEXT NOT NULL, scope TEXT NOT NULL,
              resource TEXT NOT NULL, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS access_tokens (
              token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, username TEXT NOT NULL,
              scope TEXT NOT NULL, resource TEXT NOT NULL, expires_at TEXT NOT NULL,
              revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
              token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, username TEXT NOT NULL,
              scope TEXT NOT NULL, resource TEXT NOT NULL, expires_at TEXT NOT NULL,
              revoked INTEGER NOT NULL DEFAULT 0, replaced_by TEXT
            );
            """
        )
        cutoff = now().isoformat()
        connection.execute("DELETE FROM auth_requests WHERE expires_at < ?", (cutoff,))
        connection.execute("DELETE FROM auth_codes WHERE expires_at < ?", (cutoff,))
        connection.execute("DELETE FROM access_tokens WHERE expires_at < ?", (cutoff,))


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value)


def valid_redirect(uri: str) -> str:
    parsed = urlparse(uri)
    if parsed.fragment or parsed.username or parsed.password:
        raise HTTPException(400, "Invalid redirect_uri")
    if parsed.scheme == "https" and parsed.netloc:
        return uri
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return uri
    raise HTTPException(400, "redirect_uri must use HTTPS or localhost")


def normalize_scope(value: str | None) -> str:
    requested = set((value or DEFAULT_SCOPE).split())
    if not requested or requested - set(SCOPES):
        raise HTTPException(400, "Unknown scope")
    return " ".join(sorted(requested))


def get_client(client_id: str) -> sqlite3.Row:
    with DB_LOCK, db() as connection:
        row = connection.execute(
            "SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)
        ).fetchone()
    if not row:
        raise HTTPException(400, "Unknown client_id")
    return row


def issue_tokens(username: str, client_id: str, scope: str) -> dict:
    access = "mwa_" + secrets.token_urlsafe(48)
    refresh = "mwr_" + secrets.token_urlsafe(56)
    access_expiry = iso_after(seconds=ACCESS_SECONDS)
    refresh_expiry = iso_after(days=REFRESH_DAYS)
    with DB_LOCK, db() as connection:
        connection.execute(
            "INSERT INTO access_tokens VALUES (?, ?, ?, ?, ?, ?, 0)",
            (digest(access), client_id, username, scope, RESOURCE, access_expiry),
        )
        connection.execute(
            "INSERT INTO refresh_tokens(token_hash,client_id,username,scope,resource,expires_at,revoked) VALUES(?,?,?,?,?,?,0)",
            (digest(refresh), client_id, username, scope, RESOURCE, refresh_expiry),
        )
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_SECONDS,
        "refresh_token": refresh,
        "scope": scope,
        "resource": RESOURCE,
    }


class WikiTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        with DB_LOCK, db() as connection:
            row = connection.execute(
                "SELECT * FROM access_tokens WHERE token_hash = ?", (digest(token),)
            ).fetchone()
        if not row or row["revoked"] or parse_time(row["expires_at"]) <= now():
            return None
        if row["resource"] != RESOURCE:
            return None
        return AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=row["scope"].split(),
            expires_at=int(parse_time(row["expires_at"]).timestamp()),
            resource=RESOURCE,
            subject=row["username"],
            claims={"sub": row["username"], "aud": [RESOURCE], "scope": row["scope"]},
        )


async def wiki_login(username: str, password: str) -> httpx.AsyncClient:
    client = httpx.AsyncClient(timeout=45, follow_redirects=False)

    async def retain_internal_session(response: httpx.Response) -> None:
        # Browser cookies remain Secure. Only this private client, talking to the
        # Compose service "wiki", may reuse them over the internal HTTP hop.
        # Apply after EVERY response: login and later API calls can rotate cookies.
        if response.url.scheme == "http" and response.url.host == "wiki":
            for cookie in client.cookies.jar:
                if cookie.domain in {"wiki", "wiki.local"}:
                    cookie.secure = False

    client.event_hooks["response"].append(retain_internal_session)
    try:
        token_response = await client.get(
            WIKI_API,
            params={"action": "query", "meta": "tokens", "type": "login", "format": "json"},
        )
        token_response.raise_for_status()
        login_token = token_response.json()["query"]["tokens"]["logintoken"]
        login_response = await client.post(
            WIKI_API,
            data={
                "action": "login",
                "lgname": username,
                "lgpassword": password,
                "lgtoken": login_token,
                "format": "json",
            },
        )
        login_response.raise_for_status()
        if login_response.json().get("login", {}).get("result") != "Success":
            raise ValueError("MediaWiki login failed")
        return client
    except Exception:
        await client.aclose()
        raise


async def verify_wiki_credentials(username: str, password: str) -> bool:
    if not hmac.compare_digest(username, WIKI_AUTH_USERNAME):
        return False
    try:
        client = await wiki_login(username, password)
        await client.aclose()
        return True
    except Exception:
        return False


def current_access(required: str) -> AccessToken:
    access = get_access_token()
    if not access:
        raise RuntimeError("OAuth authentication required")
    if required not in access.scopes:
        raise RuntimeError(f"Missing required OAuth scope: {required}")
    return access


def api_error(data: dict) -> RuntimeError:
    error = data.get("error", {})
    code = str(error.get("code", "wiki_api_error"))
    message = str(error.get("info", "MediaWiki rejected the request"))
    return RuntimeError(f"MediaWiki API error ({code}): {message}")


async def wiki_call(params: dict, *, write: bool = False, admin: bool = False) -> dict:
    current_access("wiki:admin" if admin else "wiki:write" if write else "wiki:read")
    client = await wiki_login(WIKI_USERNAME, read_secret("wiki_password"))
    try:
        payload = dict(params)
        payload["format"] = "json"
        if write:
            token_response = await client.get(
                WIKI_API,
                params={"action": "query", "meta": "tokens", "format": "json"},
            )
            token_response.raise_for_status()
            payload["token"] = token_response.json()["query"]["tokens"]["csrftoken"]
            response = await client.post(WIKI_API, data=payload)
        else:
            response = await client.get(WIKI_API, params=payload)
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise api_error(data)
        return data
    finally:
        await client.aclose()


READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)

mcp = FastMCP(
    "Wiki",
    instructions=(
        f"Dieser Connector liest und bearbeitet das MediaWiki unter {PUBLIC_URL}. "
        "Verwende zum Verlinken ausschließlich die zurückgegebenen öffentlichen /Wiki/-URLs. "
        "Prüfe vor Änderungen die aktuelle Seite und fasse geplante schreibende Aktionen klar zusammen."
    ),
    website_url=PUBLIC_URL,
    host="0.0.0.0",
    token_verifier=WikiTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(ISSUER),
        resource_server_url=AnyHttpUrl(RESOURCE),
        required_scopes=["wiki:read"],
    ),
    stateless_http=True,
    json_response=True,
    streamable_http_path="/",
)


Title = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[^\x00-\x1f\x7f]+$")]
Limit = Annotated[int, Field(ge=1, le=100)]


@mcp.tool(annotations=READ_ONLY)
async def get_my_permissions() -> dict:
    """Liest den angemeldeten MediaWiki-Benutzer, seine Gruppen und effektiven Rechte."""
    data = await wiki_call({"action": "query", "meta": "userinfo", "uiprop": "groups|rights|blockinfo"})
    user = data["query"]["userinfo"]
    return {"id": user.get("id"), "name": user.get("name"), "groups": user.get("groups", []), "rights": user.get("rights", []), "blocked": "blockid" in user}


@mcp.tool(annotations=READ_ONLY)
async def search_pages(query: Annotated[str, Field(min_length=1, max_length=200)], limit: Limit = 20) -> dict:
    """Sucht im Titel und Volltext der für den angemeldeten Benutzer sichtbaren Wiki-Seiten."""
    data = await wiki_call({"action": "query", "list": "search", "srsearch": query, "srlimit": limit, "srprop": "snippet|timestamp|size|wordcount"})
    items = data.get("query", {}).get("search", [])
    return {"count": len(items), "items": [{"title": item["title"], "page_id": item["pageid"], "snippet": re.sub(r"<[^>]+>", "", item.get("snippet", "")), "timestamp": item.get("timestamp"), "url": f"{PUBLIC_URL}/Wiki/{item['title'].replace(' ', '_')}"} for item in items]}


@mcp.tool(annotations=READ_ONLY)
async def list_pages(prefix: str = "", limit: Limit = 50) -> dict:
    """Listet Wiki-Seiten alphabetisch, optional ab einem Titelpräfix."""
    data = await wiki_call({"action": "query", "list": "allpages", "apprefix": prefix, "aplimit": limit, "apnamespace": 0})
    pages = data.get("query", {}).get("allpages", [])
    return {"count": len(pages), "items": [{"page_id": p["pageid"], "title": p["title"], "url": f"{PUBLIC_URL}/Wiki/{p['title'].replace(' ', '_')}"} for p in pages], "continue": data.get("continue")}


@mcp.tool(annotations=READ_ONLY)
async def get_page(title: Title) -> dict:
    """Liest den aktuellen Wikitext und die wichtigsten Metadaten einer einzelnen Seite."""
    data = await wiki_call({"action": "query", "prop": "info|revisions|categories", "inprop": "url", "rvprop": "ids|timestamp|user|comment|content", "rvlimit": 1, "cllimit": 100, "titles": title})
    page = next(iter(data["query"]["pages"].values()))
    if "missing" in page:
        return {"exists": False, "title": page.get("title", title), "url": f"{PUBLIC_URL}/Wiki/{title.replace(' ', '_')}"}
    revision = page.get("revisions", [{}])[0]
    return {"exists": True, "page_id": page["pageid"], "title": page["title"], "url": page.get("fullurl", f"{PUBLIC_URL}/Wiki/{page['title'].replace(' ', '_')}"), "revision_id": revision.get("revid"), "parent_revision_id": revision.get("parentid"), "timestamp": revision.get("timestamp"), "user": revision.get("user"), "comment": revision.get("comment", ""), "content": revision.get("*", ""), "categories": [c["title"] for c in page.get("categories", [])]}


@mcp.tool(annotations=READ_ONLY)
async def get_page_history(title: Title, limit: Limit = 20) -> dict:
    """Listet die Versionshistorie einer Seite mit Revisions-ID, Autor, Zeit und Kommentar."""
    data = await wiki_call({"action": "query", "prop": "revisions", "rvprop": "ids|timestamp|user|comment|size|flags", "rvlimit": limit, "titles": title})
    page = next(iter(data["query"]["pages"].values()))
    return {"title": page.get("title", title), "exists": "missing" not in page, "revisions": page.get("revisions", []), "continue": data.get("continue")}


@mcp.tool(annotations=READ_ONLY)
async def get_revision(revision_id: Annotated[int, Field(gt=0)]) -> dict:
    """Liest den vollständigen Wikitext und die Metadaten einer bestimmten Revision."""
    data = await wiki_call({"action": "query", "prop": "revisions", "revids": revision_id, "rvprop": "ids|timestamp|user|comment|content"})
    page = next(iter(data["query"]["pages"].values()))
    revision = page.get("revisions", [{}])[0]
    return {"page_id": page.get("pageid"), "title": page.get("title"), "revision_id": revision.get("revid"), "parent_revision_id": revision.get("parentid"), "timestamp": revision.get("timestamp"), "user": revision.get("user"), "comment": revision.get("comment", ""), "content": revision.get("*", ""), "url": f"{PUBLIC_URL}/Wiki/{page.get('title', '').replace(' ', '_')}?oldid={revision_id}"}


@mcp.tool(annotations=READ_ONLY)
async def list_recent_changes(limit: Limit = 30) -> dict:
    """Listet die letzten für den Benutzer sichtbaren Seitenänderungen und Logbuchaktionen."""
    data = await wiki_call({"action": "query", "list": "recentchanges", "rclimit": limit, "rcprop": "title|ids|sizes|flags|user|timestamp|comment|loginfo"})
    return {"items": data.get("query", {}).get("recentchanges", []), "continue": data.get("continue")}


@mcp.tool(annotations=READ_ONLY)
async def list_user_contributions(username: str = WIKI_USERNAME, limit: Limit = 30) -> dict:
    """Listet die letzten Bearbeitungen eines MediaWiki-Benutzers."""
    data = await wiki_call({"action": "query", "list": "usercontribs", "ucuser": username, "uclimit": limit, "ucprop": "ids|title|timestamp|comment|size|flags"})
    return {"username": username, "items": data.get("query", {}).get("usercontribs", []), "continue": data.get("continue")}


@mcp.tool(annotations=READ_ONLY)
async def list_backlinks(title: Title, limit: Limit = 50) -> dict:
    """Listet Seiten, die auf die angegebene Seite verlinken."""
    data = await wiki_call({"action": "query", "list": "backlinks", "bltitle": title, "bllimit": limit, "blnamespace": 0})
    return {"title": title, "items": data.get("query", {}).get("backlinks", []), "continue": data.get("continue")}


@mcp.tool(annotations=WRITE)
async def create_page(title: Title, content: Annotated[str, Field(min_length=1, max_length=500000)], summary: Annotated[str, Field(max_length=255)] = "Seite über MCP erstellt") -> dict:
    """Erstellt eine neue Seite. Schlägt fehl, wenn der Titel bereits existiert; überschreibt niemals."""
    data = await wiki_call({"action": "edit", "title": title, "text": content, "summary": summary, "createonly": 1, "bot": 1}, write=True)
    result = data["edit"]
    return {"status": result.get("result"), "title": result.get("title", title), "page_id": result.get("pageid"), "revision_id": result.get("newrevid"), "url": f"{PUBLIC_URL}/Wiki/{title.replace(' ', '_')}"}


@mcp.tool(annotations=WRITE)
async def update_page(title: Title, content: Annotated[str, Field(max_length=500000)], expected_revision_id: Annotated[int, Field(gt=0)], summary: Annotated[str, Field(max_length=255)] = "Seite über MCP aktualisiert") -> dict:
    """Ersetzt den Wikitext einer bestehenden Seite nur, wenn die erwartete Revisions-ID noch aktuell ist. So werden parallele Änderungen nicht überschrieben."""
    current = await get_page(title)
    if not current.get("exists"):
        raise RuntimeError("Page does not exist; use create_page")
    if current.get("revision_id") != expected_revision_id:
        raise RuntimeError(f"Edit conflict: expected revision {expected_revision_id}, current revision is {current.get('revision_id')}")
    data = await wiki_call({"action": "edit", "title": title, "text": content, "summary": summary, "basetimestamp": current["timestamp"], "nocreate": 1, "bot": 1}, write=True)
    result = data["edit"]
    return {"status": result.get("result"), "title": title, "old_revision_id": result.get("oldrevid"), "revision_id": result.get("newrevid"), "url": f"{PUBLIC_URL}/Wiki/{title.replace(' ', '_')}"}


@mcp.tool(annotations=WRITE)
async def append_to_page(title: Title, content: Annotated[str, Field(min_length=1, max_length=100000)], summary: Annotated[str, Field(max_length=255)] = "Inhalt über MCP angehängt") -> dict:
    """Hängt Wikitext atomar an eine vorhandene Seite an, ohne den bestehenden Inhalt zu ersetzen."""
    data = await wiki_call({"action": "edit", "title": title, "appendtext": content, "summary": summary, "nocreate": 1, "bot": 1}, write=True)
    result = data["edit"]
    return {"status": result.get("result"), "title": title, "revision_id": result.get("newrevid"), "url": f"{PUBLIC_URL}/Wiki/{title.replace(' ', '_')}"}


@mcp.tool(annotations=WRITE)
async def prepend_to_page(title: Title, content: Annotated[str, Field(min_length=1, max_length=100000)], summary: Annotated[str, Field(max_length=255)] = "Inhalt über MCP vorangestellt") -> dict:
    """Stellt Wikitext atomar vor den vorhandenen Seiteninhalt."""
    data = await wiki_call({"action": "edit", "title": title, "prependtext": content, "summary": summary, "nocreate": 1, "bot": 1}, write=True)
    result = data["edit"]
    return {"status": result.get("result"), "title": title, "revision_id": result.get("newrevid"), "url": f"{PUBLIC_URL}/Wiki/{title.replace(' ', '_')}"}


@mcp.tool(annotations=WRITE)
async def undo_revision(title: Title, revision_id: Annotated[int, Field(gt=0)], summary: Annotated[str, Field(max_length=255)] = "Revision über MCP rückgängig gemacht") -> dict:
    """Macht die Änderungen einer bestimmten Revision per MediaWiki-Undo rückgängig und erzeugt eine neue Revision."""
    data = await wiki_call({"action": "edit", "title": title, "undo": revision_id, "summary": summary, "nocreate": 1, "bot": 1}, write=True)
    result = data["edit"]
    return {"status": result.get("result"), "title": title, "revision_id": result.get("newrevid"), "url": f"{PUBLIC_URL}/Wiki/{title.replace(' ', '_')}"}


@mcp.tool(annotations=DESTRUCTIVE)
async def move_page(from_title: Title, to_title: Title, reason: Annotated[str, Field(min_length=1, max_length=255)], leave_redirect: bool = True) -> dict:
    """Verschiebt eine Seite als Wiki-Administrator. Optional bleibt am alten Titel eine Weiterleitung bestehen."""
    payload = {"action": "move", "from": from_title, "to": to_title, "reason": reason, "movetalk": 1}
    if not leave_redirect:
        payload["noredirect"] = 1
    data = await wiki_call(payload, write=True, admin=True)
    return {"status": "moved", "from": data["move"].get("from"), "to": data["move"].get("to"), "redirect_left": leave_redirect, "url": f"{PUBLIC_URL}/Wiki/{to_title.replace(' ', '_')}"}


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_page(title: Title, reason: Annotated[str, Field(min_length=1, max_length=255)]) -> dict:
    """Löscht eine Seite als Wiki-Administrator. Die Aktion erscheint im MediaWiki-Löschlogbuch und ist administrativ wiederherstellbar."""
    data = await wiki_call({"action": "delete", "title": title, "reason": reason}, write=True, admin=True)
    return {"status": "deleted", "title": data["delete"].get("title", title), "reason": data["delete"].get("reason", reason)}


web = FastAPI(title="Wiki MCP OAuth", docs_url=None, redoc_url=None)


@web.get("/.well-known/oauth-authorization-server")
@web.get("/.well-known/openid-configuration")
def oauth_metadata():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/oauth/authorize",
        "token_endpoint": ISSUER + "/oauth/token",
        "registration_endpoint": ISSUER + "/oauth/register",
        "revocation_endpoint": ISSUER + "/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": sorted(SCOPES),
    }


@web.get("/.well-known/oauth-protected-resource")
@web.get("/.well-known/oauth-protected-resource/mcp")
def resource_metadata():
    return {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
        "scopes_supported": sorted(SCOPES),
        "resource_documentation": PUBLIC_URL + "/Wiki/MCP-Connector",
    }


@web.post("/oauth/register")
@web.post("/register")
def register(payload: dict):
    uris = payload.get("redirect_uris") or []
    if not isinstance(uris, list) or not uris or len(uris) > 10:
        raise HTTPException(400, "redirect_uris required")
    uris = [valid_redirect(str(uri)) for uri in uris]
    client_id = "mwc_" + secrets.token_urlsafe(24)
    name = str(payload.get("client_name") or "MCP Client")[:120]
    with DB_LOCK, db() as connection:
        connection.execute(
            "INSERT INTO oauth_clients VALUES (?, ?, ?, ?)",
            (client_id, name, json.dumps(uris), now().isoformat()),
        )
    return {
        "client_id": client_id,
        "client_name": name,
        "redirect_uris": uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }


@web.get("/oauth/authorize", response_class=HTMLResponse)
@web.get("/authorize", response_class=HTMLResponse)
def authorize(client_id: str, redirect_uri: str, response_type: str, code_challenge: str, code_challenge_method: str, state: str = "", scope: str = "", resource: str = ""):
    client = get_client(client_id)
    allowed = json.loads(client["redirect_uris"])
    if redirect_uri not in allowed or response_type != "code" or code_challenge_method != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", code_challenge):
        raise HTTPException(400, "Invalid OAuth authorization request")
    if resource and resource != RESOURCE:
        raise HTTPException(400, "Unsupported resource")
    selected_scope = normalize_scope(scope)
    request_id = secrets.token_urlsafe(32)
    with DB_LOCK, db() as connection:
        connection.execute(
            "INSERT INTO auth_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (digest(request_id), client_id, redirect_uri, state, code_challenge, selected_scope, RESOURCE, iso_after(minutes=10)),
        )
    items = "".join(f"<li><strong>{html.escape(s)}</strong><span>{html.escape(SCOPES[s])}</span></li>" for s in selected_scope.split())
    return HTMLResponse(f'''<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wiki-Zugriff erlauben</title><style>*{{box-sizing:border-box}}body{{margin:0;background:#f6f5f2;color:#202122;font:16px system-ui,sans-serif}}main{{max-width:560px;margin:6vh auto;padding:24px}}.brand{{font:800 20px Georgia,serif;margin-bottom:14px}}section{{background:#fff;border:1px solid #c8ccd1;border-radius:14px;padding:28px;box-shadow:0 18px 55px #20212215}}h1{{margin:0 0 8px}}p,li span{{color:#54595d;line-height:1.5}}label{{display:block;font-weight:650;margin-top:16px}}input{{width:100%;padding:13px;border:1px solid #a2a9b1;border-radius:4px;margin-top:6px;font-size:16px}}ul{{list-style:none;padding:0}}li{{padding:10px 0;border-top:1px solid #eaecf0;display:grid;gap:3px}}button{{width:100%;border:0;border-radius:4px;padding:14px;background:#36c;color:#fff;font-weight:750;font-size:16px;margin-top:20px}}.cancel{{background:#eaecf0;color:#202122;margin-top:8px}}</style></head><body><main><div class="brand">MEIN WIKI</div><section><h1>Connector „Wiki“ verbinden</h1><p><strong>{html.escape(client['client_name'])}</strong> möchte auf das Wiki zugreifen. Du bestätigst mit deinem persönlichen Konto; Wiki-Aktionen werden als <strong>{html.escape(WIKI_USERNAME)}</strong> ausgeführt. Dein Passwort wird direkt durch MediaWiki geprüft und nicht im OAuth-Speicher abgelegt.</p><ul>{items}</ul><form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{request_id}"><label>Wiki-Benutzer<input name="username" autocomplete="username" value="{html.escape(WIKI_AUTH_USERNAME)}" required></label><label>Passwort<input type="password" name="password" autocomplete="current-password" required></label><button name="decision" value="allow">Zugriff erlauben</button><button class="cancel" name="decision" value="deny">Abbrechen</button></form></section></main></body></html>''', headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@web.post("/oauth/authorize")
async def authorize_submit(request: Request, request_id: str = Form(...), username: str = Form(""), password: str = Form(""), decision: str = Form(...)):
    key = request.client.host if request.client else "unknown"
    attempts, reset_at = FAILED_LOGINS.get(key, (0, now() + dt.timedelta(minutes=15)))
    if now() > reset_at:
        attempts, reset_at = 0, now() + dt.timedelta(minutes=15)
    if attempts >= 5:
        raise HTTPException(429, "Too many failed login attempts")
    with DB_LOCK, db() as connection:
        auth_request = connection.execute("SELECT * FROM auth_requests WHERE id_hash = ?", (digest(request_id),)).fetchone()
    if not auth_request or auth_request["used"] or parse_time(auth_request["expires_at"]) < now():
        raise HTTPException(400, "Authorization request expired")
    if decision != "allow":
        with DB_LOCK, db() as connection:
            connection.execute("UPDATE auth_requests SET used = 1 WHERE id_hash = ?", (digest(request_id),))
        return RedirectResponse(auth_request["redirect_uri"] + "?" + urlencode({"error": "access_denied", "state": auth_request["state"] or ""}), 303)
    if not await verify_wiki_credentials(username, password):
        FAILED_LOGINS[key] = (attempts + 1, reset_at)
        return HTMLResponse("<h1>Anmeldung fehlgeschlagen</h1><p>Bitte den Verbindungsvorgang erneut starten.</p>", 401, headers={"Cache-Control": "no-store"})
    FAILED_LOGINS.pop(key, None)
    code = secrets.token_urlsafe(48)
    with DB_LOCK, db() as connection:
        connection.execute("UPDATE auth_requests SET used = 1 WHERE id_hash = ?", (digest(request_id),))
        connection.execute(
            "INSERT INTO auth_codes VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (digest(code), auth_request["client_id"], auth_request["redirect_uri"], username, auth_request["code_challenge"], auth_request["scope"], RESOURCE, iso_after(minutes=2)),
        )
    query = {"code": code}
    if auth_request["state"]:
        query["state"] = auth_request["state"]
    return RedirectResponse(auth_request["redirect_uri"] + "?" + urlencode(query), 303)


def pkce_s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


@web.post("/oauth/token")
@web.post("/token")
def token(grant_type: str = Form(...), client_id: str = Form(...), code: str = Form(""), redirect_uri: str = Form(""), code_verifier: str = Form(""), refresh_token: str = Form(""), resource: str = Form("")):
    get_client(client_id)
    if grant_type == "authorization_code":
        with DB_LOCK, db() as connection:
            row = connection.execute("SELECT * FROM auth_codes WHERE code_hash = ?", (digest(code),)).fetchone()
        valid = row and not row["used"] and parse_time(row["expires_at"]) > now() and row["client_id"] == client_id and row["redirect_uri"] == redirect_uri and (not resource or resource == RESOURCE) and hmac.compare_digest(pkce_s256(code_verifier), row["code_challenge"])
        if not valid:
            raise HTTPException(400, "invalid_grant")
        with DB_LOCK, db() as connection:
            connection.execute("UPDATE auth_codes SET used = 1 WHERE code_hash = ?", (digest(code),))
        return JSONResponse(issue_tokens(row["username"], client_id, row["scope"]), headers={"Cache-Control": "no-store"})
    if grant_type == "refresh_token":
        old_hash = digest(refresh_token)
        with DB_LOCK, db() as connection:
            row = connection.execute("SELECT * FROM refresh_tokens WHERE token_hash = ?", (old_hash,)).fetchone()
        valid = row and not row["revoked"] and parse_time(row["expires_at"]) > now() and row["client_id"] == client_id and (not resource or resource == RESOURCE)
        if not valid:
            raise HTTPException(400, "invalid_grant")
        with DB_LOCK, db() as connection:
            connection.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?", (old_hash,))
        result = issue_tokens(row["username"], client_id, row["scope"])
        with DB_LOCK, db() as connection:
            connection.execute("UPDATE refresh_tokens SET replaced_by = ? WHERE token_hash = ?", (digest(result["refresh_token"]), old_hash))
        return JSONResponse(result, headers={"Cache-Control": "no-store"})
    raise HTTPException(400, "unsupported_grant_type")


@web.post("/oauth/revoke")
def revoke(token: str = Form(...), client_id: str = Form(...)):
    token_hash = digest(token)
    with DB_LOCK, db() as connection:
        connection.execute("UPDATE access_tokens SET revoked = 1 WHERE token_hash = ? AND client_id = ?", (token_hash, client_id))
        connection.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND client_id = ?", (token_hash, client_id))
    return Response(status_code=200)


@web.get("/health")
async def health():
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            response = await client.get(WIKI_API, params={"action": "query", "meta": "siteinfo", "format": "json"})
            response.raise_for_status()
        upstream = "ok"
    except Exception:
        upstream = "unavailable"
    status = "ok" if upstream == "ok" else "degraded"
    return JSONResponse({"status": status, "upstream": upstream}, status_code=200 if status == "ok" else 503)


@asynccontextmanager
async def lifespan(_):
    init_db()
    async with mcp.session_manager.run():
        yield


web.router.lifespan_context = lifespan


class ExactMcpPath:
    def __init__(self, child: ASGIApp):
        self.child = child

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        child_scope = dict(scope)
        child_scope["root_path"] = scope.get("root_path", "") + "/mcp"
        child_scope["path"] = "/"
        child_scope["raw_path"] = b"/"
        await self.child(child_scope, receive, send)


inner = ExactMcpPath(mcp.streamable_http_app())
web.router.routes.append(StarletteRoute("/mcp", endpoint=inner, methods=["GET", "POST", "DELETE"]))
app = web
