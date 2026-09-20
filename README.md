# Wikimedia-MCP

Self-hosted MCP connector for a private MediaWiki, with a Docker Compose example
containing the wiki and a separate Python MCP service. Independent project; not
affiliated with the Wikimedia Foundation.

The connector talks exclusively to MediaWiki's Action API. It supports searching
and reading pages, revision history, recent changes, contributions and backlinks,
plus creating, updating, appending, prepending, undoing, moving and deleting pages.
The interface and tool descriptions are in German.

## Authentication and private access

The Streamable HTTP endpoint is `/mcp`. Authorization uses authorization code flow
with PKCE S256, dynamic client registration, scoped access tokens, refresh-token
rotation and token revocation. OAuth state is stored in a separate SQLite volume;
access and refresh tokens are stored as keyed hashes.

The configured `WIKI_USERNAME` is the single integration account. The authorization
screen checks that account's password through MediaWiki. All MCP operations run as
that account, subject to its wiki permissions and the granted OAuth scopes:
`wiki:read`, `wiki:write` and `wiki:admin`.

The wiki disables anonymous reading, editing and self-registration. Administrators
can create accounts. Uploaded files use MediaWiki's `img_auth.php`; Apache denies
direct access to the uploads directory.

## Included stack

- MediaWiki 1.27.1 and PHP 5.6.40
- Historical MobileFrontend build pinned in `wiki/Dockerfile`
- SQLite wiki storage
- Python 3.12 MCP service, FastAPI and the MCP SDK
- Host Nginx examples for HTTPS termination

The bundled wiki/PHP stack is a legacy compatibility snapshot, not a modernized
distribution. Review and upgrade it before choosing it for a new deployment.
Image and source archive pins are retained from the working deployment.

## Configuration and startup

Requirements: Docker with Compose, a domain, and an HTTPS reverse proxy.

1. Copy `.env.example` to `.env` and set your public URL, account name and contact
   address. The example domain is a placeholder.
2. Create local secret files (never commit them):

   ```sh
   mkdir -p secrets
   chmod 700 secrets
   (umask 077; openssl rand -hex 32 > secrets/wiki_password)
   (umask 077; openssl rand -hex 32 > secrets/oauth_signing_secret)
   ```

   For a fresh wiki, the first secret becomes the configured administrator's
   password. For an existing wiki, it must match the integration account.
   The MCP container runs as UID 65532 and must be able to read its mounted secret
   files. With file-backed Compose secrets, grant that UID read access via local
   ACLs or ownership; keep the containing host directory private.

3. Run `docker compose up -d --build`.
4. Adapt `nginx.example.conf` for your domain, certificate paths and ports.
   `nginx-http.example.conf` provides the HTTP redirect block for an existing
   HTTPS setup. Validate with `nginx -t` before reloading Nginx.
5. Open your HTTPS wiki URL and log in. Configure an MCP client with
   `https://your-domain/mcp` and complete authorization.

Ports bind to localhost by default. Wiki data, generated configuration, uploads
and OAuth state persist in Docker volumes. Back up these volumes privately.

`wiki/LocalSettings.extra.php` is appended only during the initial wiki install.
For an existing installation, apply settings to the persistent
`/var/www/config/LocalSettings.php` inside the wiki container. Rebuilding an image
alone does not replace an existing volume's configuration.

## Validation

`tests/acceptance.py` exercises OAuth and MCP against a running deployment.
It **appends content to the existing page `MCP-Systemtest`** and registers an OAuth
client; run it only against a disposable test wiki or an intentionally designated
test page. Set `MCP_BASE`, `WIKI_PUBLIC_URL`, `WIKI_USERNAME` and supply the password
through `WIKI_PASSWORD` or the mounted `/run/secrets/wiki_password` file.
The script requires `httpx`.

## Repository contents

Only source code and generic configuration examples are included. Production
secrets, account data, page contents, database files, uploads, logs, backups and
generated `LocalSettings.php` are excluded. Configure each deployment locally.
