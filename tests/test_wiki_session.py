import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp-server"))
import server


class WikiSessionTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, api):
        seen = []

        def upstream(request):
            seen.append(request.headers.get("cookie", ""))
            step = len(seen)
            if step == 1:
                body = {"query": {"tokens": {"logintoken": "test-login-token"}}}
            elif step == 2:
                body = {"login": {"result": "Success"}}
            else:
                body = {"query": {"userinfo": {"id": 1}}}
            return httpx.Response(
                200, json=body,
                headers={"set-cookie": f"wiki_session=session-{step}; Path=/; Secure; HttpOnly"},
            )

        real_client = httpx.AsyncClient

        def client_factory(**kwargs):
            return real_client(transport=httpx.MockTransport(upstream), **kwargs)

        with patch.object(server, "WIKI_API", api), patch.object(server.httpx, "AsyncClient", client_factory):
            client = await server.wiki_login("ExampleUser", "test-password")
            try:
                await client.get(api)
                await client.get(api)
                secure = [cookie.secure for cookie in client.cookies.jar]
            finally:
                await client.aclose()
        return seen, secure

    async def test_internal_session_survives_login_and_cookie_rotation(self):
        seen, secure = await self.exercise("http://wiki/api.php")
        self.assertEqual(seen, ["", "wiki_session=session-1", "wiki_session=session-2", "wiki_session=session-3"])
        self.assertEqual(secure, [False])

    async def test_https_cookies_remain_secure(self):
        seen, secure = await self.exercise("https://wiki.example.org/api.php")
        self.assertEqual(seen[-1], "wiki_session=session-3")
        self.assertEqual(secure, [True])

    async def test_other_http_hosts_do_not_receive_secure_cookies(self):
        seen, secure = await self.exercise("http://wiki.example.org/api.php")
        self.assertEqual(seen, ["", "", "", ""])
        self.assertEqual(secure, [True])


if __name__ == "__main__":
    unittest.main()
