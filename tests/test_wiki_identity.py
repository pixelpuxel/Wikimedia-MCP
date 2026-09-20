import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp-server"))
import server


class WikiIdentityTests(unittest.IsolatedAsyncioTestCase):
    async def test_personal_account_authorizes_connector(self):
        client = Mock()
        client.aclose = AsyncMock()
        login = AsyncMock(return_value=client)
        with patch.object(server, "WIKI_USERNAME", "MCP"), patch.object(server, "WIKI_AUTH_USERNAME", "WikiOwner"), patch.object(server, "wiki_login", login):
            self.assertTrue(await server.verify_wiki_credentials("WikiOwner", "example-password"))
            login.assert_awaited_once_with("WikiOwner", "example-password")
            self.assertFalse(await server.verify_wiki_credentials("MCP", "example-password"))

    async def test_wiki_calls_use_service_account(self):
        response = Mock()
        response.json.return_value = {"query": {"userinfo": {"name": "MCP"}}}
        client = Mock()
        client.get = AsyncMock(return_value=response)
        client.aclose = AsyncMock()
        login = AsyncMock(return_value=client)
        with patch.object(server, "WIKI_USERNAME", "MCP"), patch.object(server, "WIKI_AUTH_USERNAME", "WikiOwner"), patch.object(server, "wiki_login", login), patch.object(server, "current_access"), patch.object(server, "read_secret", return_value="service-password"):
            result = await server.wiki_call({"action": "query", "meta": "userinfo"})
            self.assertEqual(result["query"]["userinfo"]["name"], "MCP")
            login.assert_awaited_once_with("MCP", "service-password")


if __name__ == "__main__":
    unittest.main()
