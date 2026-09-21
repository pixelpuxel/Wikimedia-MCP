import base64
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp-server"))
import server


class FileHelperTests(unittest.TestCase):
    def test_normalizes_file_namespace(self):
        self.assertEqual(server.normalize_filename("Datei: Beispiel Bild.PNG"), "Beispiel Bild.PNG")

    def test_rejects_paths_and_unsupported_extensions(self):
        for value in ("../secret.png", "folder/image.png", "bad|name.png", "payload.svg", "README"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                server.normalize_filename(value)

    def test_decodes_plain_base64_and_data_url(self):
        encoded = base64.b64encode(b"test file").decode()
        self.assertEqual(server.decode_upload(encoded), b"test file")
        self.assertEqual(server.decode_upload("data:image/png;base64," + encoded), b"test file")

    def test_rejects_invalid_or_empty_base64(self):
        for value in ("not-base64!", ""):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                server.decode_upload(value)


class FileToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_get_file_uses_legacy_imageusage_list_module(self):
        response = {
            "query": {
                "pages": {
                    "3": {
                        "pageid": 3,
                        "title": "File:photo.png",
                        "imageinfo": [{"size": 4, "mime": "image/png", "url": "https://wiki.example.org/img_auth.php/photo.png"}],
                    }
                },
                "imageusage": [{"pageid": 7, "title": "Page"}],
            }
        }
        with (
            patch.object(server, "markup_namespaces", AsyncMock(return_value=("Media", "File"))),
            patch.object(server, "wiki_call", AsyncMock(return_value=response)) as call,
        ):
            result = await server.get_file("photo.png")
        params = call.await_args.args[0]
        self.assertEqual(params["prop"], "imageinfo")
        self.assertEqual(params["list"], "imageusage")
        self.assertEqual(params["iutitle"], "File:photo.png")
        self.assertEqual(result["used_on"], [{"page_id": 7, "title": "Page"}])

    async def test_upload_refuses_existing_file_by_default(self):
        with patch.object(server, "get_file", AsyncMock(return_value={"exists": True})):
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                await server.upload_file("photo.png", "dGVzdA==")

    async def test_embed_image_builds_safe_wikitext(self):
        page = {"exists": True, "revision_id": 12, "content": "Intro"}
        updated = {"status": "Success", "revision_id": 13}
        with (
            patch.object(server, "get_file", AsyncMock(return_value={"exists": True})),
            patch.object(server, "get_page", AsyncMock(return_value=page)),
            patch.object(server, "markup_namespaces", AsyncMock(return_value=("Media", "File"))),
            patch.object(server, "wiki_call", AsyncMock(return_value={"purge": True})),
            patch.object(server, "update_page", AsyncMock(return_value=updated)) as update,
        ):
            result = await server.embed_file_on_page(
                "Page", "photo.png", 12, caption="Caption", alt_text="Alt", width=400
            )
        markup = "[[File:photo.png|thumb|right|400px|alt=Alt|Caption]]"
        update.assert_awaited_once_with("Page", "Intro\n\n" + markup, 12, "Datei über MCP eingebunden")
        self.assertEqual(result["markup"], markup)

    async def test_embed_pdf_inserts_protected_media_link(self):
        page = {"exists": True, "revision_id": 7, "content": ""}
        with (
            patch.object(server, "get_file", AsyncMock(return_value={"exists": True})),
            patch.object(server, "get_page", AsyncMock(return_value=page)),
            patch.object(server, "markup_namespaces", AsyncMock(return_value=("Media", "File"))),
            patch.object(server, "wiki_call", AsyncMock(return_value={"purge": True})),
            patch.object(server, "update_page", AsyncMock(return_value={"status": "Success"})) as update,
        ):
            result = await server.embed_file_on_page("Page", "manual.pdf", 7, caption="Manual")
        update.assert_awaited_once_with("Page", "[[Media:manual.pdf|Manual]]", 7, "Datei über MCP eingebunden")
        self.assertEqual(result["markup"], "[[Media:manual.pdf|Manual]]")

    async def test_delete_refuses_file_that_is_still_used(self):
        info = {"exists": True, "used_on": [{"title": "Page"}]}
        with patch.object(server, "get_file", AsyncMock(return_value=info)):
            with self.assertRaisesRegex(RuntimeError, "still used"):
                await server.delete_file("photo.png", "cleanup")


if __name__ == "__main__":
    unittest.main()
