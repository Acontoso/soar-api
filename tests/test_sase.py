import unittest
from unittest.mock import patch, MagicMock
from flask import Flask
from application.controllers.sase import SASE

class TestSASE(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.ctx = self.app.app_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.SASE.lookup_record_to_db")
    def test_block_record_exists(self, mock_lookup, mock_current_app):
        mock_lookup.return_value = {"Integration": "SASE", "Action": "Block"}
        result = SASE.block("1.2.3.4", "incident1")
        self.assertTrue(result["Added"])
        self.assertEqual(result["Integration"], "SASE")
        self.assertEqual(result["Action"], "Block")

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.Umbrella.upload")
    @patch("application.controllers.sase.SASE.lookup_record_to_db")
    @patch("application.controllers.sase.SASE.add_record_to_db_action")
    def test_block_success(self, mock_add, mock_lookup, mock_umbrella, mock_current_app):
        mock_lookup.return_value = None
        mock_umbrella.return_value = True
        result = SASE.block("1.2.3.4", "incident1")
        self.assertTrue(result["Added"])
        self.assertEqual(result["Integration"], "SASE")
        self.assertEqual(result["Action"], "Block")
        mock_add.assert_called()

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.Umbrella.upload")
    @patch("application.controllers.sase.SASE.lookup_record_to_db")
    def test_block_fail(self, mock_lookup, mock_umbrella, mock_current_app):
        mock_lookup.return_value = None
        mock_umbrella.return_value = False
        result = SASE.block("1.2.3.4", "incident1")
        self.assertFalse(result["Added"])
        self.assertEqual(result["Integration"], "SASE")
        self.assertEqual(result["Action"], "Block")

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.SASE.lookup_record_to_db")
    def test_block_private_ipv4(self, mock_lookup, mock_current_app):
        mock_lookup.return_value = None
        # 10.0.0.1 is a private IP
        result = SASE.block("10.0.0.1", "incident1")
        self.assertFalse(result["Added"])
        self.assertEqual(result["Integration"], "SASE")
        self.assertEqual(result["Action"], "Block")

    def test_ioc_type_finder(self):
        self.assertEqual(SASE.ioc_type_finder("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), "SHA256")
        self.assertEqual(SASE.ioc_type_finder("0123456789abcdef0123456789abcdef"), "MD5")
        self.assertEqual(SASE.ioc_type_finder("0123456789abcdef0123456789abcdef01234567"), "SHA1")
        self.assertEqual(SASE.ioc_type_finder("1.2.3.4"), "IPv4")
        self.assertEqual(SASE.ioc_type_finder("example.com"), "Domain")
        self.assertEqual(SASE.ioc_type_finder("notanip"), "Domain")

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.SSEServices.sandbox_file")
    @patch("application.controllers.sase.SSEServices.sandbox_api_key")
    def test_submit_file_success(self, mock_api_key, mock_sandbox_file, mock_current_app):
        mock_api_key.return_value = "key"
        mock_sandbox_file.return_value = {
            "md5": "abc",
            "sandboxSubmission": "ok",
            "virusName": "EICAR",
            "virusType": "Test",
            "code": 200
        }
        mock_current_app.logger = MagicMock()
        result = SASE.submit_file(b"filedata")
        self.assertTrue(result["Sandbox"])
        self.assertEqual(result["MD5"], "abc")
        self.assertEqual(result["Status"], "ok")
        self.assertEqual(result["VirusName"], "EICAR")
        self.assertEqual(result["VirusType"], "Test")
        self.assertEqual(result["StatusCode"], 200)

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.SSEServices.sandbox_file", return_value=None)
    @patch("application.controllers.sase.SSEServices.sandbox_api_key", return_value="key")
    def test_submit_file_failure(self, mock_api_key, mock_sandbox_file, mock_current_app):
        mock_current_app.logger = MagicMock()
        result = SASE.submit_file(b"filedata")
        self.assertFalse(result["Sandbox"])
        self.assertIn("Failed to submit file", result["Message"])

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.SSEServices.sandbox_api_key", return_value=None)
    def test_submit_file_no_api_key(self, mock_api_key, mock_current_app):
        mock_current_app.logger = MagicMock()
        result = SASE.submit_file(b"filedata")
        self.assertFalse(result["Sandbox"])
        self.assertIn("Failed to get JSESSIONID", result["Message"])

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.SSEServices.lookup_url_category")
    @patch("application.controllers.sase.SASE.lookup_record_to_db")
    @patch("application.controllers.sase.SASE.add_record_to_db_enrich")
    def test_url_category_lookup_success(self, mock_add, mock_lookup, mock_lookup_url, mock_current_app):
        mock_lookup.return_value = None
        mock_lookup_url.return_value = {"Categories": ["Malware"]}
        mock_current_app.logger = MagicMock()
        result = SASE.url_category_lookup("example.com")
        self.assertEqual(result["IOC"], "example.com")
        self.assertIn("Malware", result["Categories"])
        self.assertEqual(result["Action"], "Lookup")
        self.assertEqual(result["Integration"], "SASE")

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.SASE.lookup_record_to_db")
    def test_url_category_lookup_db(self, mock_lookup, mock_current_app):
        mock_lookup.return_value = {"Categories": ["Phishing"], "Date": "01-01-2025"}
        mock_current_app.logger = MagicMock()
        result = SASE.url_category_lookup("example.com")
        self.assertEqual(result["IOC"], "example.com")
        self.assertIn("Phishing", result["Categories"])
        self.assertEqual(result["Action"], "Lookup")
        self.assertEqual(result["Integration"], "SASE")

if __name__ == "__main__":
    unittest.main()
