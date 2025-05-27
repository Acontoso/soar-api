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
        mock_lookup.return_value = {"Platform": "SASE", "Action": "Block"}
        result = SASE.block("1.2.3.4", "incident1")
        self.assertTrue(result["Added"])
        self.assertEqual(result["Platform"], "SASE")
        self.assertEqual(result["Action"], "Block")

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.Umbrella.upload")
    @patch("application.controllers.sase.SASE.lookup_record_to_db")
    @patch("application.controllers.sase.SASE.add_record_to_db")
    def test_block_success(self, mock_add, mock_lookup, mock_umbrella, mock_current_app):
        mock_lookup.return_value = None
        mock_umbrella.return_value = True
        result = SASE.block("1.2.3.4", "incident1")
        self.assertTrue(result["Added"])
        self.assertEqual(result["Platform"], "SASE")
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
        self.assertEqual(result["Platform"], "SASE")
        self.assertEqual(result["Action"], "Block")

    @patch("application.controllers.sase.current_app")
    @patch("application.controllers.sase.SASE.lookup_record_to_db")
    def test_block_private_ipv4(self, mock_lookup, mock_current_app):
        mock_lookup.return_value = None
        # 10.0.0.1 is a private IP
        result = SASE.block("10.0.0.1", "incident1")
        self.assertFalse(result["Added"])
        self.assertEqual(result["Platform"], "SASE")
        self.assertEqual(result["Action"], "Block")

    def test_ioc_type_finder(self):
        self.assertEqual(SASE.ioc_type_finder("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), "SHA256")
        self.assertEqual(SASE.ioc_type_finder("0123456789abcdef0123456789abcdef"), "MD5")
        self.assertEqual(SASE.ioc_type_finder("0123456789abcdef0123456789abcdef01234567"), "SHA1")
        self.assertEqual(SASE.ioc_type_finder("1.2.3.4"), "IPv4")
        self.assertEqual(SASE.ioc_type_finder("example.com"), "Domain")
        self.assertEqual(SASE.ioc_type_finder("notanip"), "Domain")

if __name__ == "__main__":
    unittest.main()
