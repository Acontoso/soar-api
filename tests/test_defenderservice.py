import unittest
from unittest.mock import patch, MagicMock
from application.services.defenderservice import Defender
from application.main import app

class TestDefender(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    @patch("application.services.defenderservice.current_app")
    @patch.object(Defender, "access_token_ms_sec_api")
    @patch.object(Defender, "check_indicator")
    @patch.object(Defender, "block_indicator")
    @patch.object(Defender, "construct_payload_defender")
    def test_upload_success(self, mock_payload, mock_block, mock_check, mock_token, mock_current_app):
        mock_token.return_value = "token"
        mock_check.return_value = False
        mock_payload.return_value = {"foo": "bar"}
        mock_block.return_value = True
        result = Defender.upload("ioc", "type", "action", "incident_id")
        self.assertTrue(result)

    @patch("application.services.defenderservice.current_app")
    def test_upload_missing_params(self, mock_current_app):
        result = Defender.upload("", "type", "action", "incident_id")
        self.assertFalse(result)
        mock_current_app.logger.error.assert_called_with("One or more required parameters are empty.")

    @patch("application.services.defenderservice.current_app")
    @patch.object(Defender, "access_token_ms_sec_api")
    def test_upload_no_token(self, mock_token, mock_current_app):
        mock_token.return_value = None
        result = Defender.upload("ioc", "type", "action", "incident_id")
        self.assertFalse(result)

    @patch("application.services.defenderservice.current_app")
    @patch.object(Defender, "access_token_ms_sec_api")
    @patch.object(Defender, "check_indicator")
    def test_upload_indicator_exists(self, mock_check, mock_token, mock_current_app):
        mock_token.return_value = "token"
        mock_check.return_value = True
        result = Defender.upload("ioc", "type", "action", "incident_id")
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
