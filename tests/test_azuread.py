import unittest
from unittest.mock import patch, MagicMock
from application.services.azuread import Azure
from application.main import app

class TestAzureAD(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    @patch("application.services.azuread.current_app")
    @patch("application.services.azuread.requests.get")
    @patch("application.services.azuread.requests.patch")
    @patch.object(Azure, "access_token_graph_api")
    def test_az_ad_list_upload_success(self, mock_token, mock_patch, mock_get, mock_current_app):
        mock_token.return_value = "fake_token"
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"ipRanges": [{"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "1.2.3.4/32"}]}
        mock_patch.return_value.status_code = 204
        result = Azure.az_ad_list_upload("5.6.7.8/32", "listid", "listname")
        self.assertTrue(result)
        mock_current_app.logger.info.assert_any_call(
            "[+] Successfully added IP 5.6.7.8/32 to Azure AD list listname"
        )

    @patch("application.services.azuread.current_app")
    @patch.object(Azure, "access_token_graph_api")
    def test_az_ad_list_upload_missing_params(self, mock_token, mock_current_app):
        result = Azure.az_ad_list_upload("", "listid", "listname")
        self.assertFalse(result)
        mock_current_app.logger.error.assert_called_with("One or more required parameters are empty.")

    @patch("application.services.azuread.current_app")
    @patch("application.services.azuread.requests.get")
    @patch.object(Azure, "access_token_graph_api")
    def test_az_ad_list_upload_get_fail(self, mock_token, mock_get, mock_current_app):
        mock_token.return_value = "fake_token"
        mock_get.return_value.status_code = 404
        result = Azure.az_ad_list_upload("5.6.7.8/32", "listid", "listname")
        self.assertFalse(result)

    @patch("application.services.azuread.current_app")
    @patch("application.services.azuread.requests.get")
    @patch("application.services.azuread.requests.patch")
    @patch.object(Azure, "access_token_graph_api")
    def test_az_ad_list_upload_patch_fail(self, mock_token, mock_patch, mock_get, mock_current_app):
        mock_token.return_value = "fake_token"
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"ipRanges": []}
        mock_patch.return_value.status_code = 400
        result = Azure.az_ad_list_upload("5.6.7.8/32", "listid", "listname")
        self.assertFalse(result)
        mock_current_app.logger.error.assert_any_call(
            "[+] Failed to add IP 5.6.7.8/32 to Azure AD list listname"
        )

    @patch("application.services.azuread.current_app")
    @patch.object(Azure, "access_token_graph_api")
    def test_az_ad_list_upload_no_token(self, mock_token, mock_current_app):
        mock_token.return_value = None
        result = Azure.az_ad_list_upload("5.6.7.8/32", "listid", "listname")
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()
