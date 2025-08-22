import unittest
from unittest.mock import patch
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
        # Use approved values
        list_id = "0b7f8da0-a271-4bf8-9c85-01c7514766c9"
        list_name = "SOAR-API-Locations"
        tenant_id = "test-tenant-id"
        result = Azure.az_ad_list_upload("5.6.7.8/32", list_id, list_name, tenant_id)
        self.assertTrue(result)
        mock_current_app.logger.info.assert_any_call(
            f"[+] Successfully added IP 5.6.7.8/32 to Azure AD list {list_name}"
        )

    @patch("application.services.azuread.current_app")
    @patch.object(Azure, "access_token_graph_api")
    def test_az_ad_list_upload_missing_params(self, mock_token, mock_current_app):
        # Use approved values
        list_id = "0b7f8da0-a271-4bf8-9c85-01c7514766c9"
        list_name = "SOAR-API-Locations"
        tenant_id = "test-tenant-id"
        result = Azure.az_ad_list_upload("", list_id, list_name, tenant_id)
        self.assertFalse(result)
        mock_current_app.logger.error.assert_called_with("One or more required parameters are empty.")

    @patch("application.services.azuread.current_app")
    @patch("application.services.azuread.requests.get")
    @patch.object(Azure, "access_token_graph_api")
    def test_az_ad_list_upload_get_fail(self, mock_token, mock_get, mock_current_app):
        mock_token.return_value = "fake_token"
        mock_get.return_value.status_code = 404
        # Use approved values
        list_id = "0b7f8da0-a271-4bf8-9c85-01c7514766c9"
        list_name = "SOAR-API-Locations"
        tenant_id = "test-tenant-id"
        result = Azure.az_ad_list_upload("5.6.7.8/32", list_id, list_name, tenant_id)
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
        # Use approved values
        list_id = "0b7f8da0-a271-4bf8-9c85-01c7514766c9"
        list_name = "SOAR-API-Locations"
        tenant_id = "test-tenant-id"
        result = Azure.az_ad_list_upload("5.6.7.8/32", list_id, list_name, tenant_id)
        self.assertFalse(result)
        mock_current_app.logger.error.assert_any_call(
            f"[+] Failed to add IP 5.6.7.8/32 to Azure AD list {list_name}"
        )

    @patch("application.services.azuread.current_app")
    @patch.object(Azure, "access_token_graph_api")
    def test_az_ad_list_upload_no_token(self, mock_token, mock_current_app):
        mock_token.return_value = None
        # Use approved values
        list_id = "0b7f8da0-a271-4bf8-9c85-01c7514766c9"
        list_name = "SOAR-API-Locations"
        tenant_id = "test-tenant-id"
        result = Azure.az_ad_list_upload("5.6.7.8/32", list_id, list_name, tenant_id)
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()
