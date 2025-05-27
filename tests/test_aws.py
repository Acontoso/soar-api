import unittest
from unittest.mock import patch, MagicMock
from application.services.servicesaws import DynamoDBService, SSMServices
from application.main import app


class TestDynamoDBService(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    @patch("application.services.servicesaws.boto3.client")
    @patch("application.services.servicesaws.current_app")
    def test_get_item_success(self, mock_current_app, mock_boto_client):
        # Setup
        mock_dynamodb = MagicMock()
        mock_boto_client.return_value = mock_dynamodb
        mock_dynamodb.get_item.return_value = {
            "Item": {"id": {"S": "123"}, "value": {"N": "42"}}
        }
        service = DynamoDBService(region="us-east-1")
        result = service.get_item("table", "id", "123", "sort", "abc")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["id"], "123")
        self.assertEqual(result["value"], 42)

    @patch("application.services.servicesaws.boto3.client")
    @patch("application.services.servicesaws.current_app")
    def test_put_item_success(self, mock_current_app, mock_boto_client):
        mock_dynamodb = MagicMock()
        mock_boto_client.return_value = mock_dynamodb
        service = DynamoDBService(region="us-east-1")
        result = service.put_item("table", {"id": {"S": "123"}})
        self.assertTrue(result)


class TestSSMServices(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    @patch("application.services.servicesaws.boto3.client")
    @patch("application.services.servicesaws.base64.b64decode")
    @patch("application.services.servicesaws.current_app")
    def test_get_param_success(self, mock_current_app, mock_b64decode, mock_boto_client):
        mock_ssm = MagicMock()
        mock_kms = MagicMock()
        mock_boto_client.side_effect = [mock_ssm, mock_kms]
        mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "c2VjcmV0"}}
        mock_b64decode.return_value = b"encrypted"
        mock_kms.decrypt.return_value = {"Plaintext": b"decrypted_secret"}
        service = SSMServices(region="us-east-1")
        result = service.get_param("myparam")
        self.assertEqual(result, "decrypted_secret")


if __name__ == "__main__":
    unittest.main()
