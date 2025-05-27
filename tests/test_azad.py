import unittest
from unittest.mock import patch, MagicMock
from application.controllers.azad import AzureAD
from application.main import app

class TestAzureAD(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        self.mock_logger = MagicMock()
        app.logger = self.mock_logger

    def tearDown(self):
        self.app_context.pop()

    @patch('application.controllers.azad.AzureAD.lookup_record_to_db')
    def test_ip_upload_invalid_ip(self, mock_lookup):
        result = AzureAD.ip_upload('invalid_ip', 'listid', 'listname', 'incid')
        self.assertEqual(result, {'Action': False, 'IOC': 'invalid_ip', 'ListName': 'listname'})
        app.logger.error.assert_called()

    @patch('application.controllers.azad.AzureAD.lookup_record_to_db', return_value={'ListName': 'existinglist'})
    def test_ip_upload_record_found(self, mock_lookup):
        result = AzureAD.ip_upload('1.2.3.4/32', 'listid', 'listname', 'incid')
        self.assertEqual(result, {'Action': True, 'IOC': '1.2.3.4/32', 'ListName': 'existinglist'})
        app.logger.info.assert_called()

    @patch('application.controllers.azad.AzureAD.lookup_record_to_db', return_value=None)
    @patch('application.controllers.azad.AzureAD.add_to_list', return_value=True)
    @patch('application.controllers.azad.AzureAD.add_record_to_db')
    def test_ip_upload_add_success(self, mock_add_record, mock_add_to_list, mock_lookup):
        result = AzureAD.ip_upload('1.2.3.4', 'listid', 'listname', 'incid')
        self.assertEqual(result, {'Action': True, 'IOC': '1.2.3.4/32', 'ListName': 'listname'})
        mock_add_to_list.assert_called_once()
        mock_add_record.assert_called_once()

    @patch('application.controllers.azad.AzureAD.lookup_record_to_db', return_value=None)
    @patch('application.controllers.azad.AzureAD.add_to_list', return_value=False)
    @patch('application.controllers.azad.AzureAD.add_record_to_db')
    def test_ip_upload_add_fail(self, mock_add_record, mock_add_to_list, mock_lookup):
        result = AzureAD.ip_upload('1.2.3.4', 'listid', 'listname', 'incid')
        self.assertEqual(result, {'Action': False, 'IOC': '1.2.3.4/32', 'ListName': 'listname'})
        mock_add_to_list.assert_called_once()
        mock_add_record.assert_not_called()

    @patch('application.controllers.azad.DynamoDBService')
    def test_add_record_to_db(self, mock_dynamo):
        mock_instance = mock_dynamo.return_value
        AzureAD.add_record_to_db('ioc', 'listid', 'listname', 'incid')
        mock_instance.put_item.assert_called()

    @patch('application.controllers.azad.DynamoDBService')
    def test_lookup_record_to_db(self, mock_dynamo):
        mock_instance = mock_dynamo.return_value
        mock_instance.get_item.return_value = {'foo': 'bar'}
        result = AzureAD.lookup_record_to_db('ioc', 'AzureAD')
        mock_instance.get_item.assert_called()
        self.assertEqual(result, {'foo': 'bar'})

    @patch('application.controllers.azad.SSMServices')
    def test_get_ssm_api_key(self, mock_ssm):
        mock_instance = mock_ssm.return_value
        mock_instance.get_param.return_value = 'apikey'
        result = AzureAD.get_ssm_api_key()
        self.assertEqual(result, 'apikey')
        mock_instance.get_param.assert_called_with(param='urlscan')

    @patch('application.controllers.azad.SSMServices')
    def test_get_ssm_api_key_none(self, mock_ssm):
        mock_instance = mock_ssm.return_value
        mock_instance.get_param.return_value = None
        result = AzureAD.get_ssm_api_key()
        self.assertIsNone(result)
        mock_instance.get_param.assert_called_with(param='urlscan')

    @patch('application.services.azuread.Azure.az_ad_list_upload', return_value=True)
    def test_add_to_list(self, mock_upload):
        result = AzureAD.add_to_list('ioc', 'listid', 'listname')
        self.assertTrue(result)
        mock_upload.assert_called_once_with('ioc', 'listid', 'listname')

    def test_is_cidr(self):
        self.assertTrue(AzureAD.is_cidr('1.2.3.4/24'))
        self.assertFalse(AzureAD.is_cidr('1.2.3.4'))
        self.assertIsNone(AzureAD.is_cidr('notanip'))

if __name__ == '__main__':
    unittest.main()
