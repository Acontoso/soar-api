import unittest
from unittest.mock import patch, MagicMock
from application.controllers.defender import DATP
from application.main import app

class TestDATP(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        self.mock_logger = MagicMock()
        app.logger = self.mock_logger  # Patch the logger directly

    def tearDown(self):
        self.app_context.pop()

    @patch('application.controllers.defender.DATP.lookup_record_to_db')
    def test_ioc_upload_record_found(self, mock_lookup):
        mock_lookup.return_value = {'Platform': 'DATP', 'Action': 'Block'}
        result = DATP.ioc_upload('testioc', 'Block', 'INC123', 'test-tenant')
        self.assertEqual(result, {'Added': True, 'IOC': 'testioc', 'Platform': 'DATP', 'Action': 'Block'})
        self.mock_logger.info.assert_called()

    @patch('application.controllers.defender.DATP.lookup_record_to_db', return_value=None)
    def test_ioc_upload_ipaddress(self, mock_lookup):
        result = DATP.ioc_upload('8.8.8.8', 'Block', 'INC123', 'test-tenant')
        self.assertEqual(result, {'Added': False, 'IOC': '8.8.8.8', 'Platform': 'DATP', 'Action': 'None'})

    @patch('application.controllers.defender.DATP.lookup_record_to_db', return_value=None)
    def test_ioc_upload_domain(self, mock_lookup):
        result = DATP.ioc_upload('example.com', 'Block', 'INC123', 'test-tenant')
        self.assertEqual(result, {'Added': False, 'IOC': 'example.com', 'Platform': 'DATP', 'Action': 'None'})

    @patch('application.controllers.defender.DATP.lookup_record_to_db', return_value=None)
    @patch('application.controllers.defender.Defender.upload', return_value=True)
    @patch('application.controllers.defender.DATP.add_record_to_db')
    def test_ioc_upload_file_success(self, mock_add, mock_upload, mock_lookup):
        result = DATP.ioc_upload('a'*64, 'Block', 'INC123', 'test-tenant')
        self.assertEqual(result, {'Added': True, 'IOC': 'a'*64, 'Platform': 'DATP', 'Action': 'Block'})
        mock_upload.assert_called_once()
        mock_add.assert_called_once()

    @patch('application.controllers.defender.DATP.lookup_record_to_db', return_value=None)
    @patch('application.controllers.defender.Defender.upload', return_value=False)
    @patch('application.controllers.defender.DATP.add_record_to_db')
    def test_ioc_upload_file_fail(self, mock_add, mock_upload, mock_lookup):
        result = DATP.ioc_upload('b'*64, 'Block', 'INC123', 'test-tenant')
        self.assertEqual(result, {'Added': False, 'IOC': 'b'*64, 'Platform': 'DATP', 'Action': 'None'})
        mock_upload.assert_called_once()
        mock_add.assert_called_once()


    @patch('application.controllers.defender.DynamoDBService')
    def test_add_record_to_db(self, mock_dynamo):
        mock_instance = mock_dynamo.return_value
        DATP.add_record_to_db('ioc', 'FileSha256', 'Block', 'INC123', 'test-tenant')
        mock_instance.put_item.assert_called()

    @patch('application.controllers.defender.DynamoDBService')
    def test_lookup_record_to_db(self, mock_dynamo):
        mock_instance = mock_dynamo.return_value
        mock_instance.get_item.return_value = {'foo': 'bar'}
        result = DATP.lookup_record_to_db('ioc', 'DATPIndicator')
        mock_instance.get_item.assert_called()
        self.assertEqual(result, {'foo': 'bar'})

if __name__ == '__main__':
    unittest.main()
