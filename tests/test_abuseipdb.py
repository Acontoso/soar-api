import unittest
from unittest.mock import patch, MagicMock
from application.controllers.abuseipdb import IPAbuseDB
from application.main import app
import datetime as real_datetime

#python -W ignore -m unittest discover -s tests
class TestIPAbuseDB(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        self.mock_logger = MagicMock()
        app.logger = self.mock_logger

    def tearDown(self):
        self.app_context.pop()

    @patch('application.controllers.abuseipdb.IPAbuseDB.lookup_record_to_db', return_value=None)
    @patch('application.controllers.abuseipdb.IPAbuseDB.ipabuse_api_call', return_value={'foo': 'bar'})
    def test_ip_lookup_no_db(self, mock_api_call, mock_lookup):
        result = IPAbuseDB.ip_lookup('8.8.8.8')
        self.assertEqual(result, {'foo': 'bar'})
        mock_api_call.assert_called_once_with('8.8.8.8')

    @patch('application.controllers.abuseipdb.IPAbuseDB.lookup_record_to_db', return_value={'Date': '01-01-2020', 'Country': 'US', 'Confidence': 90, 'ReportCount': 10, 'Tor': False, 'IOC': '8.8.8.8'})
    @patch('application.controllers.abuseipdb.IPAbuseDB.ipabuse_api_call', return_value={'foo': 'bar'})
    @patch('application.controllers.abuseipdb.datetime')
    def test_ip_lookup_db_old(self, mock_datetime, mock_api_call, mock_lookup):
        mock_datetime.now.return_value = mock_datetime.strptime('01-01-2025', '%d-%m-%Y')
        mock_datetime.strptime.return_value = mock_datetime.now.return_value
        result = IPAbuseDB.ip_lookup('8.8.8.8')
        self.assertEqual(result, {'foo': 'bar'})
        mock_api_call.assert_called_once_with('8.8.8.8')

    @patch('application.controllers.abuseipdb.IPAbuseDB.ipabuse_api_call')
    @patch('application.controllers.abuseipdb.datetime')
    @patch('application.controllers.abuseipdb.IPAbuseDB.lookup_record_to_db', return_value={'Date': '01-01-2025', 'Country': 'US', 'Confidence': 90, 'ReportCount': 10, 'Tor': False, 'IOC': '8.8.8.8'})
    def test_ip_lookup_db_recent(self, mock_lookup, mock_datetime, mock_api_call):
        mock_datetime.now.return_value = real_datetime.datetime(2025, 1, 2)
        mock_datetime.strptime.side_effect = lambda s, fmt: real_datetime.datetime.strptime(s, fmt)
        result = IPAbuseDB.ip_lookup('8.8.8.8')
        self.assertIsInstance(result, dict)
        self.assertEqual(result['IOC'], '8.8.8.8')
        self.assertNotIn('Date', result)
        mock_api_call.assert_not_called()

    @patch('application.controllers.abuseipdb.IPAbuseDB.ipabuse_api_call')
    @patch('application.controllers.abuseipdb.IPAbuseDB.is_private_ip', return_value=True)
    @patch('application.controllers.abuseipdb.datetime')
    @patch('application.controllers.abuseipdb.IPAbuseDB.lookup_record_to_db', return_value={'Date': '01-01-2020', 'Country': 'US', 'Confidence': 90, 'ReportCount': 10, 'Tor': False, 'Ioc': '10.0.0.1'})
    def test_ip_lookup_db_old_private(self, mock_lookup, mock_datetime, mock_is_private, mock_api_call):
        mock_datetime.now.return_value = real_datetime.datetime(2025, 1, 1)
        mock_datetime.strptime.side_effect = lambda s, fmt: real_datetime.datetime.strptime(s, fmt)
        result = IPAbuseDB.ip_lookup('10.0.0.1')
        self.assertIsInstance(result, dict)
        self.assertTrue(result['Private'])
        self.assertEqual(result['Confidence'], 0)
        self.assertEqual(result['Ioc'], '10.0.0.1')
        mock_api_call.assert_not_called()

    @patch('application.controllers.abuseipdb.DynamoDBService')
    def test_add_record_to_db(self, mock_dynamo):
        mock_instance = mock_dynamo.return_value
        IPAbuseDB.add_record_to_db(90, 'US', 10, False, '8.8.8.8')
        mock_instance.put_item.assert_called()

    @patch('application.controllers.abuseipdb.DynamoDBService')
    def test_lookup_record_to_db(self, mock_dynamo):
        mock_instance = mock_dynamo.return_value
        mock_instance.get_item.return_value = {'foo': 'bar'}
        result = IPAbuseDB.lookup_record_to_db('8.8.8.8', 'IPAbuseDB')
        mock_instance.get_item.assert_called()
        self.assertEqual(result, {'foo': 'bar'})

    @patch('application.controllers.abuseipdb.SSMServices')
    def test_generate_headers(self, mock_ssm):
        mock_instance = mock_ssm.return_value
        mock_instance.get_param.return_value = 'apikey'
        result = IPAbuseDB.generate_headers()
        self.assertIn('Key', result)
        self.assertEqual(result['Key'], 'apikey')

    @patch('application.controllers.abuseipdb.SSMServices')
    def test_generate_headers_empty(self, mock_ssm):
        mock_instance = mock_ssm.return_value
        mock_instance.get_param.return_value = None
        result = IPAbuseDB.generate_headers()
        self.assertEqual(result, {})

    def test_is_private_ip(self):
        self.assertTrue(IPAbuseDB.is_private_ip('10.0.0.1'))
        self.assertFalse(IPAbuseDB.is_private_ip('8.8.8.8'))

if __name__ == '__main__':
    unittest.main()
