import unittest
from unittest.mock import patch, MagicMock
from application.controllers.anomali import Anomali
from application.main import app

class TestAnomali(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        self.mock_logger = MagicMock()
        app.logger = self.mock_logger

    def tearDown(self):
        self.app_context.pop()

    @patch('application.controllers.anomali.Anomali.lookup_record_to_db', return_value=None)
    @patch('application.controllers.anomali.Anomali.anomali_api_call', return_value={'foo': 'bar'})
    def test_ioc_lookup_no_db(self, mock_api_call, mock_lookup):
        result = Anomali.ioc_lookup('ioc')
        self.assertEqual(result, {'foo': 'bar'})
        mock_api_call.assert_called_once_with('ioc')

    @patch('application.controllers.anomali.Anomali.lookup_record_to_db', return_value={'Date': '01-01-2020', 'Confidence': 80, 'IOC': 'ioc', 'IOCType': 'IPv4'})
    @patch('application.controllers.anomali.Anomali.anomali_api_call', return_value={'foo': 'bar'})
    @patch('application.controllers.anomali.datetime')
    def test_ioc_lookup_db_old(self, mock_datetime, mock_api_call, mock_lookup):
        # Simulate current date > 1 year after db date
        mock_datetime.now.return_value = mock_datetime.strptime('01-01-2022', '%d-%m-%Y')
        mock_datetime.strptime.return_value = mock_datetime.now.return_value
        result = Anomali.ioc_lookup('ioc')
        self.assertEqual(result, {'foo': 'bar'})
        mock_api_call.assert_called_once_with('ioc')

    @patch('application.controllers.anomali.DynamoDBService')
    def test_add_record_to_db(self, mock_dynamo):
        mock_instance = mock_dynamo.return_value
        Anomali.add_record_to_db(80, 'IPv4', 'ioc')
        mock_instance.put_item.assert_called()

    @patch('application.controllers.anomali.DynamoDBService')
    def test_lookup_record_to_db(self, mock_dynamo):
        mock_instance = mock_dynamo.return_value
        mock_instance.get_item.return_value = {'foo': 'bar'}
        result = Anomali.lookup_record_to_db('ioc', 'Anomali')
        mock_instance.get_item.assert_called()
        self.assertEqual(result, {'foo': 'bar'})

    @patch('application.controllers.anomali.SSMServices')
    def test_generate_headers(self, mock_ssm):
        mock_instance = mock_ssm.return_value
        mock_instance.get_param.side_effect = ['user', 'key']
        result = Anomali.generate_headers()
        self.assertIn('Authorization', result)
        self.assertTrue(result['Authorization'].startswith('apikey '))

    @patch('application.controllers.anomali.SSMServices')
    def test_generate_headers_empty(self, mock_ssm):
        mock_instance = mock_ssm.return_value
        mock_instance.get_param.side_effect = [None, None]
        result = Anomali.generate_headers()
        self.assertEqual(result, {})

    def test_ioc_type_finder(self):
        self.assertEqual(Anomali.ioc_type_finder('a'*64), 'SHA256')
        self.assertEqual(Anomali.ioc_type_finder('b'*32), 'MD5')
        self.assertEqual(Anomali.ioc_type_finder('c'*40), 'SHA1')
        self.assertEqual(Anomali.ioc_type_finder('8.8.8.8'), 'IPv4')
        self.assertEqual(Anomali.ioc_type_finder('example.com'), 'Domain')
        self.assertEqual(Anomali.ioc_type_finder('weirdinput'), 'Domain')

    def test_grade_confidence(self):
        self.assertEqual(Anomali.grade_confidence(10), 'Low')
        self.assertEqual(Anomali.grade_confidence(50), 'Medium')
        self.assertEqual(Anomali.grade_confidence(90), 'High')

    def test_is_private_ip(self):
        self.assertTrue(Anomali.is_private_ip('10.0.0.1'))
        self.assertFalse(Anomali.is_private_ip('8.8.8.8'))

if __name__ == '__main__':
    unittest.main()
