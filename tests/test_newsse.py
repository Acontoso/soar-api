import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from application.services.newsse import SSEServices, obfuscateApiKey
from flask import Flask
from requests import RequestException

class TestSSEServices(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    @patch('application.services.newsse.requests.post', side_effect=RequestException('fail'))
    @patch('application.services.newsse.current_app')
    def test_sandbox_file_failure(self, mock_post, mock_app):
        mock_app.logger = MagicMock()
        mock_app.logger.info = AsyncMock()
        mock_app.logger.error = AsyncMock()
        result = SSEServices.sandbox_file(b'data', 'key')
        self.assertIsNone(result)

    @patch('application.services.newsse.requests.post')
    @patch('application.services.newsse.current_app')
    def test_sandbox_file_success(self, mock_app, mock_post):
        mock_app.logger = MagicMock()
        mock_app.logger.info = AsyncMock()
        mock_app.logger.error = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {'result': 'ok'}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        result = SSEServices.sandbox_file(b'data', 'key')
        self.assertEqual(result, {'result': 'ok'})

    @patch('application.services.newsse.requests.post', side_effect=RequestException('fail'))
    @patch('application.services.newsse.current_app')
    def test_lookup_url_category_failure(self, mock_post, mock_app):
        mock_app.logger = MagicMock()
        mock_app.logger.info = AsyncMock()
        mock_app.logger.error = AsyncMock()
        result = SSEServices.lookup_url_category('http://test.com')
        self.assertIsNone(result)

    @patch('application.services.newsse.requests.post')
    @patch('application.services.newsse.current_app')
    def test_lookup_url_category_success(self, mock_app, mock_post):
        mock_app.logger = MagicMock()
        mock_app.logger.info = AsyncMock()
        mock_app.logger.error = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {'category': 'news'}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        with patch.object(SSEServices, 'get_jsession', return_value='jsessionid'):
            result = SSEServices.lookup_url_category('http://test.com')
            self.assertEqual(result, {'category': 'news'})

    @patch('application.services.newsse.SSMServices.get_param', return_value='api_key')
    @patch('application.services.newsse.current_app')
    @patch('application.services.newsse.requests.post', side_effect=RequestException('fail'))
    def test_get_jsession_failure(self, mock_get_param, mock_app, mock_post):
        mock_app.logger = MagicMock()
        mock_app.logger.info = AsyncMock()
        mock_app.logger.error = AsyncMock()
        result = SSEServices.get_jsession()
        self.assertEqual(result, '')

    @patch('application.services.newsse.SSMServices.get_param', side_effect=['api_key', 'user', 'pass'])
    @patch('application.services.newsse.current_app')
    @patch('application.services.newsse.requests.post')
    def test_get_jsession_success(self, mock_post, mock_app, mock_get_param):
        mock_app.logger = MagicMock()
        mock_app.logger.info = AsyncMock()
        mock_app.logger.error = AsyncMock()
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {'JSESSIONID': 'jsessionid123'}
        mock_post.return_value = mock_response
        with patch('application.services.newsse.obfuscateApiKey', return_value=('obfkey', 1234567890)):
            result = SSEServices.get_jsession()
            self.assertEqual(result, 'jsessionid123')

    @patch('application.services.newsse.SSMServices.get_param', return_value='sandbox_key')
    def test_sandbox_api_key(self, mock_get_param):
        result = SSEServices.sandbox_api_key()
        self.assertEqual(result, 'sandbox_key')

    @patch('application.services.newsse.SSMServices.get_param', return_value=None)
    def test_sandbox_api_key_none(self, mock_get_param):
        result = SSEServices.sandbox_api_key()
        self.assertEqual(result, '')

    def test_obfuscate_api_key(self):
        api_key = '1234567890123456789012345678901234567890'
        key, now = obfuscateApiKey(api_key)
        self.assertIsInstance(key, str)
        self.assertIsInstance(now, int)
        self.assertTrue(len(key) > 0)

if __name__ == '__main__':
    unittest.main()
