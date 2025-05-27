import unittest
from unittest.mock import patch, MagicMock
from flask import Flask, Request
from application.middleware import authen

class TestAuthen(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.ctx = self.app.app_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch("application.middleware.authen.current_app")
    @patch("application.middleware.authen.requests.get")
    def test_get_jwk_success(self, mock_requests_get, mock_current_app):
        mock_requests_get.return_value.status_code = 200
        mock_requests_get.return_value.json.return_value = {
            "keys": [{"kid": "abc", "kty": "RSA", "n": "foo", "e": "bar"}]
        }
        key = authen.get_jwk("abc")
        self.assertEqual(key["kid"], "abc")

    @patch("application.middleware.authen.requests.get")
    def test_get_jwk_not_found(self, mock_requests_get):
        mock_requests_get.return_value.status_code = 200
        mock_requests_get.return_value.json.return_value = {"keys": []}
        with self.assertRaises(ValueError):
            authen.get_jwk("notfound")

    @patch("application.middleware.authen.current_app")
    @patch("application.middleware.authen.jwt.get_unverified_header")
    @patch("application.middleware.authen.get_jwk")
    @patch("application.middleware.authen.jwt.algorithms.RSAAlgorithm.from_jwk")
    @patch("application.middleware.authen.jwt.decode")
    def test_verify_jwt_success(self, mock_jwt_decode, mock_from_jwk, mock_get_jwk, mock_get_unverified_header, mock_current_app):
        mock_get_unverified_header.return_value = {"kid": "abc"}
        mock_get_jwk.return_value = {"kty": "RSA", "kid": "abc"}
        mock_from_jwk.return_value = "public_key"
        mock_jwt_decode.return_value = {"client_id": "cid", "scope": "soar-api/admin.readwrite.all"}
        req = MagicMock(spec=Request)
        req.headers = {"Authorization": "Bearer sometoken"}
        result = authen.verify_jwt(req)
        self.assertIsNone(result)  # Should not return a response on success
        mock_current_app.logger.info.assert_any_call("[+] Authorization token is valid, proceeding with request")

    @patch("application.middleware.authen.current_app")
    def test_verify_jwt_missing_token(self, mock_current_app):
        #Creates a fake Flask request object that allows real flask request attributes and methods to be tested.
        req = MagicMock(spec=Request)
        req.headers = {}  # No Authorization header
        response = authen.verify_jwt(req)
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"JWT token is missing or invalid", response.data)
        mock_current_app.logger.error.assert_any_call("[-] Authorization token is missing")

    @patch("application.middleware.authen.current_app")
    @patch("application.middleware.authen.jwt.get_unverified_header")
    def test_verify_jwt_invalid_header(self, mock_get_unverified_header, mock_current_app):
        mock_get_unverified_header.return_value = None
        req = MagicMock(spec=Request)
        req.headers = {"Authorization": "Bearer sometoken"}
        response = authen.verify_jwt(req)
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"JWT token is missing or invalid", response.data)

    def test_verify_scopes(self):
        token = {"scope": "a b c"}
        self.assertTrue(authen.verify_scopes(token, ["a"]))
        self.assertFalse(authen.verify_scopes(token, ["x"]))

if __name__ == "__main__":
    unittest.main()
