import unittest
from unittest.mock import patch, MagicMock
from flask import Flask, g
from application.routes.route import init_routes

class TestRoutes(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.client = self.app.test_client()
        init_routes(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        g.token = {"scope": "soar-api/admin.readwrite.all"}

    def tearDown(self):
        self.ctx.pop()

    @patch("application.routes.route.IPAbuseDB")
    @patch("application.routes.route.verify_scopes", return_value=True)
    def test_ipabuse_path_success(self, mock_verify, mock_ipabusedb):
        mock_ipabusedb.ip_lookup.return_value = {"result": "ok"}
        response = self.client.get("/ipabusedb?ip=1.2.3.4")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ok", response.data)

    @patch("application.routes.route.IPAbuseDB")
    @patch("application.routes.route.verify_scopes", return_value=True)
    def test_ipabuse_path_missing_param(self, mock_verify, mock_ipabusedb):
        response = self.client.get("/ipabusedb")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Missing ip uri param", response.data)

    @patch("application.routes.route.IPAbuseDB")
    @patch("application.routes.route.verify_scopes", return_value=True)
    def test_ipabuse_path_upstream_error(self, mock_verify, mock_ipabusedb):
        mock_ipabusedb.ip_lookup.return_value = None
        response = self.client.get("/ipabusedb?ip=1.2.3.4")
        self.assertEqual(response.status_code, 500)
        self.assertIn(b"Upstream API issue", response.data)

    @patch("application.routes.route.verify_scopes", return_value=False)
    def test_ipabuse_path_unauthorized(self, mock_verify):
        response = self.client.get("/ipabusedb?ip=1.2.3.4")
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Missing required scopes", response.data)

if __name__ == "__main__":
    unittest.main()
