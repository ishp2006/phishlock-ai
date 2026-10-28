import json
import socket
import unittest
from unittest.mock import patch

import app as app_module

# Change these two if app.py expects different JSON keys
URL_FIELD = "url"
MESSAGE_FIELD = "message"

if hasattr(app_module, "app"):
    flask_app = app_module.app
elif hasattr(app_module, "create_app"):
    flask_app = app_module.create_app()
else:
    raise ImportError("app.py mein 'app' ya 'create_app' nahi mila")

flask_app.config["TESTING"] = True


def block_network(*args, **kwargs):
    raise RuntimeError("Network call blocked in tests")


class PhishLockApiTests(unittest.TestCase):
    def setUp(self):
        self.client = flask_app.test_client()
        self.patches = [
            patch("socket.socket.connect", side_effect=block_network),
            patch("socket.getaddrinfo", side_effect=block_network),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def require_route(self, path, method):
        for rule in flask_app.url_map.iter_rules():
            if rule.rule == path and method in rule.methods:
                return
        self.skipTest(f"{method} {path} app.py mein implemented nahi hai")

    def post_json(self, path, payload):
        return self.client.post(path, json=payload)

    def assert_json(self, response):
        self.assertIn("application/json", response.content_type)
        data = json.loads(response.get_data(as_text=True))
        self.assertIsInstance(data, (dict, list))
        return data

    def test_health(self):
        self.require_route("/api/health", "GET")
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = self.assert_json(response)
        print("\nhealth response:", data)

    def test_analyze_url(self):
        self.require_route("/api/analyze-url", "POST")
        response = self.post_json("/api/analyze-url", {URL_FIELD: "https://example.com"})
        self.assertEqual(response.status_code, 200)
        data = self.assert_json(response)
        print("\nanalyze-url response:", data)

    def test_analyze_message(self):
        self.require_route("/api/analyze-message", "POST")
        response = self.post_json(
            "/api/analyze-message", {MESSAGE_FIELD: "Hi, meeting kal 10 baje hai."}
        )
        self.assertEqual(response.status_code, 200)
        data = self.assert_json(response)
        print("\nanalyze-message response:", data)

    def test_analyze_url_empty_body(self):
        self.require_route("/api/analyze-url", "POST")
        response = self.post_json("/api/analyze-url", {})
        self.assertLess(response.status_code, 500)
        print("\nanalyze-url empty body status:", response.status_code)

    def test_analyze_message_empty_body(self):
        self.require_route("/api/analyze-message", "POST")
        response = self.post_json("/api/analyze-message", {})
        self.assertLess(response.status_code, 500)
        print("\nanalyze-message empty body status:", response.status_code)

    def test_invalid_json_does_not_crash(self):
        self.require_route("/api/analyze-url", "POST")
        response = self.client.post(
            "/api/analyze-url", data="not json", content_type="application/json"
        )
        self.assertLess(response.status_code, 500)


if __name__ == "__main__":
    unittest.main()