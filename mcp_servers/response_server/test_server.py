import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import requests

import server


class AdapterLoggingTest(unittest.TestCase):
    def setUp(self):
        self.context = {
            "action_id": "action-1",
            "incident_id": 42,
            "action_type": "temporary_ip_block",
            "target": "10.229.0.4",
            "approval_token": "must-not-leave-response-server",
        }

    def test_success_logs_gateway_result_without_forwarding_approval_token(self):
        response = Mock()
        response.status_code = 200
        response.text = '{"status":"EXECUTED","message":"rule installed"}'
        response.json.return_value = {"status": "EXECUTED", "message": "rule installed"}
        response.raise_for_status.return_value = None

        output = io.StringIO()
        with (
            patch.object(server, "EXECUTION_MODE", "live"),
            patch.object(server, "ACTION_WEBHOOK_URL", "http://gateway:9000/v1/actions"),
            patch.object(server.requests, "post", return_value=response) as post,
            redirect_stdout(output),
        ):
            result = server._execute_adapter(
                "action-1", "temporary_ip_block", "10.229.0.4", self.context
            )

        self.assertEqual("EXECUTED", result["status"])
        self.assertEqual("rule installed", result["message"])
        forwarded_context = post.call_args.kwargs["json"]["context"]
        self.assertNotIn("approval_token", forwarded_context)
        logs = output.getvalue()
        self.assertIn('"event":"gateway_request_started"', logs)
        self.assertIn('"event":"gateway_response_received"', logs)
        self.assertNotIn("must-not-leave-response-server", logs)

    def test_http_error_includes_safe_gateway_response(self):
        response = Mock()
        response.status_code = 400
        response.text = '{"error":"target_not_allowed_in_lab"}'
        response.raise_for_status.side_effect = requests.HTTPError(
            "400 Client Error", response=response
        )

        with (
            patch.object(server, "EXECUTION_MODE", "live"),
            patch.object(server, "ACTION_WEBHOOK_URL", "http://gateway:9000/v1/actions"),
            patch.object(server.requests, "post", return_value=response),
        ):
            result = server._execute_adapter(
                "action-1", "temporary_ip_block", "8.8.8.8", self.context
            )

        self.assertEqual("FAILED", result["status"])
        self.assertIn("HTTP 400", result["message"])
        self.assertIn("target_not_allowed_in_lab", result["message"])


if __name__ == "__main__":
    unittest.main()
