import asyncio
import os
import unittest
from unittest.mock import patch

from app.kafka_bridge import bounded_int_env
from app.orchestrator import SOAROrchestrator


class FakeKafkaBridge:
    def __init__(self, events):
        self.events = events
        self.committed = False

    def poll_approved_actions(self):
        return [
            {"action_id": "action-1"},
            {"action_id": "action-2"},
            {"action_id": "action-3"},
        ]

    def publish_action_result(self, request, result):
        self.events.append(("publish", request["action_id"]))

    def commit_actions(self):
        self.committed = True


class FakeResponseEngine:
    def __init__(self, events):
        self.events = events
        self.in_flight = 0
        self.max_in_flight = 0

    async def execute_approved_action(self, request):
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        self.events.append(("start", request["action_id"]))
        await asyncio.sleep(0)
        self.events.append(("finish", request["action_id"]))
        self.in_flight -= 1
        return {"status": "DRY_RUN"}


class ApprovedActionProcessingTest(unittest.IsolatedAsyncioTestCase):
    def test_batch_size_is_clamped_to_safe_range(self):
        with patch.dict(os.environ, {"SOAR_ACTION_BATCH_SIZE": "500"}):
            self.assertEqual(100, bounded_int_env("SOAR_ACTION_BATCH_SIZE", 50, 1, 100))
        with patch.dict(os.environ, {"SOAR_ACTION_BATCH_SIZE": "0"}):
            self.assertEqual(1, bounded_int_env("SOAR_ACTION_BATCH_SIZE", 50, 1, 100))
        with patch.dict(os.environ, {"SOAR_ACTION_BATCH_SIZE": "invalid"}):
            self.assertEqual(50, bounded_int_env("SOAR_ACTION_BATCH_SIZE", 50, 1, 100))

    async def test_actions_are_executed_and_published_sequentially(self):
        events = []
        orchestrator = SOAROrchestrator.__new__(SOAROrchestrator)
        orchestrator.kafka_bridge = FakeKafkaBridge(events)
        orchestrator.response_engine = FakeResponseEngine(events)
        orchestrator.action_delay_seconds = 0

        processed = await orchestrator.process_approved_actions()

        self.assertEqual(3, processed)
        self.assertEqual(1, orchestrator.response_engine.max_in_flight)
        self.assertTrue(orchestrator.kafka_bridge.committed)
        self.assertEqual(
            [
                ("start", "action-1"), ("finish", "action-1"), ("publish", "action-1"),
                ("start", "action-2"), ("finish", "action-2"), ("publish", "action-2"),
                ("start", "action-3"), ("finish", "action-3"), ("publish", "action-3"),
            ],
            events,
        )


if __name__ == "__main__":
    unittest.main()
