import unittest

from app.envelope import RawEventEnvelope
from app.normalizer import normalize
from app.file_reader import records


class NormalizerTest(unittest.TestCase):
    def test_suricata_event_maps_to_security_event_v1(self):
        envelope = RawEventEnvelope(
            tenant_id="lab",
            source_product="suricata",
            ingestion_mode="realtime",
            payload={
                "timestamp": "2026-10-08T08:00:00Z",
                "flow_id": 123,
                "event_type": "alert",
                "src_ip": "192.0.2.10",
                "dest_ip": "192.0.2.20",
                "alert": {"signature_id": 1001, "signature": "SQL injection attempt", "severity": 1},
            },
        )
        event = normalize(envelope)[0]
        self.assertEqual("1.0", event["schema_version"])
        self.assertEqual("ids", event["source_type"])
        self.assertEqual("192.0.2.10", event["source_ip"])
        self.assertGreaterEqual(event["severity"], 90)
        self.assertEqual(64, len(event["event_id"]))

    def test_existing_web_log_uses_same_detection_rules(self):
        envelope = RawEventEnvelope(
            tenant_id="dataset",
            source_product="nginx",
            ingestion_mode="replay",
            source_file="access.log",
            source_offset=7,
            payload={"message": '192.0.2.8 - - [08/Oct/2026:08:00:00 +0700] "GET /?id=1+OR+1=1 HTTP/1.1"'},
        )
        event = normalize(envelope)[0]
        self.assertEqual("sql_injection", event["event_type"])
        self.assertEqual("replay", event["metadata"]["ingestion_mode"])
        self.assertEqual("raw:" + envelope.ingestion_id + ":7", event["raw_reference"])

    def test_event_id_is_deterministic_for_same_source_record(self):
        arguments = dict(
            tenant_id="lab", source_product="zeek", ingestion_mode="replay",
            source_file="conn.log", source_offset=2,
            payload={"ts": 1700000000.0, "uid": "C1", "id.orig_h": "192.0.2.1", "id.resp_h": "192.0.2.2"},
        )
        first = normalize(RawEventEnvelope(**arguments))[0]
        second = normalize(RawEventEnvelope(**arguments))[0]
        self.assertEqual(first["event_id"], second["event_id"])

    def test_native_zeek_tsv_is_parsed(self):
        content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.resp_h\n"
            "1700000000.0\tC1\t192.0.2.1\t192.0.2.2\n"
        ).encode()
        parsed = list(records(content, "conn.log", "zeek"))
        self.assertEqual(1, len(parsed))
        self.assertEqual("192.0.2.1", parsed[0][1]["id.orig_h"])


if __name__ == "__main__":
    unittest.main()
