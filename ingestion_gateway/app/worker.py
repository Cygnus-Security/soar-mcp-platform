import os
import traceback
from datetime import datetime, timezone

from app.envelope import RawEventEnvelope
from app.kafka_io import consumer, producer
from app.normalizer import normalize
from app.settings import DLQ_TOPIC, NORMALIZED_TOPIC, RAW_TOPIC


def main():
    input_stream = consumer(RAW_TOPIC, os.getenv("NORMALIZER_CONSUMER_GROUP", "soar-normalizer-v1"))
    output = producer()
    for message in input_stream:
        try:
            envelope = RawEventEnvelope.model_validate(message.value)
            events = normalize(envelope)
            for event in events:
                output.send(NORMALIZED_TOPIC, key=f"{event['tenant_id']}:{event.get('source_ip') or event['event_id']}", value=event).get(timeout=10)
            input_stream.commit()
        except Exception as error:
            dlq = {
                "schema_version": "1.0",
                "source": "raw_normalizer",
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "error": str(error),
                "trace": traceback.format_exc(limit=3),
                "payload": message.value,
            }
            output.send(DLQ_TOPIC, key=message.key or "raw_normalizer", value=dlq).get(timeout=10)
            input_stream.commit()


if __name__ == "__main__":
    main()
