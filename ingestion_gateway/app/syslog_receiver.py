import asyncio
import os

from app.envelope import RawEventEnvelope
from app.kafka_io import producer
from app.settings import RAW_TOPIC, TENANT_ID


HOST = os.getenv("SYSLOG_HOST", "0.0.0.0")
PORT = int(os.getenv("SYSLOG_PORT", "5514"))
SOURCE_PRODUCT = os.getenv("SYSLOG_SOURCE_PRODUCT", "generic_syslog")
_producer = None


def publish(data: bytes, peer):
    message = data.decode("utf-8", errors="replace").strip()
    if not message:
        return
    envelope = RawEventEnvelope(
        tenant_id=TENANT_ID,
        source_product=SOURCE_PRODUCT,
        ingestion_mode="realtime",
        content_type="text/plain",
        connector_id=f"syslog:{peer[0] if peer else 'unknown'}",
        payload={"message": message, "sender": peer[0] if peer else None},
    )
    _producer.send(RAW_TOPIC, key=envelope.kafka_key(), value=envelope.model_dump()).get(timeout=10)


class SyslogDatagram(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        try:
            publish(data, addr)
        except Exception as error:
            print(f"[SYSLOG UDP] {error}")


async def tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        while line := await reader.readline():
            publish(line, peer)
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    global _producer
    _producer = producer()
    loop = asyncio.get_running_loop()
    udp_transport, _ = await loop.create_datagram_endpoint(SyslogDatagram, local_addr=(HOST, PORT))
    tcp_server = await asyncio.start_server(tcp_client, HOST, PORT)
    print(f"Syslog TCP/UDP listening on {HOST}:{PORT}")
    try:
        async with tcp_server:
            await tcp_server.serve_forever()
    finally:
        udp_transport.close()


if __name__ == "__main__":
    asyncio.run(main())
