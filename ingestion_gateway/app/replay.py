import argparse
import json
import os

import requests


def main():
    parser = argparse.ArgumentParser(description="Replay an existing security log through the SOAR ingestion gateway")
    parser.add_argument("--input", required=True)
    parser.add_argument("--source", required=True, choices=["wazuh", "suricata", "snort", "zeek", "web", "nginx", "apache", "auth", "auditd", "firewall", "generic_syslog"])
    parser.add_argument("--tenant", default=os.getenv("SOAR_TENANT_ID", "lab"))
    parser.add_argument("--mode", default="immediate", choices=["immediate", "original", "accelerated"])
    parser.add_argument("--speed", type=float, default=10.0)
    parser.add_argument("--dataset-id")
    parser.add_argument("--gateway", default=os.getenv("INGESTION_GATEWAY_URL", "http://ingestion_gateway:8080"))
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()

    params = {
        "source_product": args.source,
        "tenant_id": args.tenant,
        "mode": args.mode,
        "speed": args.speed,
        "resume": str(not args.no_resume).lower(),
    }
    if args.dataset_id:
        params["dataset_id"] = args.dataset_id
    headers = {}
    if token := os.getenv("INGESTION_API_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    with open(args.input, "rb") as stream:
        response = requests.post(
            f"{args.gateway.rstrip('/')}/v1/files",
            params=params,
            headers=headers,
            files={"file": (os.path.basename(args.input), stream)},
            timeout=None,
        )
    response.raise_for_status()
    print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
