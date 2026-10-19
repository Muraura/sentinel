"""Generate a sample Grafana/Loki export: 4 hours of container logs from a fictional online shop on 2026-09-30 (UTC).

Writes data/sample/sample_logs.json (not committed: run this script to create it) in four line formats
(JSON, Python "LEVEL:logger:msg", multi-line tracebacks, logfmt). All names are fictional:

  orders-api     payment-gateway timeouts (each event logged twice: JSON + plain text) with a 10-line
                 traceback after every error, stock-reservation retries, coupon misses, orders shipped
  metrics-agent  a metrics collector failing to scrape one target, in logfmt

The log tests (tests/test_log_tools.py) are written against this file.
Fixed seed: every run produces identical data.
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SENTINEL_DIR = Path(__file__).resolve().parent.parent
OUT_FILE = SENTINEL_DIR / "data" / "sample" / "sample_logs.json"
START = datetime(2026, 9, 30, 5, 10, tzinfo=timezone.utc)
END = START + timedelta(hours=4)
rng = random.Random(7)

VM = "shop-vm-1"
API_CONTAINER = rng.randbytes(32).hex()
AGENT_CONTAINER = rng.randbytes(32).hex()
WAREHOUSES = ["WH-01", "WH-02", "WH-03", "WH-04"]
COUPONS = ["SPRING10", "WELCOME5", "FREESHIP", "BLACKFRI"]
SCRAPE_URL = "http://inventory-db-exporter:9187/metrics"

entries: list[dict] = []


def ns_of(t: datetime) -> int:
    return int(t.replace(microsecond=0).timestamp()) * 10**9 + t.microsecond * 1000


def add(t: datetime, line: str, service: str, level_label: str | None, step_ns: int = 0) -> None:
    api = service == "orders-api"
    container = API_CONTAINER if api else AGENT_CONTAINER
    fields = {
        "compose_project": "shop" if api else "monitoring",
        "compose_service": "orders" if api else "metrics-agent",
        "container_name": service,
        "environment": "production",
        "filename": f"/var/lib/docker/containers/{container}/{container}-json.log",
        "service_name": service,
        "vm": VM,
    }
    if level_label:
        fields["level"] = level_label
    entries.append({"line": line + "\n", "timestamp": str(ns_of(t) + step_ns),
                    "date": t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z", "fields": fields})


def api_event(t: datetime, level: str, message: str, traceback: list[str] | None = None) -> None:
    """orders-api writes every event twice (JSON formatter + default logging), then the traceback if any."""
    label = "WARN" if level == "WARNING" else level
    payload = {"asctime": t.strftime("%Y-%m-%d %H:%M:%S,") + f"{t.microsecond // 1000:03d}",
               "levelname": level, "name": "orders-api", "message": message,
               "app_name": "orders-api", "environment": "prod", "event_id": None}
    add(t, json.dumps(payload), "orders-api", label)
    add(t, f"{level}:orders-api:{message}", "orders-api", label, step_ns=30_000)
    for i, frame in enumerate(traceback or []):
        add(t, frame, "orders-api", "Error" if i >= len(traceback) - 2 else None, step_ns=40_000 + i * 20_000)


def timeout_traceback(app_frame: str, call: str) -> list[str]:
    requests = "/usr/local/lib/python3.12/site-packages/requests"
    return [
        "Traceback (most recent call last):",
        f'  File "/srv/shop/orders/{app_frame}',
        f"    {call}",
        f'  File "{requests}/sessions.py", line 637, in post',
        '    return self.request("POST", url, data=data, json=json, **kwargs)',
        f'  File "{requests}/sessions.py", line 589, in request',
        "    resp = self.send(prep, **send_kwargs)",
        '  File "/srv/shop/orders/payments/client.py", line 88, in _send',
        '    raise GatewayTimeoutError(f"{self.host} did not respond within {self.timeout}s")',
        "orders.payments.errors.GatewayTimeoutError: pay.example.com did not respond within 5s",
    ]


def random_time() -> datetime:
    """Busier in the morning peak (06:00-09:00) than at the edges of the window."""
    while True:
        t = START + timedelta(seconds=rng.uniform(0, (END - START).total_seconds()))
        if 6 <= t.hour < 9 or rng.random() < 0.4:
            return t


CHARGE_TRACE = timeout_traceback('payments/client.py", line 64, in charge',
                                 "response = self.session.post(url, json=payload, timeout=5)")
REFUND_TRACE = timeout_traceback('payments/refunds.py", line 31, in refund',
                                 "response = self.session.post(refund_url, json=body, timeout=5)")

# Counts are fixed so tests/test_log_tools.py can assert exact numbers.
for _ in range(198):
    api_event(random_time(), "ERROR", "Payment gateway request failed: read timeout", CHARGE_TRACE)
for _ in range(2):
    api_event(random_time(), "ERROR", "Refund request failed: read timeout", REFUND_TRACE)
for _ in range(250):
    api_event(random_time(), "WARNING", f"Stock reservation retry: {rng.choice(WAREHOUSES)} lock busy")
for _ in range(39):
    api_event(random_time(), "WARNING", f"Coupon code not found: {rng.choice(COUPONS)}")
for _ in range(168):
    api_event(random_time(), "INFO", f"Order ORD-{rng.randint(10000, 99999)} shipped from {rng.choice(WAREHOUSES)}")

# metrics-agent: one failed scrape every ~8.5s, then a summary and a flush after each batch of retries
t = START + timedelta(seconds=3)
agent_lines = 0
while agent_lines < 1686:
    for attempt in range(5):
        if agent_lines >= 1686:
            break
        add(t, f'ts={t.isoformat().replace("+00:00", "Z")} level=info msg="scrape failed" attempt={attempt} '
               f'target=inventory-db err="Get \\"{SCRAPE_URL}\\": dial tcp 172.18.0.9:9187: connect: '
               f'connection refused"', "metrics-agent", "info")
        agent_lines += 1
        t += timedelta(seconds=rng.uniform(5, 12))
    for line in ['msg="target marked down" target=inventory-db failures=5',
                 f'msg="flushed batch" samples={rng.randint(800, 1200)} duration_ms={rng.randint(20, 90)}']:
        if agent_lines >= 1686:
            break
        add(t, f'ts={t.isoformat().replace("+00:00", "Z")} level=info {line}', "metrics-agent", "info")
        agent_lines += 1

entries.sort(key=lambda e: int(e["timestamp"]))
OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
OUT_FILE.write_text(json.dumps(entries))
print(f"Wrote {len(entries)} log lines ({START:%H:%M}-{END:%H:%M} UTC on {START:%Y-%m-%d}) -> {OUT_FILE}")
