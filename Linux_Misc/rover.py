#!/usr/bin/env python3

import base64
import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone

import requests

OO_BASE = os.environ.get("OO_BASE", "http://127.0.0.1").rstrip("/")
OO_ORG = os.environ.get("OO_ORG", "default")
OO_EMAIL = os.environ.get("OO_EMAIL", "admin@example.com")
OO_PASS = os.environ.get("OO_PASS", "0f4c667f-9819-44e3-8f27-88ec0df4a1d5")
OO_AUTH_MODE = os.environ.get("OO_AUTH_MODE", "basic").strip().lower()

SPLUNK_HEC = os.environ.get(
    "SPLUNK_HEC", "http://127.0.0.1:8088/services/collector"
).rstrip("/")
SPLUNK_HEC_TOKEN = os.environ.get(
    "SPLUNK_HEC_TOKEN", "0f4c667f-9819-44e3-8f27-88ec0df4a1d5"
)
SPLUNK_INDEX = os.environ.get("SPLUNK_INDEX", "main")

SAMPLE_PERCENT = int(os.environ.get("SAMPLE_PERCENT", "100"))
TIME_WINDOW_HOURS = int(os.environ.get("TIME_WINDOW_HOURS", "48"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "1000"))
REQUEST_TIMEOUT_SECS = int(os.environ.get("REQUEST_TIMEOUT_SECS", "30"))
MAX_PAGES_PER_STREAM = int(os.environ.get("MAX_PAGES_PER_STREAM", "1000"))

STATE_FILE = "checkpoint.json"


def deterministic_event_id(event: dict) -> str:
    normalized = json.dumps(event, sort_keys=True)
    return hashlib.sha256(normalized.encode()).hexdigest()


def should_sample_event(event_id: str, percent: int) -> bool:
    if percent <= 0:
        return False
    if percent >= 100:
        return True
    bucket = int(event_id[:8], 16) % 100
    return bucket < percent


def ts_to_splunk_epoch_seconds(ts: int | float | None) -> float:
    if ts is None:
        return float(time.time())
    try:
        ts = float(ts)
    except Exception:
        return float(time.time())

    if ts >= 1e15:
        return ts / 1e6
    if ts >= 1e12:
        return ts / 1e3
    return ts


def load_checkpoint():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_checkpoint(data):
    with open(STATE_FILE, "w") as f:
        json.dump(data, f)


def oo_login_token():
    url = f"{OO_BASE}/auth/login"

    body = {"email": OO_EMAIL, "password": OO_PASS}

    r = requests.post(url, json=body, timeout=REQUEST_TIMEOUT_SECS)
    r.raise_for_status()

    token = r.json().get("access_token")
    if not token:
        raise Exception("Failed to retrieve OpenObserve token")

    return token


def oo_auth_headers():
    if OO_AUTH_MODE == "login":
        token = oo_login_token()
        return {"Authorization": f"Bearer {token}"}

    if OO_AUTH_MODE != "basic":
        raise Exception(
            f"Unsupported OO_AUTH_MODE={OO_AUTH_MODE!r} (expected 'basic' or 'login')"
        )

    raw = f"{OO_EMAIL}:{OO_PASS}".encode()
    b64 = base64.b64encode(raw).decode()
    return {"Authorization": f"Basic {b64}"}


def get_streams(headers):
    url = f"{OO_BASE}/api/{OO_ORG}/streams?type=logs"

    r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECS)
    r.raise_for_status()

    return r.json().get("list", [])


def query_stream_sql(
    stream_name: str, start_us: int, end_us: int, offset: int, headers
):
    url = f"{OO_BASE}/api/{OO_ORG}/_search"

    esc_stream = stream_name.replace('"', '""')
    sql = f'SELECT * FROM "{esc_stream}" ORDER BY _timestamp ASC'

    body = {
        "query": {
            "sql": sql,
            "start_time": int(start_us),
            "end_time": int(end_us),
            "from": int(offset),
            "size": int(BATCH_SIZE),
        },
        "search_type": "ui",
        "timeout": 0,
    }

    req_headers = dict(headers)
    req_headers["Content-Type"] = "application/json"

    r = requests.post(url, json=body, headers=req_headers, timeout=REQUEST_TIMEOUT_SECS)
    r.raise_for_status()

    return r.json().get("hits", [])


def send_to_splunk(stream_name, events):
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json",
    }

    payload_lines = []

    for event in events:
        event_id = deterministic_event_id(event)

        payload = {
            "index": SPLUNK_INDEX,
            "sourcetype": stream_name,
            "event": event,
            "time": ts_to_splunk_epoch_seconds(event.get("_timestamp")),
            "fields": {
                "openobserve_event_id": event_id,
                "source_system": "openobserve",
            },
        }

        payload_lines.append(json.dumps(payload))

    if not payload_lines:
        return True

    r = requests.post(
        SPLUNK_HEC,
        headers=headers,
        data="\n".join(payload_lines),
        timeout=REQUEST_TIMEOUT_SECS,
    )

    if r.status_code != 200:
        print(f"[!] Splunk error: {r.status_code} {r.text}")
        return False
    else:
        print(f"[+] Sent {len(payload_lines)} events to Splunk")
        return True


def main():
    print("[+] Preparing OpenObserve auth...")
    oo_headers = oo_auth_headers()

    checkpoint = load_checkpoint()

    start_time = datetime.now(timezone.utc) - timedelta(hours=TIME_WINDOW_HOURS)
    start_us = int(start_time.timestamp() * 1_000_000)
    end_us = int(datetime.now(timezone.utc).timestamp() * 1_000_000)

    print(f"[+] Pulling logs since {start_time.isoformat()}")
    print(f"[+] Sampling at {SAMPLE_PERCENT}%")

    streams = get_streams(oo_headers)

    for stream in streams:
        stream_name = stream["name"]
        print(f"\n[+] Processing stream: {stream_name}")

        last_ts = int(checkpoint.get(stream_name, start_us))
        query_start_us = last_ts + 1

        total_retrieved = 0
        total_sampled = 0
        max_ts_seen = last_ts

        for page in range(MAX_PAGES_PER_STREAM):
            offset = page * BATCH_SIZE
            try:
                events = query_stream_sql(
                    stream_name, query_start_us, end_us, offset, oo_headers
                )
            except Exception as e:
                print(f"    [!] Failed querying stream: {e}")
                break

            if not events:
                break

            total_retrieved += len(events)

            sampled = []
            for event in events:
                ts = event.get("_timestamp", 0) or 0
                if ts > max_ts_seen:
                    max_ts_seen = ts

                event_id = deterministic_event_id(event)
                if should_sample_event(event_id, SAMPLE_PERCENT):
                    sampled.append(event)

            total_sampled += len(sampled)

            ok = send_to_splunk(stream_name, sampled)
            if not ok:
                max_ts_seen = last_ts
                break

            if len(events) < BATCH_SIZE:
                break

        print(f"    Retrieved: {total_retrieved} events")
        print(f"    Sampled:   {total_sampled} events")

        if max_ts_seen > last_ts:
            checkpoint[stream_name] = int(max_ts_seen)

    save_checkpoint(checkpoint)
    print("\n[+] Done")


if __name__ == "__main__":
    main()
