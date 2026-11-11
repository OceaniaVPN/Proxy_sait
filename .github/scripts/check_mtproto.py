#!/usr/bin/env python3
"""Build a per-link MTProto health snapshot using a real Telegram protocol check."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MAX_SOURCE_BYTES = 512 * 1024
MAX_RESULTS = 12000
WORKERS = 12
CHECK_TIMEOUT = "6s"
PROCESS_TIMEOUT_SECONDS = 9

SOURCES = [
    ("own-public", "https://raw.githubusercontent.com/OceaniaVPN/Proxy_sait/main/public/proxies.txt"),
    ("own-data", "https://raw.githubusercontent.com/OceaniaVPN/Proxy_sait/main/data/proxies.txt"),
    ("iwizard-working", "https://iwizard7.github.io/MTProxy_list/working.txt"),
    ("iwizard-stable", "https://iwizard7.github.io/MTProxy_list/stable.txt"),
    ("iwizard-all", "https://iwizard7.github.io/MTProxy_list/all.txt"),
    ("radikal-fast", "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/fast/tg.txt"),
    ("radikal-stable", "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/stable/tg.txt"),
    ("radikal-resilient-tg", "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/resilient/tg.txt"),
    ("radikal-resilient-tme", "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/resilient/tme.txt"),
    ("radikal-top100", "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/top100.txt"),
    ("solispirit-all", "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt"),
]

LINK_RE = re.compile(
    r"(?:tg://proxy\?[^\s\"'<>]+|https?://t\.me/proxy\?[^\s\"'<>]+)",
    re.IGNORECASE,
)
PING_RE = re.compile(r"(?:ping|пинг)\s*[:=]?\s*([0-9]+(?:\.[0-9]+)?)\s*ms", re.IGNORECASE)


def fetch_source(name: str, url: str) -> tuple[str, str | None]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "text/plain", "User-Agent": "ProxySait-MTProto-Health/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = response.read(MAX_SOURCE_BYTES + 1)
            if len(payload) > MAX_SOURCE_BYTES:
                raise ValueError("source_too_large")
            return payload.decode("utf-8", errors="replace"), None
    except Exception as exc:
        return "", f"{name}:{type(exc).__name__}"


def parse_mtproto_links(feed: str) -> list[tuple[str, tuple[str, int, str]]]:
    unique: dict[tuple[str, int, str], str] = {}
    for raw_line in feed.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        for match in LINK_RE.findall(line):
            candidate = re.sub(r"[),.;\]}]+$", "", match)
            try:
                parsed = urllib.parse.urlsplit(candidate)
                query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                server = query.get("server", [""])[0].strip().lower()
                port = int(query.get("port", ["0"])[0])
                secret = query.get("secret", [""])[0]
                if not server or not (1 <= port <= 65535) or not secret:
                    continue
                identity = (server, port, secret)
                unique.setdefault(identity, candidate)
            except (ValueError, TypeError):
                continue
    return [(url, identity) for identity, url in unique.items()]


def check_one(item: tuple[str, tuple[str, int, str]], checker: str) -> dict:
    url, identity = item
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [checker, "check", "-timeout", CHECK_TIMEOUT, url],
            capture_output=True,
            text=True,
            timeout=PROCESS_TIMEOUT_SECONDS,
            check=False,
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        match = PING_RE.search(output)
        elapsed = max(1, round((time.monotonic() - started) * 1000))
        if proc.returncode == 0 and match:
            return {
                "url": url,
                "server": identity[0],
                "port": identity[1],
                "status": "online",
                "latencyMs": max(1, round(float(match.group(1)))),
                "checkedMs": elapsed,
                "errorCode": None,
            }
        error_code = "CHECK_FAILED"
        lower = output.lower()
        if "timeout" in lower or proc.returncode == 124:
            error_code = "TIMEOUT"
        elif "secret" in lower or "invalid" in lower:
            error_code = "INVALID_PROXY"
        return {
            "url": url,
            "server": identity[0],
            "port": identity[1],
            "status": "offline",
            "latencyMs": None,
            "checkedMs": elapsed,
            "errorCode": error_code,
        }
    except subprocess.TimeoutExpired:
        return {
            "url": url,
            "server": identity[0],
            "port": identity[1],
            "status": "offline",
            "latencyMs": None,
            "checkedMs": PROCESS_TIMEOUT_SECONDS * 1000,
            "errorCode": "TIMEOUT",
        }
    except Exception:
        return {
            "url": url,
            "server": identity[0],
            "port": identity[1],
            "status": "offline",
            "latencyMs": max(1, round((time.monotonic() - started) * 1000)),
            "errorCode": "CHECKER_ERROR",
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checker", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    started = time.monotonic()
    all_items: dict[tuple[str, int, str], tuple[str, tuple[str, int, str]]] = {}
    source_errors: list[str] = []
    loaded_sources = 0

    for name, url in SOURCES:
        feed, error = fetch_source(name, url)
        if error:
            source_errors.append(error)
            continue
        parsed = parse_mtproto_links(feed)
        if parsed:
            loaded_sources += 1
            for item in parsed:
                all_items.setdefault(item[1], item)

    if not all_items:
        raise RuntimeError("No MTProto proxy links were collected; refusing to publish an empty snapshot.")
    if len(all_items) > MAX_RESULTS:
        raise RuntimeError(f"Collected {len(all_items)} links, over the safety limit {MAX_RESULTS}.")

    items = list(all_items.values())
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(check_one, item, args.checker) for item in items]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda item: (item["status"] != "online", item["latencyMs"] or 10**9, item["server"], item["port"]))
    online = sum(item["status"] == "online" for item in results)
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    snapshot = {
        "version": 1,
        "checker": "imbecility/mtproxy-checker",
        "checkLevel": "MTProto handshake + HelpGetNearestDC",
        "checkedAt": checked_at,
        "durationMs": max(1, round((time.monotonic() - started) * 1000)),
        "sourceCount": loaded_sources,
        "sourceErrors": source_errors[:20],
        "discoveredLinks": len(items),
        "checkedCount": len(results),
        "workingCount": online,
        "failedCount": len(results) - online,
        "results": results,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(json.dumps({
        "discovered": len(items),
        "checked": len(results),
        "working": online,
        "failed": len(results) - online,
        "sources": loaded_sources,
        "durationMs": snapshot["durationMs"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"MTProto health build failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
