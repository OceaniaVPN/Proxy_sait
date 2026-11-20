#!/usr/bin/env python3
"""Build a static Telegram proxy catalog and mirror the Worker season setting."""
from __future__ import annotations

import concurrent.futures
import json
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
WORKER = "https://proxy-sait.novogodniysait.workers.dev"
SOURCES = [
    ("OceaniaVPN/Proxy_sait:public", "https://raw.githubusercontent.com/OceaniaVPN/Proxy_sait/main/public/proxies.txt"),
    ("OceaniaVPN/Proxy_sait:data", "https://raw.githubusercontent.com/OceaniaVPN/Proxy_sait/main/data/proxies.txt"),
    ("iwizard7:working", "https://iwizard7.github.io/MTProxy_list/working.txt"),
    ("iwizard7:stable", "https://iwizard7.github.io/MTProxy_list/stable.txt"),
    ("iwizard7:all", "https://iwizard7.github.io/MTProxy_list/all.txt"),
    ("0xRadikal:fast", "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/fast/tg.txt"),
    ("0xRadikal:stable", "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/stable/tg.txt"),
    ("0xRadikal:resilient-tg", "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/resilient/tg.txt"),
    ("0xRadikal:resilient-tme", "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/resilient/tme.txt"),
    ("0xRadikal:top100", "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/top100.txt"),
    ("SoliSpirit:all", "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt"),
]
LINK_RE = re.compile(r'(?:tg://(?:proxy|socks)\?[^\s"\'<>]+|https?://t\.me/(?:proxy|socks|webproxy)\?[^\s"\'<>]+|socks5://[^\s"\'<>]+)', re.I)

def fetch(url: str) -> str:
    import urllib.request
    request = urllib.request.Request(url, headers={"User-Agent": "StekloVPN-GitHub-Actions/1.0", "Accept": "text/plain"})
    with urllib.request.urlopen(request, timeout=18) as response:
        data = response.read(512 * 1024 + 1)
    if len(data) > 512 * 1024:
        raise RuntimeError("source exceeds 512 KiB")
    return data.decode("utf-8", errors="replace")

def parse_link(raw: str, source: str):
    raw = raw.rstrip("),.;]}")
    try:
        u = urlparse(raw)
        q = parse_qs(u.query)
        if u.scheme == "tg" and u.netloc.lower() in ("proxy", "socks"):
            kind = u.netloc.lower()
        elif u.scheme in ("http", "https") and u.hostname and u.hostname.lower() == "t.me" and u.path.lower() in ("/proxy", "/socks", "/webproxy"):
            kind = u.path.strip("/").lower()
        elif u.scheme == "socks5":
            kind = "socks5"
        else:
            return None
        server = (q.get("server", [u.hostname if kind == "socks5" else ""])[0] or "").strip()
        port_raw = q.get("port", [u.port or (443 if kind == "webproxy" else "")])[0]
        port = int(port_raw)
        secret = q.get("secret", [""])[0]
        if not server or len(server) > 253 or not 1 <= port <= 65535:
            return None
        if kind == "proxy" and not 16 <= len(secret) <= 512:
            return None
        protocol = "MTProto" if kind == "proxy" else ("WEB (TG)" if kind == "webproxy" else "SOCKS5 (TG)")
        return {"url": raw, "name": f"{server}:{port}", "protocol": protocol, "server": server, "port": port, "source": source}
    except (ValueError, TypeError):
        return None

def probe(item):
    start = time.monotonic()
    try:
        with socket.create_connection((item["server"], item["port"]), timeout=2.5):
            item["pingStatus"] = "online"
            item["latencyMs"] = max(1, round((time.monotonic() - start) * 1000))
    except OSError:
        item["pingStatus"] = "offline"
        item["latencyMs"] = None
    item["checkType"] = "tcp"
    return item

def main():
    PUBLIC.mkdir(parents=True, exist_ok=True)
    all_links, source_ok = {}, 0
    failures = []
    for name, url in SOURCES:
        try:
            feed = fetch(url)
            found = 0
            for line in feed.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                for raw in LINK_RE.findall(line):
                    item = parse_link(raw, name)
                    if item:
                        all_links.setdefault(item["url"], item)
                        found += 1
            if found:
                source_ok += 1
            else:
                failures.append(f"{name}: no valid links")
        except Exception as exc:
            failures.append(f"{name}: {exc}")
    if not all_links or not source_ok:
        raise RuntimeError("No proxy source produced valid links; keeping previous catalog")

    links = list(all_links.values())
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        checked = list(pool.map(probe, links))
    checked.sort(key=lambda x: (x["pingStatus"] != "online", x["latencyMs"] or 999999, x["name"].lower()))
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "version": 1,
        "generatedAt": now,
        "sourceCount": source_ok,
        "sourceFailures": failures,
        "count": len(checked),
        "onlineCount": sum(x["pingStatus"] == "online" for x in checked),
        "proxies": checked,
    }
    (PUBLIC / "proxies.json").write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    (PUBLIC / "proxies.txt").write_text("\n".join(x["url"] for x in checked) + "\n", encoding="utf-8")

    # Season is controlled in the Worker admin panel. Mirror that exact value into Pages.
    season_data = json.loads(fetch(WORKER + "/api/season"))
    season = season_data.get("season")
    if season not in {"spring", "summer", "autumn", "winter"}:
        raise RuntimeError("Worker returned an invalid season; refusing to overwrite season.json")
    season_payload = {"season": season, "updatedAt": season_data.get("updatedAt"), "syncedAt": now}
    (PUBLIC / "season.json").write_text(json.dumps(season_payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")

    print(f"Catalog: {len(checked)} links, {payload['onlineCount']} TCP-online, {source_ok}/{len(SOURCES)} sources.")
    print(f"Season mirrored from Worker: {season}")
    if failures:
        print("Source warnings: " + " | ".join(failures))

if __name__ == "__main__":
    main()
