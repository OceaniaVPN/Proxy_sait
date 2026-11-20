#!/usr/bin/env python3
"""Build the public Telegram proxy snapshot and mirror the Worker season setting."""
from __future__ import annotations

import concurrent.futures
import json
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "public"
WORKER = "https://proxy-sait.novogodniysait.workers.dev"
SOURCES = [
    ("Proxy_sait:public/proxies.txt", "https://raw.githubusercontent.com/OceaniaVPN/Proxy_sait/main/public/proxies.txt"),
    ("Proxy_sait:data/proxies.txt", "https://raw.githubusercontent.com/OceaniaVPN/Proxy_sait/main/data/proxies.txt"),
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
VALID_SEASONS = {"spring", "summer", "autumn", "winter"}

def get_text(url: str) -> str:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "ProxySait-GitHubActions/1.0", "Accept": "text/plain,application/json"})
    with urllib.request.urlopen(req, timeout=15) as response:
        data = response.read(512 * 1024 + 1)
    if len(data) > 512 * 1024:
        raise ValueError("feed exceeds 512 KiB")
    return data.decode("utf-8", errors="replace")

def extract_links(feed: str, source: str) -> list[dict]:
    found = {}
    for line in feed.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        for candidate in LINK_RE.findall(line):
            candidate = candidate.rstrip("),.;]}")
            try:
                parsed = urlparse(candidate)
                kind = ""
                if parsed.scheme == "tg" and parsed.netloc.lower() in ("proxy", "socks"):
                    kind = parsed.netloc.lower()
                elif parsed.scheme in ("http", "https") and parsed.hostname and parsed.hostname.lower() == "t.me" and parsed.path.lower() in ("/proxy", "/socks", "/webproxy"):
                    kind = parsed.path.strip("/").lower()
                elif parsed.scheme == "socks5":
                    kind = "socks5"
                if not kind:
                    continue
                query = parse_qs(parsed.query)
                server = (query.get("server", [parsed.hostname if kind == "socks5" else ""])[0] or "").strip()
                port_raw = query.get("port", [parsed.port or (443 if kind == "webproxy" else 0)])[0]
                port = int(port_raw)
                secret = query.get("secret", [""])[0]
                if not server or len(server) > 253 or not 1 <= port <= 65535:
                    continue
                if kind == "proxy" and not 16 <= len(secret) <= 512:
                    continue
                found[candidate] = {"url": candidate, "server": server, "port": port, "kind": kind, "source": source}
            except (ValueError, TypeError):
                continue
    return list(found.values())

def probe(item: dict) -> dict:
    started = time.monotonic()
    try:
        with socket.create_connection((item["server"], item["port"]), timeout=2.0):
            latency = max(1, round((time.monotonic() - started) * 1000))
            return {"server": item["server"], "port": item["port"], "status": "online", "latencyMs": latency}
    except OSError:
        return {"server": item["server"], "port": item["port"], "status": "offline", "latencyMs": None}

def mirror_season() -> dict:
    data = json.loads(get_text(WORKER + "/api/season"))
    season = data.get("season")
    if season not in VALID_SEASONS:
        raise ValueError("Worker returned an invalid season")
    html_path = PUBLIC / "index.html"
    html = html_path.read_text(encoding="utf-8")
    updated = re.sub(r'(<html\b[^>]*\bdata-season=")[^"]*(")', rf'\g<1>{season}\g<2>', html, count=1, flags=re.I)
    if updated == html and not re.search(r'<html\b[^>]*\bdata-season="', html, re.I):
        raise ValueError("Could not find data-season attribute in public/index.html")
    html_path.write_text(updated, encoding="utf-8")
    snapshot = {"season": season, "updatedAt": data.get("updatedAt"), "syncedAt": datetime.now(timezone.utc).isoformat()}
    (PUBLIC / "season.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return snapshot

def main() -> None:
    PUBLIC.mkdir(parents=True, exist_ok=True)
    season = mirror_season()
    all_links, source_health = {}, []
    for name, url in SOURCES:
        try:
            links = extract_links(get_text(url), name)
            if not links:
                raise ValueError("no valid links found")
            for item in links:
                all_links.setdefault(item["url"], item)
            source_health.append({"source": name, "status": "ok", "links": len(links)})
        except Exception as exc:
            source_health.append({"source": name, "status": "error", "error": str(exc)[:180], "links": 0})

    if not all_links:
        raise RuntimeError("All proxy sources failed; existing generated catalog was not replaced")

    links = list(all_links.values())
    endpoints = {}
    for item in links:
        endpoints[(item["server"].lower(), item["port"])] = {"server": item["server"], "port": item["port"]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        statuses = list(pool.map(probe, endpoints.values()))
    status_map = {(x["server"].lower(), x["port"]): x for x in statuses}
    for item in links:
        status = status_map[(item["server"].lower(), item["port"])]
        item["status"] = status["status"]
        item["latencyMs"] = status["latencyMs"]

    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "generatedAt": now,
        "season": season["season"],
        "total": len(links),
        "online": sum(1 for x in statuses if x["status"] == "online"),
        "offline": sum(1 for x in statuses if x["status"] == "offline"),
        "proxies": links,
        "sources": source_health,
    }
    (PUBLIC / "proxies.json").write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    (PUBLIC / "proxies.txt").write_text("\n".join(x["url"] for x in links) + "\n", encoding="utf-8")
    (PUBLIC / "proxy-status.json").write_text(json.dumps({"generatedAt": now, "results": statuses}, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(json.dumps({"season": season["season"], "links": len(links), "online": payload["online"], "offline": payload["offline"], "sourcesOk": sum(x["status"] == "ok" for x in source_health), "sourcesFailed": sum(x["status"] == "error" for x in source_health)}, ensure_ascii=False))

if __name__ == "__main__":
    main()
