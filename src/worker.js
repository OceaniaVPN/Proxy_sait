import { connect } from "cloudflare:sockets";
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "X-DNS-Prefetch-Control": "off"
};
const VALID_SEASONS = new Set(["spring", "summer", "autumn", "winter"]);
const COOKIE_NAME = "steklovpn_admin";
const SESSION_SECONDS = 8 * 60 * 60;
const encoder = new TextEncoder();
const TCP_PROBE_VERSION = "v4";
const PROXY_REFRESH_INTERVAL_MS = 5 * 60 * 60 * 1000;
const PROXY_CACHE_MAX_AGE_MS = 6 * 60 * 60 * 1000;
const MAX_PROXY_TARGETS = 48; // Maximum endpoints in one probe batch, not a catalog limit.
const MAX_PROXY_SOURCE_BYTES = 512 * 1024;
const PROXY_SOURCES = [
  { name: "OceaniaVPN/Proxy_sait:public/proxies.txt", url: "https://raw.githubusercontent.com/OceaniaVPN/Proxy_sait/main/public/proxies.txt" },
  { name: "OceaniaVPN/Proxy_sait:data/proxies.txt", url: "https://raw.githubusercontent.com/OceaniaVPN/Proxy_sait/main/data/proxies.txt" },
  { name: "iwizard7/MTProxy_list:working", url: "https://iwizard7.github.io/MTProxy_list/working.txt" },
  { name: "iwizard7/MTProxy_list:stable", url: "https://iwizard7.github.io/MTProxy_list/stable.txt" },
  { name: "iwizard7/MTProxy_list:all", url: "https://iwizard7.github.io/MTProxy_list/all.txt" },
  { name: "0xRadikal/Free-Telegram-Proxy:fast", url: "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/fast/tg.txt" },
  { name: "0xRadikal/Free-Telegram-Proxy:stable", url: "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/stable/tg.txt" },
  { name: "0xRadikal/Free-Telegram-Proxy:resilient-tg", url: "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/resilient/tg.txt" },
  { name: "0xRadikal/Free-Telegram-Proxy:resilient-tme", url: "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/resilient/tme.txt" },
  { name: "0xRadikal/Free-Telegram-Proxy:top100", url: "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/top100.txt" },
  { name: "SoliSpirit/mtproto:all_proxies", url: "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt" }
];

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Pragma": "no-cache",
      ...extraHeaders
    }
  });
}
function cookieValue(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index >= 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return "";
}
function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value))));
}
async function safeEqual(left, right) {
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right))
  ]);
  const aa = new Uint8Array(a), bb = new Uint8Array(b);
  let difference = 0;
  for (let i = 0; i < aa.length; i++) difference |= aa[i] ^ bb[i];
  return difference === 0;
}
function sameOrigin(request, url) {
  const origin = request.headers.get("Origin");
  if (!origin) return false;
  try { return new URL(origin).origin === url.origin; } catch { return false; }
}
async function createSession(secret) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const nonce = crypto.randomUUID();
  const payload = expires + "." + nonce;
  return payload + "." + await hmac(payload, secret);
}
async function isAdmin(request, secret) {
  if (!secret) return false;
  const parts = cookieValue(request, COOKIE_NAME).split(".");
  const now = Math.floor(Date.now() / 1000);
  if (parts.length !== 3) return false;
  const expires = Number(parts[0]);
  if (!Number.isSafeInteger(expires) || expires <= now || expires > now + SESSION_SECONDS + 60) return false;
  return safeEqual(parts[2], await hmac(parts[0] + "." + parts[1], secret));
}
function sessionCookie(token) {
  return COOKIE_NAME + "=" + token + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + SESSION_SECONDS;
}
function expiredCookie() {
  return COOKIE_NAME + "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
function proxyTargetKey(server, port) {
  return String(server).trim().toLowerCase() + "|" + String(port);
}

function extractAllowedProxyTargets(feed) {
  const targets = new Map();
  const pattern = /(?:tg:\/\/(?:proxy|socks)\?[^\s"'<>]+|https?:\/\/t\.me\/(?:proxy|socks|webproxy)\?[^\s"'<>]+|socks5:\/\/[^\s"'<>]+)/gi;
  for (const rawLine of feed.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    const matches = line.match(pattern) || [];
    for (let candidate of matches) {
      candidate = candidate.replace(/[),.;\]}]+$/g, "");
      try {
        const parsed = new URL(candidate);
        const server = parsed.searchParams.get("server") || (parsed.protocol === "socks5:" ? parsed.hostname : "");
        const rawPort = parsed.searchParams.get("port") || parsed.port;
        const port = rawPort ? Number(rawPort) : (parsed.protocol === "https:" && parsed.pathname.toLowerCase() === "/webproxy" ? 443 : 0);
        if (!server || !Number.isInteger(port) || port < 1 || port > 65535) continue;
        const target = { server: server.trim(), port };
        targets.set(proxyTargetKey(target.server, target.port), target);
      } catch (_) {
        // Пропускаем некорректные строки из списка.
      }
    }
  }
  return targets;
}

async function probeTcpTarget(target) {
  const startedAt = Date.now();
  let socket = null;
  let timer = null;
  try {
    socket = connect({ hostname: target.server, port: target.port });
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("TCP timeout")), 1800);
      })
    ]);
    return {
      server: target.server,
      port: target.port,
      status: "online",
      latencyMs: Math.max(1, Date.now() - startedAt)
    };
  } catch (error) {
    console.warn("TCP probe failed:", target.server, target.port, error?.message || String(error));
    return {
      server: target.server,
      port: target.port,
      status: "offline",
      latencyMs: null
    };
  } finally {
    if (timer !== null) clearTimeout(timer);
    if (socket) {
      try { await socket.close(); } catch (_) {}
    }
  }
}

async function probeTcpTargets(targets) {
  const results = new Array(targets.length);
  let nextIndex = 0;
  const worker = async () => {
    while (true) {
      const index = nextIndex++;
      if (index >= targets.length) return;
      results[index] = await probeTcpTarget(targets[index]);
    }
  };
  // Stay within the Workers outbound-connection limit while finishing a bounded probe batch.
  const count = Math.min(6, targets.length);
  await Promise.all(Array.from({ length: count }, () => worker()));
  return results;
}


async function hashProxyFeed(feed) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(feed + "\n" + TCP_PROBE_VERSION));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function extractTelegramProxyLinks(feed, sourceName) {
  const links = new Map();
  const pattern = /(?:tg:\/\/(?:proxy|socks)\?[^\s"'<>]+|https?:\/\/t\.me\/(?:proxy|socks|webproxy)\?[^\s"'<>]+|socks5:\/\/[^\s"'<>]+)/gi;
  for (const rawLine of feed.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    for (let candidate of (line.match(pattern) || [])) {
      candidate = candidate.replace(/[),.;\]}]+$/g, "");
      try {
        const parsed = new URL(candidate);
        let kind = "";
        if (parsed.protocol === "tg:" && ["proxy", "socks"].includes(parsed.hostname.toLowerCase())) {
          kind = parsed.hostname.toLowerCase();
        } else if ((parsed.protocol === "https:" || parsed.protocol === "http:")
          && parsed.hostname.toLowerCase() === "t.me"
          && ["/proxy", "/socks", "/webproxy"].includes(parsed.pathname.toLowerCase())) {
          kind = parsed.pathname.slice(1).toLowerCase();
        } else if (parsed.protocol === "socks5:") {
          kind = "socks5";
        }
        if (!kind) continue;

        const server = (parsed.searchParams.get("server") || (kind === "socks5" ? parsed.hostname : "")).trim();
        const rawPort = parsed.searchParams.get("port") || parsed.port;
        const port = rawPort ? Number(rawPort) : (kind === "webproxy" ? 443 : 0);
        const secret = parsed.searchParams.get("secret") || "";
        if (!server || server.length > 253 || !Number.isInteger(port) || port < 1 || port > 65535) continue;
        if (kind === "proxy" && (secret.length < 16 || secret.length > 512)) continue;

        // Keep separate links when the endpoint is the same but the secret differs.
        const normalizedUrl = parsed.toString();
        const target = { server, port, url: normalizedUrl, source: sourceName };
        if (!links.has(normalizedUrl)) links.set(normalizedUrl, target);
      } catch (_) {
        // Ignore malformed or unsupported lines from public list files.
      }
    }
  }
  return links;
}

async function fetchProxySource(source) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(source.url, {
      headers: { "Accept": "text/plain" },
      redirect: "follow",
      signal: controller.signal
    });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const feed = await response.text();
    if (feed.length > MAX_PROXY_SOURCE_BYTES) throw new Error("Source feed too large");
    return feed;
  } finally {
    clearTimeout(timer);
  }
}

async function runDbBatch(env, statements, batchSize = 40) {
  for (let offset = 0; offset < statements.length; offset += batchSize) {
    await env.DB.batch(statements.slice(offset, offset + batchSize));
  }
}

async function syncProxySources(env) {
  if (!env.DB) throw new Error("D1 binding DB is not configured");
  const sourceResults = await Promise.all(PROXY_SOURCES.map(async source => {
    try {
      const feed = await fetchProxySource(source);
      const links = extractTelegramProxyLinks(feed, source.name);
      if (!links.size) throw new Error("No valid Telegram proxy links found");
      return { source, feed, links, error: null };
    } catch (error) {
      const message = error?.message || String(error);
      console.warn("Proxy source failed:", source.name, message);
      return { source, feed: "", links: new Map(), error: message };
    }
  }));

  const loaded = sourceResults.filter(item => item.links.size > 0);
  const checkedAt = new Date().toISOString();
  if (!loaded.length) {
    await runDbBatch(env, sourceResults.map(item => env.DB.prepare(
      "INSERT INTO proxy_source_health (source, url, status, http_status, bytes, parsed_count, checked_count, online_count, offline_count, checked_at, error) " +
      "VALUES (?, ?, 'error', NULL, 0, 0, 0, 0, 0, ?, ?) ON CONFLICT(source) DO UPDATE SET " +
      "url=excluded.url, status='error', bytes=0, parsed_count=0, checked_count=0, online_count=0, offline_count=0, checked_at=excluded.checked_at, error=excluded.error"
    ).bind(item.source.name, item.source.url, checkedAt, item.error || "Unknown source error")));
    throw new Error("All proxy sources failed; existing catalog kept");
  }

  const linkStatements = [];
  const queueStatements = new Map();
  const legacyStatements = new Map();
  const sourceHealthStatements = [];
  const sourceFingerprintParts = [];
  let parsedLinkCount = 0;

  for (const item of sourceResults) {
    if (item.links.size) {
      sourceFingerprintParts.push(item.source.url + "\n" + item.feed);
      parsedLinkCount += item.links.size;
      for (const link of item.links.values()) {
        const linkId = item.source.name + "|" + link.url;
        linkStatements.push(env.DB.prepare(
          "INSERT INTO proxy_catalog_links (link_id, server, port, proxy_url, source, first_seen_at, last_seen_at) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(link_id) DO UPDATE SET " +
          "server=excluded.server, port=excluded.port, proxy_url=excluded.proxy_url, source=excluded.source, last_seen_at=excluded.last_seen_at"
        ).bind(linkId, link.server, link.port, link.url, item.source.name, checkedAt, checkedAt));

        const endpointKey = proxyTargetKey(link.server, link.port);
        if (!queueStatements.has(endpointKey)) {
          queueStatements.set(endpointKey, env.DB.prepare(
            "INSERT INTO proxy_probe_queue (server, port, queued_at, checked_at, next_check_at) VALUES (?, ?, ?, NULL, ?) " +
            "ON CONFLICT(server, port) DO UPDATE SET next_check_at=excluded.next_check_at"
          ).bind(link.server, link.port, checkedAt, checkedAt));
        }
        // Keep one compatibility row per host:port for older API paths.
        if (!legacyStatements.has(endpointKey)) {
          legacyStatements.set(endpointKey, env.DB.prepare(
            "INSERT INTO proxy_links (server, port, proxy_url, source) VALUES (?, ?, ?, ?) " +
            "ON CONFLICT(server, port) DO UPDATE SET proxy_url=excluded.proxy_url, source=excluded.source"
          ).bind(link.server, link.port, link.url, item.source.name));
        }
      }
    }

    sourceHealthStatements.push(env.DB.prepare(
      "INSERT INTO proxy_source_health (source, url, status, http_status, bytes, parsed_count, checked_count, online_count, offline_count, checked_at, error) " +
      "VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?) ON CONFLICT(source) DO UPDATE SET " +
      "url=excluded.url, status=excluded.status, http_status=excluded.http_status, bytes=excluded.bytes, parsed_count=excluded.parsed_count, " +
      "checked_at=excluded.checked_at, error=excluded.error"
    ).bind(item.source.name, item.source.url, item.error ? "error" : "ok", item.error ? null : 200,
      item.feed.length, item.links.size, checkedAt, item.error));
  }

  await runDbBatch(env, linkStatements, 40);
  await runDbBatch(env, Array.from(queueStatements.values()), 40);
  await runDbBatch(env, Array.from(legacyStatements.values()), 40);
  await runDbBatch(env, sourceHealthStatements, 40);

  // Keep old entries during temporary upstream outages, but retire links that have
  // disappeared from every configured source for 30 days.
  const staleBefore = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  await env.DB.prepare("DELETE FROM proxy_catalog_links WHERE last_seen_at < ?").bind(staleBefore).run();
  await env.DB.prepare(
    "DELETE FROM proxy_probe_queue WHERE NOT EXISTS (" +
    "SELECT 1 FROM proxy_catalog_links l WHERE l.server=proxy_probe_queue.server AND l.port=proxy_probe_queue.port)"
  ).run();

  const sourceHash = await hashProxyFeed(sourceFingerprintParts.join("\n---\n"));
  const totalEndpoints = await env.DB.prepare("SELECT COUNT(*) AS count FROM proxy_probe_queue").first();
  await env.DB.prepare(
    "INSERT INTO proxy_catalog_meta (id, sources_checked_at, source_hash, source_count, parsed_link_count, endpoint_count) " +
    "VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET sources_checked_at=excluded.sources_checked_at, " +
    "source_hash=excluded.source_hash, source_count=excluded.source_count, parsed_link_count=excluded.parsed_link_count, endpoint_count=excluded.endpoint_count"
  ).bind(checkedAt, sourceHash, loaded.length, parsedLinkCount, Number(totalEndpoints?.count || 0)).run();

  return {
    sourceCount: loaded.length,
    failedSourceCount: sourceResults.length - loaded.length,
    parsedLinkCount,
    endpointCount: Number(totalEndpoints?.count || 0),
    checkedAt
  };
}

async function updateProxySourceHealthCounts(env) {
  const cutoff = new Date(Date.now() - PROXY_CACHE_MAX_AGE_MS).toISOString();
  const aggregates = await env.DB.prepare(
    "SELECT l.source AS source, COUNT(DISTINCT l.proxy_url) AS parsedCount, " +
    "COUNT(DISTINCT CASE WHEN c.checked_at >= ? THEN l.server || '|' || l.port END) AS checkedCount, " +
    "COUNT(DISTINCT CASE WHEN c.status='online' AND c.checked_at >= ? THEN l.server || '|' || l.port END) AS onlineCount, " +
    "COUNT(DISTINCT CASE WHEN c.status='offline' AND c.checked_at >= ? THEN l.server || '|' || l.port END) AS offlineCount " +
    "FROM proxy_catalog_links l LEFT JOIN proxy_status_cache c ON c.server=l.server AND c.port=l.port GROUP BY l.source"
  ).bind(cutoff, cutoff, cutoff).all();

  const writes = (aggregates.results || []).map(item => env.DB.prepare(
    "UPDATE proxy_source_health SET parsed_count=?, checked_count=?, online_count=?, offline_count=? WHERE source=?"
  ).bind(Number(item.parsedCount || 0), Number(item.checkedCount || 0), Number(item.onlineCount || 0),
    Number(item.offlineCount || 0), item.source));
  await runDbBatch(env, writes, 40);
}

async function processProxyProbeBatch(env) {
  const now = new Date().toISOString();
  const due = await env.DB.prepare(
    "SELECT server, port FROM proxy_probe_queue WHERE next_check_at <= ? ORDER BY next_check_at, queued_at, server LIMIT ?"
  ).bind(now, MAX_PROXY_TARGETS).all();
  const targets = (due.results || []).map(item => ({ server: item.server, port: Number(item.port) }));
  if (!targets.length) {
    const counts = await env.DB.prepare("SELECT COUNT(*) AS total FROM proxy_probe_queue").first();
    return { checkedCount: 0, onlineCount: 0, offlineCount: 0, targetCount: Number(counts?.total || 0), checkedAt: null };
  }

  const checked = await probeTcpTargets(targets);
  const checkedAt = new Date().toISOString();
  const nextCheckAt = new Date(Date.now() + PROXY_REFRESH_INTERVAL_MS).toISOString();
  const writes = [];
  for (const result of checked) {
    writes.push(env.DB.prepare(
      "INSERT INTO proxy_status_cache (server, port, status, latency_ms, checked_at) VALUES (?, ?, ?, ?, ?) " +
      "ON CONFLICT(server, port) DO UPDATE SET status=excluded.status, latency_ms=excluded.latency_ms, checked_at=excluded.checked_at"
    ).bind(result.server, result.port, result.status, result.latencyMs, checkedAt));
    writes.push(env.DB.prepare(
      "UPDATE proxy_probe_queue SET checked_at=?, next_check_at=? WHERE server=? AND port=?"
    ).bind(checkedAt, nextCheckAt, result.server, result.port));
  }
  await runDbBatch(env, writes, 40);

  const sourceMeta = await env.DB.prepare("SELECT source_hash FROM proxy_catalog_meta WHERE id=1").first();
  const totals = await env.DB.prepare("SELECT COUNT(*) AS count FROM proxy_probe_queue").first();
  await env.DB.prepare(
    "INSERT INTO proxy_status_meta (id, feed_hash, checked_at, target_count) VALUES (1, ?, ?, ?) " +
    "ON CONFLICT(id) DO UPDATE SET feed_hash=excluded.feed_hash, checked_at=excluded.checked_at, target_count=excluded.target_count"
  ).bind(sourceMeta?.source_hash || "", checkedAt, Number(totals?.count || 0)).run();

  await updateProxySourceHealthCounts(env);
  return {
    checkedCount: checked.length,
    onlineCount: checked.filter(item => item.status === "online").length,
    offlineCount: checked.filter(item => item.status === "offline").length,
    targetCount: Number(totals?.count || 0),
    checkedAt
  };
}

async function refreshProxyCatalog(env, forceSourceSync = false) {
  if (!env.DB) throw new Error("D1 binding DB is not configured");
  const sourceMeta = await env.DB.prepare(
    "SELECT sources_checked_at FROM proxy_catalog_meta WHERE id=1"
  ).first();
  const sourceCheckedAt = sourceMeta?.sources_checked_at ? Date.parse(sourceMeta.sources_checked_at) : NaN;
  let sourceResult = null;

  if (forceSourceSync || !Number.isFinite(sourceCheckedAt) || Date.now() - sourceCheckedAt >= PROXY_REFRESH_INTERVAL_MS) {
    sourceResult = await syncProxySources(env);
  }

  const batchResult = await processProxyProbeBatch(env);
  return {
    changed: Boolean(sourceResult || batchResult.checkedCount),
    sourceCount: sourceResult?.sourceCount || 0,
    failedSourceCount: sourceResult?.failedSourceCount || 0,
    parsedLinkCount: sourceResult?.parsedLinkCount || 0,
    checkedCount: batchResult.checkedCount,
    targetCount: batchResult.targetCount,
    onlineCount: batchResult.onlineCount,
    offlineCount: batchResult.offlineCount,
    checkedAt: batchResult.checkedAt || new Date().toISOString()
  };
}

async function runLockedProxyRefresh(env, forceSourceSync = false) {
  const startedAt = new Date().toISOString();
  const staleBefore = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const lock = await env.DB.prepare(
    "INSERT INTO proxy_refresh_lock (id, started_at) VALUES (1, ?) " +
    "ON CONFLICT(id) DO UPDATE SET started_at=excluded.started_at WHERE proxy_refresh_lock.started_at < ?"
  ).bind(startedAt, staleBefore).run();
  if (Number(lock.meta?.changes || 0) !== 1) return { skipped: true };
  try {
    return await refreshProxyCatalog(env, forceSourceSync);
  } finally {
    await env.DB.prepare("DELETE FROM proxy_refresh_lock WHERE id=1 AND started_at=?").bind(startedAt).run();
  }
}

async function getVerifiedProxyFeed(env, ctx) {
  const response = await getVerifiedProxyCatalog(env, ctx);
  if (!response.ok) {
    return new Response("Каталог прокси обновляется.\n", {
      status: response.status,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Proxy-Refresh": "pending" }
    });
  }
  const payload = await response.json();
  return new Response((payload.proxies || []).join("\n"), {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Proxy-Count": String(payload.count || 0),
      "X-Proxy-Checked-At": payload.checkedAt || ""
    }
  });
}

async function getVerifiedProxyCatalog(env, ctx) {
  if (!env.DB) return json({ error: "Database binding DB is not configured." }, 503);

  const now = new Date().toISOString();
  const cutoff = new Date(Date.now() - PROXY_CACHE_MAX_AGE_MS).toISOString();
  const lock = await env.DB.prepare("SELECT started_at FROM proxy_refresh_lock WHERE id=1").first();
  const lockStartedAt = lock?.started_at ? Date.parse(lock.started_at) : NaN;
  const refreshInProgress = Number.isFinite(lockStartedAt) && Date.now() - lockStartedAt < 10 * 60 * 1000;
  const sourceMeta = await env.DB.prepare(
    "SELECT sources_checked_at FROM proxy_catalog_meta WHERE id=1"
  ).first();
  const sourceCheckedAt = sourceMeta?.sources_checked_at ? Date.parse(sourceMeta.sources_checked_at) : NaN;
  const due = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM proxy_probe_queue WHERE next_check_at <= ?"
  ).bind(now).first();
  const needsSourceSync = !Number.isFinite(sourceCheckedAt) || Date.now() - sourceCheckedAt >= PROXY_REFRESH_INTERVAL_MS;
  const hasDueChecks = Number(due?.count || 0) > 0;

  if (!refreshInProgress && (needsSourceSync || hasDueChecks) && ctx?.waitUntil) {
    ctx.waitUntil(runLockedProxyRefresh(env, false).catch(error => console.error("Background proxy catalog update failed:", error)));
  }

  const [meta, rows, progress] = await Promise.all([
    env.DB.prepare("SELECT checked_at, target_count FROM proxy_status_meta WHERE id=1").first(),
    env.DB.prepare(
      "SELECT DISTINCT l.proxy_url FROM proxy_catalog_links l " +
      "JOIN proxy_status_cache c ON c.server=l.server AND c.port=l.port " +
      "WHERE c.status='online' AND c.checked_at >= ? AND l.last_seen_at >= ? " +
      "ORDER BY l.proxy_url"
    ).bind(cutoff, new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()).all(),
    env.DB.prepare(
      "SELECT COUNT(*) AS total, " +
      "SUM(CASE WHEN q.checked_at >= ? AND q.next_check_at > ? THEN 1 ELSE 0 END) AS checked, " +
      "SUM(CASE WHEN q.next_check_at <= ? THEN 1 ELSE 0 END) AS pending " +
      "FROM proxy_probe_queue q"
    ).bind(cutoff, now, now).first()
  ]);

  const proxies = (rows.results || []).map(row => row.proxy_url).filter(value => typeof value === "string" && value.trim());
  const total = Number(progress?.total || 0);
  const checked = Number(progress?.checked || 0);
  const pending = Number(progress?.pending || 0);
  const responsePayload = {
    pending: pending > 0 || needsSourceSync,
    count: proxies.length,
    checkedAt: meta?.checked_at || null,
    proxies,
    progress: {
      totalEndpoints: total,
      checkedRecently: checked,
      pendingChecks: pending,
      percent: total ? Math.min(100, Math.round(checked / total * 100)) : 0
    }
  };

  if (!proxies.length && (pending > 0 || needsSourceSync || refreshInProgress)) {
    return json(
      { ...responsePayload, message: "Собираем источники и проверяем первую партию прокси." },
      503,
      { "X-Proxy-Refresh": "pending", "Retry-After": "4" }
    );
  }
  return json(responsePayload);
}

async function getCachedProxyStatuses(env) {
  if (!env.DB) return json({ error: "Database binding DB is not configured." }, 503);
  const cutoff = new Date(Date.now() - PROXY_CACHE_MAX_AGE_MS).toISOString();
  const [meta, rows] = await Promise.all([
    env.DB.prepare("SELECT checked_at, target_count FROM proxy_status_meta WHERE id = 1").first(),
    env.DB.prepare(
      "SELECT server, port, status, latency_ms AS latencyMs FROM proxy_status_cache " +
      "WHERE checked_at >= ? ORDER BY server, port"
    ).bind(cutoff).all()
  ]);
  return json({
    results: rows.results || [],
    checkedAt: meta?.checked_at || null,
    targetCount: meta?.target_count || 0,
    ready: Boolean(rows.results?.length)
  });
}

async function getHealth(env) {
  if (!env.DB) return json({ ok: false, error: "D1 binding DB is not configured." }, 503);

  const [sourceTable, catalogTable] = await Promise.all([
    env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='proxy_source_health' LIMIT 1").first(),
    env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='proxy_catalog_links' LIMIT 1").first()
  ]);
  if (!sourceTable || !catalogTable) {
    return json({
      ok: false,
      code: "MIGRATION_REQUIRED",
      message: "Не применены миграции каталога прокси.",
      migrations: ["0004_proxy_source_health.sql", "0005_full_proxy_catalog.sql"],
      configuredSources: PROXY_SOURCES.length
    }, 503);
  }

  const cutoff = new Date(Date.now() - PROXY_CACHE_MAX_AGE_MS).toISOString();
  const [meta, statusRows, savedSources, sourceAggregates, feedCount, lock, catalogMeta, queueStats, linkCount] = await Promise.all([
    env.DB.prepare("SELECT checked_at, target_count FROM proxy_status_meta WHERE id=1").first(),
    env.DB.prepare(
      "SELECT status, COUNT(*) AS count FROM proxy_status_cache WHERE checked_at >= ? GROUP BY status"
    ).bind(cutoff).all(),
    env.DB.prepare(
      "SELECT source, url, status, http_status AS httpStatus, bytes, parsed_count AS parsedCount, " +
      "checked_count AS checkedCount, online_count AS onlineCount, offline_count AS offlineCount, checked_at AS checkedAt, error " +
      "FROM proxy_source_health ORDER BY source"
    ).all(),
    env.DB.prepare(
      "SELECT l.source AS source, COUNT(DISTINCT l.proxy_url) AS parsedCount, " +
      "COUNT(DISTINCT CASE WHEN c.checked_at >= ? THEN l.server || '|' || l.port END) AS checkedCount, " +
      "COUNT(DISTINCT CASE WHEN c.status='online' AND c.checked_at >= ? THEN l.server || '|' || l.port END) AS onlineCount, " +
      "COUNT(DISTINCT CASE WHEN c.status='offline' AND c.checked_at >= ? THEN l.server || '|' || l.port END) AS offlineCount " +
      "FROM proxy_catalog_links l LEFT JOIN proxy_status_cache c ON c.server=l.server AND c.port=l.port GROUP BY l.source"
    ).bind(cutoff, cutoff, cutoff).all(),
    env.DB.prepare(
      "SELECT COUNT(DISTINCT l.server || '|' || l.port) AS count FROM proxy_catalog_links l " +
      "JOIN proxy_status_cache c ON c.server=l.server AND c.port=l.port " +
      "WHERE c.status='online' AND c.checked_at >= ?"
    ).bind(cutoff).first(),
    env.DB.prepare("SELECT started_at FROM proxy_refresh_lock WHERE id=1").first(),
    env.DB.prepare(
      "SELECT sources_checked_at AS sourcesCheckedAt, source_count AS sourceCount, " +
      "parsed_link_count AS parsedLinkCount, endpoint_count AS endpointCount FROM proxy_catalog_meta WHERE id=1"
    ).first(),
    env.DB.prepare(
      "SELECT COUNT(*) AS total, " +
      "SUM(CASE WHEN checked_at >= ? AND next_check_at > ? THEN 1 ELSE 0 END) AS checkedRecently, " +
      "SUM(CASE WHEN next_check_at <= ? THEN 1 ELSE 0 END) AS pending " +
      "FROM proxy_probe_queue"
    ).bind(cutoff, new Date().toISOString(), new Date().toISOString()).first(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM proxy_catalog_links").first()
  ]);

  const counts = Object.fromEntries((statusRows.results || []).map(row => [row.status, Number(row.count || 0)]));
  const online = counts.online || 0;
  const offline = counts.offline || 0;
  const uniqueChecked = online + offline;
  const saved = new Map((savedSources.results || []).map(item => [item.source, item]));
  const aggregates = new Map((sourceAggregates.results || []).map(item => [item.source, item]));
  const sourceRows = PROXY_SOURCES.map(config => {
    const recorded = saved.get(config.name);
    const aggregate = aggregates.get(config.name);
    if (!recorded && !aggregate) {
      return {
        source: config.name, url: config.url, status: "pending",
        parsedCount: 0, checkedCount: 0, onlineCount: 0, offlineCount: 0,
        checkedAt: null, error: "Источник ещё не обработан"
      };
    }
    return {
      source: config.name,
      url: config.url,
      status: recorded?.status || "ok",
      httpStatus: recorded?.httpStatus ?? null,
      bytes: Number(recorded?.bytes || 0),
      parsedCount: Number(aggregate?.parsedCount ?? recorded?.parsedCount ?? 0),
      checkedCount: Number(aggregate?.checkedCount || 0),
      onlineCount: Number(aggregate?.onlineCount || 0),
      offlineCount: Number(aggregate?.offlineCount || 0),
      checkedAt: recorded?.checkedAt || null,
      error: recorded?.error || null
    };
  });

  const totalEndpoints = Number(queueStats?.total || catalogMeta?.endpointCount || 0);
  const checkedRecently = Number(queueStats?.checkedRecently || 0);
  const pendingChecks = Number(queueStats?.pending || 0);
  const feedOnline = Number(feedCount?.count || 0);
  return json({
    ok: true,
    service: "Proxy Sait",
    checkedAt: meta?.checked_at || null,
    lastSourceSyncAt: catalogMeta?.sourcesCheckedAt || null,
    refreshing: Boolean(lock?.started_at && Date.now() - Date.parse(lock.started_at) < 10 * 60 * 1000),
    summary: {
      configuredSources: PROXY_SOURCES.length,
      sourcesOk: sourceRows.filter(item => item.status === "ok").length,
      sourcesFailed: sourceRows.filter(item => item.status === "error").length,
      sourcesPending: sourceRows.filter(item => item.status === "pending").length,
      sourcesWithExistingData: 0,
      discoveredLinks: Number(linkCount?.count || 0),
      uniqueEndpoints: totalEndpoints,
      checkedRecently,
      pendingChecks,
      uniqueChecked,
      cachedStatusRows: uniqueChecked,
      online,
      offline,
      feedOnline,
      onlinePercent: uniqueChecked ? Math.round(online / uniqueChecked * 100) : 0
    },
    sources: sourceRows
  });
}

async function handleProxyStatus(request, env, url) {
  if (!sameOrigin(request, url)) return json({ error: "Origin check failed." }, 403);
  if (!env.ASSETS) return json({ error: "Assets binding is not configured." }, 503);

  let raw;
  try {
    raw = await request.text();
    if (raw.length > 8000) return json({ error: "Некорректный запрос." }, 413);
  } catch (_) {
    return json({ error: "Некорректный запрос." }, 400);
  }

  let body;
  try { body = JSON.parse(raw); } catch (_) {
    return json({ error: "Некорректный запрос." }, 400);
  }
  if (!Array.isArray(body?.targets) || body.targets.length < 1 || body.targets.length > 24) {
    return json({ error: "Некорректный список серверов." }, 400);
  }

  const catalogRows = await env.DB.prepare("SELECT server, port FROM proxy_links").all();
  const allowed = new Map((catalogRows.results || []).map(item => [
    proxyTargetKey(item.server, item.port), { server: item.server, port: Number(item.port) }
  ]));
  const requested = new Map();
  const unverified = [];
  for (const item of body.targets) {
    const server = typeof item?.server === "string" ? item.server.trim() : "";
    const port = Number(item?.port);
    if (!server || server.length > 253 || !Number.isInteger(port) || port < 1 || port > 65535) {
      return json({ error: "Некорректный адрес сервера." }, 400);
    }
    const key = proxyTargetKey(server, port);
    if (requested.has(key)) continue;
    if (allowed.has(key)) requested.set(key, allowed.get(key));
    else unverified.push({ server, port, status: "unknown", latencyMs: null });
  }

  const checked = await probeTcpTargets(Array.from(requested.values()));
  return json({ results: checked.concat(unverified) });
}

async function handleApi(request, env, url, ctx) {
  const path = url.pathname;
  const method = request.method;
  if (path === "/api/proxies" && method === "GET") {
    return getVerifiedProxyCatalog(env, ctx);
  }
  if (path === "/api/proxy-status" && method === "GET") {
    return getCachedProxyStatuses(env);
  }
  if (path === "/api/health" && method === "GET") {
    return getHealth(env);
  }
  if (!env.DB) return json({ error: "Database binding DB is not configured." }, 503);

  if (path === "/api/proxy-refresh" && method === "POST") {
    if (!sameOrigin(request, url)) return json({ error: "Origin check failed." }, 403);
    if (!ctx?.waitUntil) return json({ error: "Background refresh is unavailable." }, 503);

    const startedAt = new Date().toISOString();
    const staleBefore = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const lock = await env.DB.prepare(
      "INSERT INTO proxy_refresh_lock (id, started_at) VALUES (1, ?) " +
      "ON CONFLICT(id) DO UPDATE SET started_at=excluded.started_at WHERE proxy_refresh_lock.started_at < ?"
    ).bind(startedAt, staleBefore).run();
    if (Number(lock.meta?.changes || 0) !== 1) {
      return json({ accepted: true, alreadyRunning: true, message: "Обновление уже выполняется." }, 202);
    }

    const task = refreshProxyCatalog(env, true).then(result => {
      console.log("Manual proxy catalog update completed:", result.onlineCount + " online from " + result.checkedCount + " checked; " + result.targetCount + " total endpoints; sources=" + result.sourceCount);
    }).catch(error => {
      console.error("Manual proxy refresh failed:", error);
    }).finally(async () => {
      await env.DB.prepare("DELETE FROM proxy_refresh_lock WHERE id=1 AND started_at=?").bind(startedAt).run();
    });
    ctx.waitUntil(task);
    return json({ accepted: true, message: "Обновление каталога запущено." }, 202);
  }

  if (path === "/api/season" && method === "GET") {
    const row = await env.DB.prepare(
      "SELECT setting_value, updated_at FROM site_settings WHERE setting_key = 'season' LIMIT 1"
    ).first();
    return json({
      season: VALID_SEASONS.has(row?.setting_value) ? row.setting_value : "autumn",
      updatedAt: row?.updated_at || null
    });
  }

  if (path === "/api/admin/session" && method === "GET") {
    return json({ authenticated: await isAdmin(request, env.SESSION_SECRET || "") });
  }

  if (path === "/api/admin/login" && method === "POST") {
    if (!sameOrigin(request, url)) return json({ error: "Origin check failed." }, 403);
    if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return json({ error: "Admin secrets are not configured." }, 503);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const ipHash = await hmac("login-ip:" + ip, env.ADMIN_PASSWORD);
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare("DELETE FROM admin_login_attempts WHERE attempted_at < ?").bind(now - 3600).run();
    const attempts = await env.DB.prepare(
      "SELECT COUNT(*) AS total FROM admin_login_attempts WHERE ip_hash = ? AND attempted_at > ?"
    ).bind(ipHash, now - 600).first();
    if (Number(attempts?.total || 0) >= 6) {
      return json({ error: "Слишком много попыток. Попробуй позже." }, 429, { "Retry-After": "600" });
    }

    let body;
    try {
      const raw = await request.text();
      if (raw.length > 4096) return json({ error: "Некорректный запрос." }, 413);
      body = JSON.parse(raw);
    } catch { return json({ error: "Некорректный запрос." }, 400); }

    const supplied = typeof body?.password === "string" ? body.password : "";
    if (!await safeEqual(supplied, env.ADMIN_PASSWORD)) {
      await env.DB.prepare(
        "INSERT INTO admin_login_attempts (ip_hash, attempted_at) VALUES (?, ?)"
      ).bind(ipHash, now).run();
      return json({ error: "Неверный пароль." }, 401);
    }
    await env.DB.prepare("DELETE FROM admin_login_attempts WHERE ip_hash = ?").bind(ipHash).run();
    return json({ authenticated: true }, 200, { "Set-Cookie": sessionCookie(await createSession(env.SESSION_SECRET)) });
  }

  if (path === "/api/admin/logout" && method === "POST") {
    if (!sameOrigin(request, url)) return json({ error: "Origin check failed." }, 403);
    return json({ authenticated: false }, 200, { "Set-Cookie": expiredCookie() });
  }

  if (path === "/api/admin/season" && method === "POST") {
    if (!sameOrigin(request, url)) return json({ error: "Origin check failed." }, 403);
    if (!await isAdmin(request, env.SESSION_SECRET || "")) return json({ error: "Требуется вход администратора." }, 401);

    let body;
    try {
      const raw = await request.text();
      if (raw.length > 2048) return json({ error: "Некорректный запрос." }, 413);
      body = JSON.parse(raw);
    } catch { return json({ error: "Некорректный запрос." }, 400); }

    if (typeof body?.season !== "string" || !VALID_SEASONS.has(body.season)) {
      return json({ error: "Неизвестный сезон." }, 400);
    }
    await env.DB.prepare(
      "INSERT INTO site_settings (setting_key, setting_value, updated_at) VALUES ('season', ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = excluded.updated_at"
    ).bind(body.season).run();
    const saved = await env.DB.prepare(
      "SELECT setting_value, updated_at FROM site_settings WHERE setting_key = 'season' LIMIT 1"
    ).first();
    return json({ season: saved.setting_value, updatedAt: saved.updated_at });
  }

  if (path.startsWith("/api/")) return json({ error: "Not found." }, 404);
  return null;
}
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.protocol !== "https:") {
      url.protocol = "https:";
      return Response.redirect(url.toString(), 301);
    }

    let response;
    try {
      if (url.pathname === "/health" && request.method === "GET") {
        response = await getHealth(env);
      } else if (url.pathname.startsWith("/api/")) {
        if (request.method !== "GET" && request.method !== "POST") {
          response = json({ error: "Method not allowed." }, 405, { "Allow": "GET, POST" });
        } else {
          response = await handleApi(request, env, url, ctx);
        }
      } else if (request.method === "GET" && url.pathname === "/proxies.txt") {
        response = await getVerifiedProxyFeed(env, ctx);
      } else if (request.method === "GET" || request.method === "HEAD") {
        response = env.ASSETS ? await env.ASSETS.fetch(request) : new Response("Assets binding is not configured.", { status: 503 });
      } else {
        response = new Response("Method Not Allowed", { status: 405, headers: { "Allow": "GET, HEAD" } });
      }
    } catch (error) {
      console.error("Proxy Worker error:", error);
      response = (url.pathname.startsWith("/api/") || url.pathname === "/health")
        ? json({
            ok: false,
            error: "Внутренняя ошибка при чтении D1. Проверь удалённые миграции и привязку DB.",
            hint: "Выполни: npx wrangler d1 migrations list steklovpn-shared --remote"
          }, 500)
        : new Response("Internal Server Error", { status: 500 });
    }

    const headers = new Headers(response.headers);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
    if (url.pathname.startsWith("/api/") || url.pathname === "/health" || url.pathname === "/proxies.txt") {
      headers.set("Cache-Control", "no-store");
      headers.set("Pragma", "no-cache");
    } else if (url.pathname === "/" || url.pathname.endsWith(".html")) {
      headers.set("Cache-Control", "public, max-age=0, must-revalidate");
    } else if (/\.(?:js|css)$/i.test(url.pathname)) {
      headers.set("Cache-Control", "no-store, max-age=0");
      headers.set("Pragma", "no-cache");
    } else if (response.ok) {
      headers.set("Cache-Control", "public, max-age=3600");
    }
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  },
  async scheduled(controller, env) {
    if (!env.DB) throw new Error("D1 binding DB is not configured");
    const now = new Date().toISOString();
    const sourceMeta = await env.DB.prepare(
      "SELECT sources_checked_at FROM proxy_catalog_meta WHERE id=1"
    ).first();
    const lastSourceSync = sourceMeta?.sources_checked_at ? Date.parse(sourceMeta.sources_checked_at) : NaN;
    const due = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM proxy_probe_queue WHERE next_check_at <= ?"
    ).bind(now).first();
    const sourceSyncDue = !Number.isFinite(lastSourceSync) || Date.now() - lastSourceSync >= PROXY_REFRESH_INTERVAL_MS;
    const checksDue = Number(due?.count || 0) > 0;
    if (!sourceSyncDue && !checksDue) return;

    const result = await runLockedProxyRefresh(env, false);
    if (result.changed) {
      console.log(
        "Proxy catalog batch:", result.onlineCount + " online / " + result.checkedCount + " checked",
        "queue=" + result.targetCount, "sources=" + result.sourceCount, result.checkedAt
      );
    }
  }
};
