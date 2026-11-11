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
const MAX_PROXY_TARGETS = 48;
const MAX_PROXY_SOURCE_BYTES = 512 * 1024;
const PROXY_SOURCES = [
  { name: "OceaniaVPN/Proxy_sait:public/proxies.txt", url: "https://raw.githubusercontent.com/OceaniaVPN/Proxy_sait/main/public/proxies.txt" },
  { name: "OceaniaVPN/Proxy_sait:data/proxies.txt", url: "https://raw.githubusercontent.com/OceaniaVPN/Proxy_sait/main/data/proxies.txt" },
  { name: "iwizard7/MTProxy_list:working", url: "https://raw.githubusercontent.com/iwizard7/MTProxy_list/data/working.txt" },
  { name: "iwizard7/MTProxy_list:stable", url: "https://iwizard7.github.io/MTProxy_list/stable.txt" },
  { name: "0xRadikal/Free-Telegram-Proxy:fast", url: "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/fast/tg.txt" },
  { name: "0xRadikal/Free-Telegram-Proxy:stable", url: "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/stable/tg.txt" },
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

        // MTProto requires its secret; SOCKS and WEB links have different URL formats.
        if (kind === "proxy" && (secret.length < 16 || secret.length > 512)) continue;

        const target = { server, port, url: parsed.toString(), source: sourceName };
        const key = proxyTargetKey(server, port);
        if (!links.has(key)) links.set(key, target);
      } catch (_) {
        // Пропускаем некорректные строки из списка.
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

async function refreshProxyStatusCache(env) {
  if (!env.DB) throw new Error("D1 binding DB is not configured");
  const previous = await env.DB.prepare("SELECT server, port, proxy_url, source FROM proxy_links").all();

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
  const failed = sourceResults.filter(item => item.links.size === 0);
  const loadedNames = new Set(loaded.map(item => item.source.name));
  const failedNames = new Set(failed.map(item => item.source.name));

  if (!loaded.length) {
    const checkedAt = new Date().toISOString();
    await env.DB.batch(sourceResults.map(item => env.DB.prepare(
      "INSERT INTO proxy_source_health (source, url, status, http_status, bytes, parsed_count, checked_count, online_count, offline_count, checked_at, error) " +
      "VALUES (?, ?, 'error', NULL, 0, 0, 0, 0, 0, ?, ?) ON CONFLICT(source) DO UPDATE SET " +
      "url=excluded.url, status='error', bytes=0, parsed_count=0, checked_count=0, online_count=0, offline_count=0, checked_at=excluded.checked_at, error=excluded.error"
    ).bind(item.source.name, item.source.url, checkedAt, item.error || "Unknown source error")));
    throw new Error("All proxy sources failed; existing catalog kept");
  }

  // Build one pool per source and interleave them. This prevents a large repository
  // file from consuming the entire probe budget before other sources are considered.
  const pools = loaded.map(item => Array.from(item.links.values()));
  for (const sourceName of failedNames) {
    const preserved = (previous.results || [])
      .filter(row => row.source === sourceName)
      .map(row => ({
        server: row.server,
        port: Number(row.port),
        url: row.proxy_url,
        source: row.source
      }));
    if (preserved.length) pools.push(preserved);
  }

  const candidates = new Map();
  const rotationSlot = Math.floor(Date.now() / PROXY_REFRESH_INTERVAL_MS);
  const maxPoolLength = Math.max(0, ...pools.map(pool => pool.length));
  for (let offset = 0; candidates.size < MAX_PROXY_TARGETS && offset < maxPoolLength; offset++) {
    let foundAtOffset = false;
    for (const pool of pools) {
      if (!pool.length) continue;
      // Move eight positions per five-hour refresh window so later entries are eventually checked.
      const startIndex = (rotationSlot * 8) % pool.length;
      const link = pool[(startIndex + offset) % pool.length];
      if (!link) continue;
      foundAtOffset = true;
      const key = proxyTargetKey(link.server, link.port);
      if (!candidates.has(key) && candidates.size < MAX_PROXY_TARGETS) candidates.set(key, link);
    }
    if (!foundAtOffset) break;
  }

  const selected = Array.from(candidates.values());
  if (!selected.length) throw new Error("No proxy endpoints found");
  const checked = await probeTcpTargets(selected.map(item => ({ server: item.server, port: item.port })));
  const checkedAt = new Date().toISOString();

  for (let offset = 0; offset < checked.length; offset += 30) {
    const batch = [];
    for (let i = offset; i < Math.min(offset + 30, checked.length); i++) {
      const link = selected[i], status = checked[i];
      batch.push(env.DB.prepare(
        "INSERT INTO proxy_links (server, port, proxy_url, source) VALUES (?, ?, ?, ?) " +
        "ON CONFLICT(server, port) DO UPDATE SET proxy_url=excluded.proxy_url, source=excluded.source"
      ).bind(link.server, link.port, link.url, link.source));
      batch.push(env.DB.prepare(
        "INSERT INTO proxy_status_cache (server, port, status, latency_ms, checked_at) VALUES (?, ?, ?, ?, ?) " +
        "ON CONFLICT(server, port) DO UPDATE SET status=excluded.status, latency_ms=excluded.latency_ms, checked_at=excluded.checked_at"
      ).bind(status.server, status.port, status.status, status.latencyMs, checkedAt));
    }
    await env.DB.batch(batch);
  }

  await env.DB.prepare(
    "DELETE FROM proxy_links WHERE NOT EXISTS (SELECT 1 FROM proxy_status_cache c WHERE c.server=proxy_links.server AND c.port=proxy_links.port AND c.checked_at=?)"
  ).bind(checkedAt).run();
  await env.DB.prepare("DELETE FROM proxy_status_cache WHERE checked_at <> ?").bind(checkedAt).run();

  const sourceHealthWrites = sourceResults.map(item => {
    const sourceLinks = item.links ? Array.from(item.links.values()) : [];
    const checkedIndexes = [];
    for (let i = 0; i < selected.length; i++) {
      if (selected[i].source === item.source.name) checkedIndexes.push(i);
    }
    const sourceOnline = checkedIndexes.filter(i => checked[i]?.status === "online").length;
    const sourceOffline = checkedIndexes.length - sourceOnline;
    const status = item.links.size ? "ok" : "error";
    return env.DB.prepare(
      "INSERT INTO proxy_source_health (source, url, status, http_status, bytes, parsed_count, checked_count, online_count, offline_count, checked_at, error) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(source) DO UPDATE SET " +
      "url=excluded.url, status=excluded.status, http_status=excluded.http_status, bytes=excluded.bytes, parsed_count=excluded.parsed_count, " +
      "checked_count=excluded.checked_count, online_count=excluded.online_count, offline_count=excluded.offline_count, checked_at=excluded.checked_at, error=excluded.error"
    ).bind(item.source.name, item.source.url, status, item.error ? null : 200, item.feed.length, sourceLinks.length,
      checkedIndexes.length, sourceOnline, sourceOffline, checkedAt, item.error);
  });
  await env.DB.batch(sourceHealthWrites);

  const fingerprint = loaded.map(item => item.source.url + "\n" + item.feed).join("\n---\n");
  const feedHash = await hashProxyFeed(fingerprint);
  await env.DB.prepare(
    "INSERT INTO proxy_status_meta (id, feed_hash, checked_at, target_count) VALUES (1, ?, ?, ?) " +
    "ON CONFLICT(id) DO UPDATE SET feed_hash=excluded.feed_hash, checked_at=excluded.checked_at, target_count=excluded.target_count"
  ).bind(feedHash, checkedAt, checked.length).run();

  return {
    changed: true,
    targetCount: checked.length,
    onlineCount: checked.filter(item => item.status === "online").length,
    sourceCount: loaded.length,
    checkedAt
  };
}

async function runLockedProxyRefresh(env) {
  const startedAt = new Date().toISOString();
  const staleBefore = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const lock = await env.DB.prepare(
    "INSERT INTO proxy_refresh_lock (id, started_at) VALUES (1, ?) " +
    "ON CONFLICT(id) DO UPDATE SET started_at=excluded.started_at WHERE proxy_refresh_lock.started_at < ?"
  ).bind(startedAt, staleBefore).run();
  if (Number(lock.meta?.changes || 0) !== 1) return { skipped: true };
  try {
    return await refreshProxyStatusCache(env);
  } finally {
    await env.DB.prepare("DELETE FROM proxy_refresh_lock WHERE id=1 AND started_at=?").bind(startedAt).run();
  }
}

async function getVerifiedProxyFeed(env, ctx) {
  const pendingMessage = "Каталог прокси обновляется. Страница сайта проверит результат автоматически.\n";
  if (!env.DB) return new Response("База каталога пока недоступна.\n", { status: 503, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });

  const lock = await env.DB.prepare("SELECT started_at FROM proxy_refresh_lock WHERE id=1").first();
  const lockStartedAt = lock?.started_at ? Date.parse(lock.started_at) : NaN;
  const refreshInProgress = Number.isFinite(lockStartedAt) && Date.now() - lockStartedAt < 10 * 60 * 1000;
  const meta = await env.DB.prepare("SELECT checked_at FROM proxy_status_meta WHERE id=1").first();
  const checkedAt = meta?.checked_at ? Date.parse(meta.checked_at) : NaN;

  if (refreshInProgress) {
    return new Response(pendingMessage, {
      status: 503,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Proxy-Refresh": "pending" }
    });
  }

  if (!Number.isFinite(checkedAt) || Date.now() - checkedAt > PROXY_CACHE_MAX_AGE_MS) {
    if (ctx?.waitUntil) ctx.waitUntil(runLockedProxyRefresh(env).catch(error => console.error("Proxy refresh failed:", error)));
    return new Response(pendingMessage, {
      status: 503,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Proxy-Refresh": "pending" }
    });
  }
  const rows = await env.DB.prepare(
    "SELECT l.proxy_url FROM proxy_links l JOIN proxy_status_cache c ON c.server=l.server AND c.port=l.port " +
    "WHERE c.status='online' AND c.checked_at=? ORDER BY COALESCE(c.latency_ms,2147483647)"
  ).bind(meta.checked_at).all();
  return new Response((rows.results || []).map(row => row.proxy_url).join("\n"), {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Proxy-Count": String(rows.results?.length || 0),
      "X-Proxy-Checked-At": meta.checked_at
    }
  });
}

async function getCachedProxyStatuses(env) {
  if (!env.DB) return json({ error: "Database binding DB is not configured." }, 503);
  const [meta, rows] = await Promise.all([
    env.DB.prepare("SELECT checked_at, target_count FROM proxy_status_meta WHERE id = 1").first(),
    env.DB.prepare("SELECT server, port, status, latency_ms AS latencyMs FROM proxy_status_cache ORDER BY server, port").all()
  ]);
  return json({
    results: rows.results || [],
    checkedAt: meta?.checked_at || null,
    targetCount: meta?.target_count || 0,
    ready: Boolean(meta?.checked_at)
  });
}

async function getHealth(env) {
  if (!env.DB) return json({ ok: false, error: "D1 binding DB is not configured." }, 503);
  const [meta, rows, sources, lock] = await Promise.all([
    env.DB.prepare("SELECT checked_at, target_count FROM proxy_status_meta WHERE id=1").first(),
    env.DB.prepare("SELECT status, COUNT(*) AS count FROM proxy_status_cache GROUP BY status").all(),
    env.DB.prepare("SELECT source, url, status, http_status AS httpStatus, bytes, parsed_count AS parsedCount, checked_count AS checkedCount, online_count AS onlineCount, offline_count AS offlineCount, checked_at AS checkedAt, error FROM proxy_source_health ORDER BY source").all(),
    env.DB.prepare("SELECT started_at FROM proxy_refresh_lock WHERE id=1").first()
  ]);
  const counts = Object.fromEntries((rows.results || []).map(row => [row.status, Number(row.count || 0)]));
  const sourceRows = sources.results || [];
  const online = counts.online || 0;
  const offline = counts.offline || 0;
  return json({
    ok: true,
    service: "Proxy Sait",
    checkedAt: meta?.checked_at || null,
    refreshing: Boolean(lock?.started_at && Date.now() - Date.parse(lock.started_at) < 10 * 60 * 1000),
    summary: {
      configuredSources: PROXY_SOURCES.length,
      sourcesOk: sourceRows.filter(item => item.status === "ok").length,
      sourcesFailed: sourceRows.filter(item => item.status !== "ok").length,
      uniqueChecked: Number(meta?.target_count || 0),
      online,
      offline,
      onlinePercent: meta?.target_count ? Math.round(online / Number(meta.target_count) * 100) : 0
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
  if (path === "/api/proxy-status" && method === "GET") {
    return getCachedProxyStatuses(env);
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

    const task = refreshProxyStatusCache(env).then(result => {
      console.log("Manual proxy refresh completed:", result.onlineCount + "/" + result.targetCount + " online");
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
      response = url.pathname.startsWith("/api/")
        ? json({ error: "Внутренняя ошибка сервера." }, 500)
        : new Response("Internal Server Error", { status: 500 });
    }

    const headers = new Headers(response.headers);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
    if (url.pathname.startsWith("/api/")) {
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
    const meta = await env.DB.prepare("SELECT checked_at FROM proxy_status_meta WHERE id=1").first();
    const last = meta?.checked_at ? Date.parse(meta.checked_at) : NaN;
    if (Number.isFinite(last) && Date.now() - last < PROXY_REFRESH_INTERVAL_MS) return;
    const result = await runLockedProxyRefresh(env);
    if (result.changed) {
      console.log("Proxy catalog refreshed:", result.onlineCount + "/" + result.targetCount + " online", "sources=" + result.sourceCount, result.checkedAt);
    }
  }
};
