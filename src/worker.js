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
const TCP_PROBE_VERSION = "v2";

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
  // Keep below the Workers outbound-connection concurrency limit.
  const count = Math.min(4, targets.length);
  await Promise.all(Array.from({ length: count }, () => worker()));
  return results;
}


const VERIFIED_PROXY_SOURCES = [
  {
    name: "iwizard7 stable (MTProto checked within 24h)",
    url: "https://iwizard7.github.io/MTProxy_list/stable.txt"
  },
  {
    name: "0xRadikal stable (MTProto verified, >=90% recent checks)",
    url: "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/stable/tg.txt"
  }
];

async function getProxyFeed() {
  const results = await Promise.all(VERIFIED_PROXY_SOURCES.map(async source => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(source.url, {
        headers: { "Accept": "text/plain" },
        redirect: "follow",
        signal: controller.signal
      });
      if (!response.ok) throw new Error("HTTP " + response.status);
      const body = await response.text();
      if (!body.trim() || body.length > 512 * 1024) throw new Error("Empty or oversized feed");
      return { source, body };
    } catch (error) {
      console.warn("Verified proxy source failed:", source.name, error?.message || String(error));
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }));

  const good = results.filter(Boolean);
  if (!good.length) throw new Error("All verified MTProto sources are unavailable; previous cache is preserved");

  // These upstream feeds contain only links that passed real MTProto relay checks.
  // The local TCP probe below is an additional reachability filter, not a substitute for that handshake.
  const merged = good.map(item => "# " + item.source.name + "\n" + item.body.trim()).join("\n");
  if (!extractAllowedProxyTargets(merged).size) {
    throw new Error("No valid MTProto proxy links found; previous cache is preserved");
  }
  return merged;
}

async function hashProxyFeed(feed) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(feed + "\n" + TCP_PROBE_VERSION));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function refreshProxyStatusCache(env) {
  if (!env.DB) throw new Error("D1 binding DB is not configured");
  const feed = await getProxyFeed();
  const feedHash = await hashProxyFeed(feed);
  const saved = await env.DB.prepare(
    "SELECT feed_hash FROM proxy_status_meta WHERE id = 1"
  ).first();

  // Re-check even when the upstream list is unchanged: proxies can stop working between publishes.

  const targets = Array.from(extractAllowedProxyTargets(feed).values());
  if (!targets.length) throw new Error("No MTProto proxy candidates; previous cache is preserved");
  const checked = await probeTcpTargets(targets);
  const onlineCount = checked.filter(item => item.status === "online").length;
  if (!onlineCount) throw new Error("No candidate passed the local reachability check; previous cache is preserved");
  const checkedAt = new Date().toISOString();

  await env.DB.prepare("DELETE FROM proxy_status_cache").run();
  for (let offset = 0; offset < checked.length; offset += 40) {
    const batch = checked.slice(offset, offset + 40).map(item =>
      env.DB.prepare(
        "INSERT INTO proxy_status_cache (server, port, status, latency_ms, checked_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(item.server, item.port, item.status, item.latencyMs, checkedAt)
    );
    if (batch.length) await env.DB.batch(batch);
  }

  await env.DB.prepare(
    "INSERT INTO proxy_status_meta (id, feed_hash, checked_at, target_count) VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET feed_hash = excluded.feed_hash, checked_at = excluded.checked_at, target_count = excluded.target_count"
  ).bind(feedHash, checkedAt, checked.length).run();

  return { changed: true, targetCount: checked.length, onlineCount, checkedAt };
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

  let feedResponse;
  try {
    feedResponse = await env.ASSETS.fetch(new Request(new URL("/proxies.txt", url), {
      method: "GET",
      headers: { "Accept": "text/plain" }
    }));
  } catch (_) {
    return json({ error: "Не удалось получить список серверов." }, 503);
  }
  if (!feedResponse.ok) return json({ error: "Не удалось получить список серверов." }, 503);

  const allowed = extractAllowedProxyTargets(await feedResponse.text());
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

async function handleApi(request, env, url) {
  const path = url.pathname;
  const method = request.method;
  if (path === "/api/proxy-status" && method === "GET") {
    return getCachedProxyStatuses(env);
  }
  if (!env.DB) return json({ error: "Database binding DB is not configured." }, 503);

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
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.protocol !== "https:") {
      url.protocol = "https:";
      return Response.redirect(url.toString(), 301);
    }

    let response;
    try {
      if (url.pathname.startsWith("/api/")) {
        if (request.method !== "GET" && request.method !== "POST") {
          response = json({ error: "Method not allowed." }, 405, { "Allow": "GET, POST" });
        } else {
          response = await handleApi(request, env, url);
        }
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
    // Await the job so Cron reports failures instead of silently swallowing them.
    const result = await refreshProxyStatusCache(env);
    if (result.changed) {
      console.log("Proxy status cache refreshed:", result.targetCount, result.checkedAt);
    }
  }
};
