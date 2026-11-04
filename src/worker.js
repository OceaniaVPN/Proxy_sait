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
async function handleApi(request, env, url) {
  if (!env.DB) return json({ error: "Database binding DB is not configured." }, 503);
  const path = url.pathname;
  const method = request.method;

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
  }
};
