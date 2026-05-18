// Entry point: /?go=<ENTRY_TOKEN> → gera slug HMAC e redireciona para /s/<slug>
// Caso contrário → manda para FALLBACK_URL (Google)
import crypto from "node:crypto";

const ENTRY_TOKEN = "online";
const FALLBACK_URL = "https://www.google.com";
const HMAC_SECRET = "sc-guias-2026-1167a8c9359ce493353764016606e2b20678376b1f68be2d8a0c6c319dc5af05-fixed";

function b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomNonce(len = 10) {
  const alpha = "abcdefghijkmnpqrstuvwxyz23456789";
  const bytes = crypto.randomBytes(len);
  let out = "";
  for (let i = 0; i < len; i++) out += alpha[bytes[i] % alpha.length];
  return out;
}

function hmacSign(message) {
  return b64url(crypto.createHmac("sha256", HMAC_SECRET).update(message).digest());
}

function makeSlug() {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = randomNonce(10);
  const payload = `${ts}.${nonce}`;
  return `${payload}.${hmacSign(payload)}`;
}

export default async (request) => {
  const url = new URL(request.url);
  const go = url.searchParams.get("go") || "";

  if (go !== ENTRY_TOKEN) {
    return Response.redirect(FALLBACK_URL, 302);
  }

  const slug = makeSlug();
  return new Response(null, {
    status: 302,
    headers: {
      "Location": `${url.origin}/s/${slug}`,
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    },
  });
};

export const config = { path: "/" };
