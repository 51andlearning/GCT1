/* Vercel Edge Middleware for the GCT Group proposal site.
   Two jobs:
     1. Server side access code gate, so no page HTML reaches an
        unauthenticated visitor. The code lives in GATE_CODE, never here.
     2. The signing API used by mvno-light.html, handled here rather
        than as a separate function so the static build config is
        left alone.
   Added 2026-08-31, signing API added 2026-09-09. */
import { next } from "@vercel/edge";

/* The access code is shareable, because MVNE gives it to GCT Group, but it is
   still a credential, so it lives in GATE_CODE and never in this file. When it
   is unset the gate refuses everyone rather than falling open. Compared case
   insensitively and in constant time, so it cannot be recovered a character at
   a time. */
const PIN = (process.env.GATE_CODE || "").trim().toLowerCase();
const GATE_READY = PIN.length >= 4;

/* The session cookie. The __Host- prefix binds it to this exact host over
   HTTPS with Path=/, so no sibling or parent host can plant one. Rotating
   TOKEN signs every existing session out. */
const COOKIE = "__Host-gct_access";
const TOKEN = "gct-2026-a41f7c08b9d2e653";

/* Signs the one time codes and the signing records. Unlike the access code
   this is a real secret, so an unset value refuses to sign rather than
   falling back to a value that sits in the repository. */
const SECRET = process.env.SIGNING_SECRET || "";
const SIGNING_READY = SECRET.length >= 16;
const RESEND_KEY = process.env.RESEND_API_KEY || "";
const FROM_EMAIL = process.env.SIGN_FROM_EMAIL || "";
const NOTIFY_EMAIL = process.env.SIGN_NOTIFY_EMAIL || "edwardw@mvne.co.za";
const MAIL_READY = Boolean(RESEND_KEY && FROM_EMAIL && SIGNING_READY);

const OTP_TTL = 600;      // seconds a verification code stays valid
const VERIFIED_TTL = 1800; // seconds a verified email stays valid for signing

export const config = { matcher: "/((?!favicon).*)" };

/* ---------- small helpers ---------- */

const enc = new TextEncoder();

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64url(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function hmacHex(message) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

/* Compares two strings without leaking their difference through timing. */
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function readCookie(req, name) {
  const raw = req.headers.get("cookie") || "";
  for (const part of raw.split(/;\s*/)) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq) === name) return part.slice(eq + 1);
  }
  return null;
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers }
  });
}

function sixDigitCode() {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return String(buf[0] % 1000000).padStart(6, "0");
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const clip = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");
const escapeHtml = s => String(s == null ? "" : s)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

/* ---------- email delivery via Resend ----------
   Returns true only when the provider accepted the message. */
async function sendMail({ to, subject, html, attachments }) {
  if (!MAIL_READY) return false;
  try {
    const body = { from: FROM_EMAIL, to: Array.isArray(to) ? to : [to], subject, html };
    if (attachments && attachments.length) body.attachments = attachments;
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return res.ok;
  } catch (e) {
    return false;
  }
}

/* ---------- who is calling, and how often ----------

   On Vercel the edge sets x-vercel-forwarded-for itself, so a caller cannot
   choose it. x-forwarded-for can be appended to by the caller, so it is only
   a last resort and only its first hop is taken. */
function clientAddress(req) {
  const vercel = req.headers.get("x-vercel-forwarded-for");
  if (vercel) return vercel.split(",")[0].trim();
  const real = req.headers.get("x-real-ip");
  if (real) return real.trim();
  const fwd = req.headers.get("x-forwarded-for");
  return fwd ? fwd.split(",")[0].trim() : "unknown";
}

/* Attempts are counted in memory, per edge instance. A shared store would
   count globally, but an edge middleware has none, and a per instance count
   still turns a fast guessing run into a slow one. The limiter degrades to
   allowing the request rather than failing the route. */
const WINDOW_MS = 60000;   // attempts are counted over one minute
const MAX_TRIES = 6;       // per address, per window
const attempts = new Map();

function tooManyAttempts(addr) {
  try {
    const now = Date.now();
    if (attempts.size > 4000) attempts.clear();   // bound the memory
    const row = attempts.get(addr);
    if (!row || now > row.until) {
      // The window opens on the first failure and is never extended.
      attempts.set(addr, { count: 1, until: now + WINDOW_MS });
      return false;
    }
    row.count += 1;
    return row.count > MAX_TRIES;
  } catch (e) {
    return false;
  }
}

function clearAttempts(addr) {
  try { attempts.delete(addr); } catch (e) { /* nothing to clear */ }
}

/* ---------- signing API ---------- */

async function handleApi(req, path) {
  // An unconfigured secret refuses the call rather than signing with a value
  // that anyone reading the repository already has.
  if (!SIGNING_READY && path !== "/api/config") {
    return json({ error: "Signing is not configured on this deployment. Contact MVNE." }, 503);
  }

  if (path === "/api/config") {
    return json({ otpEnabled: MAIL_READY, signingEnabled: SIGNING_READY });
  }

  if (req.method !== "POST") return json({ error: "POST required" }, 405);

  let body;
  try { body = await req.json(); }
  catch (e) { return json({ error: "Body must be JSON" }, 400); }

  /* Issue a verification code. The code itself never leaves the server
     except by email. The cookie holds only an HMAC of it. */
  if (path === "/api/otp/request") {
    if (!MAIL_READY) return json({ delivered: false, reason: "Email delivery is not configured on this deployment." });
    const email = clip(body.email, 200).trim().toLowerCase();
    if (!EMAIL_RE.test(email)) return json({ delivered: false, reason: "That email address is not valid." }, 400);

    const code = sixDigitCode();
    const exp = Math.floor(Date.now() / 1000) + OTP_TTL;
    const mac = await hmacHex(`otp.${exp}.${email}.${code}`);
    const challenge = b64url(enc.encode(`${exp}|${email}|${mac}`));

    const sent = await sendMail({
      to: email,
      subject: "Your verification code for the GCT Group MVNO Light proposal",
      html: `<div style="font-family:Inter,Helvetica,Arial,sans-serif;color:#0F172A">
        <p>Your verification code is:</p>
        <p style="font-size:30px;font-weight:800;letter-spacing:6px;margin:18px 0">${code}</p>
        <p style="font-size:13px;color:#64748B">The code expires in 10 minutes. If you did not request it, ignore this email.</p>
        <p style="font-size:13px;color:#64748B">MVNE (Pty) Ltd</p></div>`
    });
    if (!sent) return json({ delivered: false, reason: "The email provider rejected the message." }, 502);

    return json({ delivered: true }, 200, {
      "Set-Cookie": `otp_chal=${challenge}; Path=/; Max-Age=${OTP_TTL}; HttpOnly; Secure; SameSite=Lax`
    });
  }

  /* Check a submitted code against the challenge cookie. */
  if (path === "/api/otp/verify") {
    const chal = readCookie(req, "otp_chal");
    if (!chal) return json({ ok: false, error: "No code has been requested, or it has expired." }, 400);

    let exp, email, mac;
    try {
      const parts = new TextDecoder().decode(unb64url(chal)).split("|");
      exp = Number(parts[0]); email = parts[1]; mac = parts[2];
    } catch (e) {
      return json({ ok: false, error: "The verification session is not readable. Request a new code." }, 400);
    }
    if (!exp || Math.floor(Date.now() / 1000) > exp) {
      return json({ ok: false, error: "That code has expired. Request a new one." }, 400);
    }

    const code = clip(body.code, 12).replace(/\D/g, "");
    if (code.length !== 6) return json({ ok: false, error: "Enter the six digit code." }, 400);

    const expect = await hmacHex(`otp.${exp}.${email}.${code}`);
    if (!safeEqual(expect, mac)) return json({ ok: false, error: "That code was not recognised." }, 400);

    const vexp = Math.floor(Date.now() / 1000) + VERIFIED_TTL;
    const vmac = await hmacHex(`verified.${vexp}.${email}`);
    const token = b64url(enc.encode(`${vexp}|${email}|${vmac}`));
    return json({ ok: true, email }, 200, {
      "Set-Cookie": [
        `otp_ok=${token}; Path=/; Max-Age=${VERIFIED_TTL}; HttpOnly; Secure; SameSite=Lax`,
        `otp_chal=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
      ].join(", ")
    });
  }

  /* Record a signature and return the signing certificate details. */
  if (path === "/api/sign") {
    const s = body.signatory || {};
    const name = clip(s.name, 120).trim();
    const position = clip(s.position, 120).trim();
    const company = clip(s.company, 160).trim();
    const email = clip(s.email, 200).trim();
    const mobile = clip(s.mobile, 40).trim();
    const docHash = clip((body.document || {}).hash, 128).trim();

    if (!name || !position || !company || !EMAIL_RE.test(email)) {
      return json({ error: "Signatory name, position, organisation and a valid email address are required." }, 400);
    }
    if (!/^[0-9a-f]{64}$/.test(docHash)) {
      return json({ error: "A SHA 256 document hash is required." }, 400);
    }

    // When email verification is switched on, it is mandatory.
    let verification = "site access code and signatory confirmation";
    if (MAIL_READY) {
      const tok = readCookie(req, "otp_ok");
      if (!tok) return json({ error: "Verify your email address before signing." }, 403);
      let vexp, vemail, vmac;
      try {
        const parts = new TextDecoder().decode(unb64url(tok)).split("|");
        vexp = Number(parts[0]); vemail = parts[1]; vmac = parts[2];
      } catch (e) {
        return json({ error: "The verification token is not readable. Verify your email again." }, 403);
      }
      const expect = await hmacHex(`verified.${vexp}.${vemail}`);
      if (!safeEqual(expect, vmac)) return json({ error: "The verification token is not valid." }, 403);
      if (Math.floor(Date.now() / 1000) > vexp) return json({ error: "The verification has expired. Verify your email again." }, 403);
      if (vemail !== email.toLowerCase()) return json({ error: "The verified address does not match the signatory address." }, 403);
      verification = "email one time code";
    }

    const acc = body.accepted || {};
    const services = Array.isArray(acc.services) ? acc.services.slice(0, 20) : [];
    const totals = acc.totals || {};
    const onceOff = Number(totals.onceOffUsd) || 0;
    const monthly = Number(totals.monthlyMinimumUsd) || 0;
    const serviceIds = services.map(x => clip(x.id, 40)).join(",");

    const signedAt = new Date().toISOString();
    const reference = "GCT-ML-" + signedAt.slice(0, 10).replace(/-/g, "") + "-"
      + (await hmacHex(`ref.${docHash}.${email}.${signedAt}`)).slice(0, 6).toUpperCase();

    // The canonical string is what the record signature covers. Recompute it
    // from the certificate fields with the same secret to check a record later.
    const canonical = [
      "gct-mvno-light-v1", docHash, name, position, company, email.toLowerCase(),
      signedAt, verification, serviceIds, String(onceOff), String(monthly)
    ].join("|");
    const recordSignature = await hmacHex(canonical);

    const ip = clientAddress(req);
    const rows = [
      ["Reference", reference],
      ["Signed by", `${name}, ${position}`],
      ["On behalf of", company],
      ["Email", email],
      ["Mobile", mobile || "not given"],
      ["Signed at", signedAt],
      ["Verification", verification],
      ["Document", "GCT Group MVNO Light Proposal, 9 September 2026"],
      ["Document hash", docHash],
      ["Record signature", recordSignature],
      ["Once off", "$" + onceOff.toLocaleString("en-GB")],
      ["Monthly minimum", "$" + monthly.toLocaleString("en-GB")],
      ["Services", services.length ? services.map(x => clip(x.name, 80)).join(", ") : "none selected"],
      ["Source address", ip || "not available"]
    ];
    const html = `<div style="font-family:Inter,Helvetica,Arial,sans-serif;color:#0F172A">
      <h2 style="margin:0 0 4px">MVNO Light proposal signed</h2>
      <p style="color:#64748B;font-size:13px;margin:0 0 18px">GCT Group, recorded by the MVNE signing service.</p>
      <table style="border-collapse:collapse;font-size:13px">${rows.map(([k, v]) =>
        `<tr><td style="padding:6px 14px 6px 0;color:#64748B;vertical-align:top">${escapeHtml(k)}</td>
             <td style="padding:6px 0;word-break:break-all">${escapeHtml(v)}</td></tr>`).join("")}</table>
      <p style="color:#64748B;font-size:12px;margin-top:18px">Acceptance remains subject to the two conditions
      precedent in Section 2 and to signature of a full contract and scope of work.</p></div>`;

    // The drawn or typed signature travels as a PNG attachment.
    const attachments = [];
    const img = (body.signature || {}).image;
    if (typeof img === "string" && img.startsWith("data:image/png;base64,") && img.length < 2000000) {
      attachments.push({ filename: `signature ${reference}.png`, content: img.split(",")[1] });
    }

    const delivered = await sendMail({
      to: [NOTIFY_EMAIL, email],
      subject: `GCT Group MVNO Light proposal signed, ${reference}`,
      html, attachments
    });

    return json({
      reference, signedAt, recordSignature, delivered,
      recordedBy: "MVNE signing service",
      verification: { method: verification, emailVerified: verification === "email one time code" },
      note: delivered ? null : (MAIL_READY
        ? "The certificate could not be emailed. Download it and send it on."
        : "Email delivery is not configured on this deployment. Download the certificate and send it on.")
    });
  }

  return json({ error: "Unknown endpoint" }, 404);
}

/* ---------- request handling ---------- */

function redirect(to, status = 303) {
  return new Response(null, { status, headers: { Location: to, "Cache-Control": "no-store" } });
}

export default async function middleware(req) {
  const url = new URL(req.url);
  // tolerate a trailing slash so a trailingSlash:true project cannot loop on /gate
  const path = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : url.pathname;

  // the gate page and link preview assets are served before authentication
  const PUBLIC = new Set(["/gate", "/gate.html", "/favicon.svg", "/favicon.ico",
    "/favicon.png", "/apple-touch-icon.png", "/og-image.png", "/assets/og-image.png"]);
  if (PUBLIC.has(path)) return next();

  const authed = (req.headers.get("cookie") || "")
    .split(/;\s*/).some(c => c === `${COOKIE}=${TOKEN}`);

  if (path === "/unlock") {
    // The code travels in a POST body. In a query string it would land in
    // server logs, browser history and the Referer header of the next page.
    if (req.method !== "POST") return redirect("/gate");

    // No code configured means nobody gets in, rather than everybody.
    if (!GATE_READY) return redirect("/gate?e=3");

    const addr = clientAddress(req);
    if (tooManyAttempts(addr)) return redirect("/gate?e=2");

    let submitted = "";
    try {
      const form = await req.formData();
      submitted = String(form.get("code") || "").trim().toLowerCase();
    } catch (e) {
      submitted = "";
    }

    if (submitted && safeEqual(submitted, PIN)) {
      clearAttempts(addr);
      return new Response(null, { status: 303, headers: {
        Location: "/",
        "Cache-Control": "no-store",
        "Set-Cookie": `${COOKIE}=${TOKEN}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`
      } });
    }
    return redirect("/gate?e=1");
  }

  // The signing API sits behind the same access code as the pages.
  if (path.startsWith("/api/")) {
    if (!authed) return json({ error: "Not authenticated." }, 401);
    return handleApi(req, path);
  }

  if (authed) return next();
  return redirect("/gate", 302);
}
