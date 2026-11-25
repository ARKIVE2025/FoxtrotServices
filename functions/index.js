// Foxtrot quote endpoint.
//
// POST (public, no key): the website quote form sends a quote here.
//   A key in the page source would be public anyway, so the public side
//   relies on validation, a honeypot field and a light rate limit.
//   Accepted quotes are stored in Firestore collection "foxtrotQuotes"
//   with status "new" for Muse to pick up.
//
// GET (key-guarded): Muse reads new quotes with the x-foxtrot-key header.
//   The key lives in the FOXTROT_KEY secret, never in this repo.
//   A keyless/wrong-key request gets 401; an unconfigured secret gets 503.
//
// Deploy: firebase deploy --only functions:quote
//   (from this functions/ directory, with .firebaserc pointing at the
//   Firebase project — see README.md)
"use strict";

const functions = require("firebase-functions");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");

const foxtrotKey = defineSecret("FOXTROT_KEY");
admin.initializeApp();
const db = admin.firestore();

const SITE_ORIGIN = "https://arkive2025.github.io";
const COLLECTION = "foxtrotQuotes";
const MAX_PER_HOUR_PER_IP = 10;
const MAX_LEN = { name: 100, email: 120, phone: 40, address: 200, message: 2000 };
const ALLOWED_SERVICES = [
  "Camera installation",
  "Digital Safety Checkup",
  "Phone scam & fraud protection",
  "Passwords & identity protection",
  "Wi-Fi or router help",
  "Smart TV or device setup",
  "Phone or tablet help",
  "Minor home service",
  "Not sure",
];
const ALLOWED_CONTACT = ["Phone call", "Text message", "Email"];
const ALLOWED_PAYMENT = ["Pay once", "Monthly plan", "Not sure"];
const ALLOWED_CAMERAS = ["0", "1", "2", "3", "4 or more"];
const ALLOWED_AUTHORITY = ["Yes, I own it", "Yes, I have written permission", "No"];

// Best-effort per-IP rate limit (in-memory; fine for a beta form).
const hits = new Map(); // ip -> [epoch ms]
function rateLimited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < 3600 * 1000);
  if (list.length >= MAX_PER_HOUR_PER_IP) return true;
  list.push(now);
  hits.set(ip, list);
  return false;
}

function setCors(req, res) {
  res.set("Access-Control-Allow-Origin", SITE_ORIGIN);
  res.set("Access-Control-Allow-Headers", "Content-Type, x-foxtrot-key");
  res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
}

function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd) return fwd.split(",")[0].trim();
  return req.ip || "unknown";
}

function clean(v, max) {
  if (typeof v !== "string") return "";
  return v.trim().slice(0, max);
}

function parseBody(req) {
  const ct = String(req.headers["content-type"] || "");
  if (ct.includes("application/json")) {
    return req.body && typeof req.body === "object" ? req.body : {};
  }
  if (ct.includes("application/x-www-form-urlencoded")) {
    const raw = typeof req.body === "string" ? req.body : "";
    const out = {};
    for (const [k, v] of new URLSearchParams(raw)) out[k] = v;
    return out;
  }
  return req.body && typeof req.body === "object" ? req.body : {};
}

function validate(b) {
  const name = clean(b.name, MAX_LEN.name);
  const email = clean(b.email, MAX_LEN.email);
  const phone = clean(b.phone, MAX_LEN.phone);
  const address = clean(b.address, MAX_LEN.address);
  const message = clean(b.message, MAX_LEN.message);
  if (!name) return { error: "Please enter your name." };
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { error: "Please enter a valid email address." };
  }
  if (!phone) return { error: "Please enter a phone number." };
  if (!address) return { error: "Please enter the service address." };
  if (b.service && !ALLOWED_SERVICES.includes(b.service)) {
    return { error: "Please choose a service from the list." };
  }
  if (b.contact_method && !ALLOWED_CONTACT.includes(b.contact_method)) {
    return { error: "Please choose how we should reach you." };
  }
  if (b.payment && !ALLOWED_PAYMENT.includes(b.payment)) {
    return { error: "Please choose a payment preference." };
  }
  if (b.cameras && !ALLOWED_CAMERAS.includes(String(b.cameras))) {
    return { error: "Please choose the number of cameras." };
  }
  if (b.authority && !ALLOWED_AUTHORITY.includes(b.authority)) {
    return { error: "Please answer the home-permission question." };
  }
  if (b.consent !== true && b.consent !== "on" && b.consent !== "true") {
    return { error: "Please agree that Foxtrot may contact you." };
  }
  return {
    value: {
      name,
      email,
      phone,
      address,
      contact_method: b.contact_method || "",
      service: b.service || "Not sure",
      cameras: String(b.cameras || "0"),
      payment: b.payment || "Not sure",
      authority: b.authority || "",
      message,
      status: "new",
      source: "website",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    },
  };
}

async function handlePost(req, res) {
  const ip = clientIp(req);
  if (rateLimited(ip)) {
    return res.status(429).json({ ok: false, error: "Too many requests. Please try again later." });
  }
  const body = parseBody(req);
  if (body.company) return res.json({ ok: true }); // honeypot: pretend success, store nothing
  const v = validate(body);
  if (v.error) return res.status(400).json({ ok: false, error: v.error });
  try {
    const ref = await db.collection(COLLECTION).add(v.value);
    return res.json({ ok: true, id: ref.id });
  } catch (e) {
    functions.logger.error("quote store failed", e);
    return res.status(500).json({ ok: false, error: "Could not save your request. Please call 256-749-5464." });
  }
}

async function handleGet(req, res) {
  const key = process.env.FOXTROT_KEY;
  if (!key) {
    return res.status(503).json({ ok: false, error: "Quote read is not configured yet." });
  }
  if (req.headers["x-foxtrot-key"] !== key) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  try {
    const snap = await db
      .collection(COLLECTION)
      .orderBy("createdAt", "desc")
      .limit(100)
      .get();
    const quotes = snap.docs.map((d) => {
      const data = d.data();
      return {
        id: d.id,
        ...data,
        createdAt: data.createdAt && data.createdAt.toDate ? data.createdAt.toDate().toISOString() : null,
      };
    });
    return res.json({ ok: true, quotes });
  } catch (e) {
    functions.logger.error("quote read failed", e);
    return res.status(500).json({ ok: false, error: "Could not read quotes." });
  }
}

exports.quote = functions.runWith({ secrets: [foxtrotKey] }).https.onRequest((req, res) => {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(204).send("");
  if (req.method === "POST") return handlePost(req, res);
  if (req.method === "GET") return handleGet(req, res);
  return res.status(405).json({ ok: false, error: "Method not allowed." });
});
