// Geodude email relay — Vercel serverless function at /api/send
// Holds the Resend key server-side and performs the actual send so that
// sandboxed / browser callers (blocked egress or CORS) can still send mail.

export default async function handler(req, res) {
  // --- Permissive CORS so this can be called from a browser or web_fetch ---
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed. Use POST." });
  }

  const SHARED_SECRET = process.env.SHARED_SECRET;
  const RESEND_API_KEY = process.env.RESEND_API_KEY;
  if (!SHARED_SECRET || !RESEND_API_KEY) {
    return res
      .status(500)
      .json({ error: "Server not configured: missing SHARED_SECRET or RESEND_API_KEY." });
  }

  // --- Parse JSON body (Vercel may hand us an object or a raw string) ---
  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }
  body = body || {};

  // --- Shared-secret check: body.token OR "Authorization: Bearer <secret>" ---
  const authHeader = req.headers["authorization"] || "";
  const bearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  const token = body.token || bearer;
  if (token !== SHARED_SECRET) {
    return res.status(401).json({ error: "Unauthorized: bad or missing token." });
  }

  const { to, cc, subject, html } = body;
  if (!to || !subject) {
    return res.status(400).json({ error: "Missing required fields: 'to' and 'subject'." });
  }

  try {
    // --- Determine a VERIFIED sending domain from the Resend account ---
    const domResp = await fetch("https://api.resend.com/domains", {
      headers: { Authorization: `Bearer ${RESEND_API_KEY}` },
    });
    const domData = await domResp.json();
    const domains = domData && Array.isArray(domData.data) ? domData.data : [];
    const verified = domains.find((d) => d.status === "verified") || domains[0];
    if (!verified) {
      return res
        .status(500)
        .json({ error: "No verified domain found in this Resend account.", domains: domData });
    }
    const from = `Geodude <geodude@${verified.name}>`;

    // --- Send via Resend ---
    const payload = { from, to, subject, html: html || "" };
    if (cc) payload.cc = cc;

    const sendResp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const sendData = await sendResp.json();

    if (!sendResp.ok) {
      return res.status(sendResp.status).json({ error: sendData, from });
    }
    // Success — include the id and the from-address actually used.
    return res.status(200).json({ ...sendData, from });
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
}
