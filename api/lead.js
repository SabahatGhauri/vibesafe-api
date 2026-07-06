// VibeSafe lead capture — stores an interested visitor's email so it can be
// converted to a paid plan later. Privacy-safe: email + where/what they opted in.

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// Basic email shape check — good enough to reject junk without being strict.
function validEmail(e) {
  return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 200;
}

// naive per-instance rate limit: 5 submissions/min per IP
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear();
  return arr.length > 5;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const body = req.body || {};

    // Honeypot: real forms never fill this hidden field — bots do.
    // Pretend success so the bot moves on.
    if (body.website) return res.status(200).json({ ok: true, stored: true });

    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
    if (limited(ip)) return res.status(429).json({ ok: false, error: 'Too many submissions — try again in a minute.' });

    const email = String(body.email || '').trim().toLowerCase();
    if (!validEmail(email)) return res.status(400).json({ ok: false, error: 'Enter a valid email.' });

    // If analytics/storage isn't configured, don't hard-fail the visitor.
    if (!SERVICE_KEY) return res.status(200).json({ ok: true, stored: false });

    // Duplicate suppression: same email within 7 days is a no-op (still "ok").
    const since = new Date(Date.now() - 7 * 86400e3).toISOString();
    const dupRes = await fetch(
      `${SUPABASE_URL}/rest/v1/leads?email=eq.${encodeURIComponent(email)}&created_at=gte.${since}&select=id&limit=1`,
      { headers: { 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}` } }
    );
    if (dupRes.ok) {
      const dups = await dupRes.json();
      if (dups.length) return res.status(200).json({ ok: true, stored: true, duplicate: true });
    }

    const row = {
      email,
      name: body.name ? String(body.name).trim().slice(0, 80) : null,
      source: body.source ? String(body.source).slice(0, 40) : 'website',
      magnet: body.magnet ? String(body.magnet).slice(0, 80) : null,
    };

    const r = await fetch(`${SUPABASE_URL}/rest/v1/leads`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SERVICE_KEY,
        'Authorization': `Bearer ${SERVICE_KEY}`,
        'Prefer': 'return=minimal',
      },
      body: JSON.stringify(row),
    });

    if (!r.ok) return res.status(200).json({ ok: true, stored: false });
    return res.status(200).json({ ok: true, stored: true });
  } catch (err) {
    return res.status(200).json({ ok: true, stored: false });
  }
}
