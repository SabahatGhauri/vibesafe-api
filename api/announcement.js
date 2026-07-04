// VibeSafe broadcast — returns the current active announcement for the extension
// to show on startup. Read-only, metadata only. No auth required.

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();

  // No storage configured → no announcement (never break the extension).
  if (!SERVICE_KEY) return res.status(200).json({ announcement: null });

  try {
    const url = `${SUPABASE_URL}/rest/v1/announcements`
      + `?active=eq.true&select=id,message,cta_label,cta_url,audience`
      + `&order=created_at.desc&limit=1`;
    const r = await fetch(url, {
      headers: { 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}` },
    });
    if (!r.ok) return res.status(200).json({ announcement: null });
    const rows = await r.json();
    return res.status(200).json({ announcement: (rows && rows[0]) || null });
  } catch (err) {
    return res.status(200).json({ announcement: null });
  }
}
