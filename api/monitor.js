// VibeSafe Continuous Monitoring — user-facing CRUD for watched URLs.
//   GET    → list the signed-in user's watched URLs
//   POST   → add a URL to watch   { url, label? }   (Pro/Team only)
//   DELETE → stop watching a URL  { id }
// Auth: Supabase user access token in Authorization: Bearer <token>.
// Writes go through the user's own token so RLS (owner-only) is enforced.

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_hgCpN6tsYqEiCkyvJm06qQ_1Ddlvznn';
const MAX_URLS_PRO = 5;
const MAX_URLS_TEAM = 25;

async function getUser(token) {
  if (!token) return { error: 'Authentication required. Please sign in.' };
  const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { 'Authorization': `Bearer ${token}`, 'apikey': SUPABASE_ANON_KEY },
  });
  if (!userRes.ok) return { error: 'Session expired. Please sign in again.' };
  const user = await userRes.json();
  const planRes = await fetch(`${SUPABASE_URL}/rest/v1/vibesafe_plans?id=eq.${user.id}&select=plan`, {
    headers: { 'Authorization': `Bearer ${token}`, 'apikey': SUPABASE_ANON_KEY },
  });
  const planData = await planRes.json().catch(() => []);
  const plan = (planData[0] && planData[0].plan) || 'free';
  return { userId: user.id, plan };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();

  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  const auth = { 'Authorization': `Bearer ${token}`, 'apikey': SUPABASE_ANON_KEY, 'Content-Type': 'application/json' };
  const { userId, plan, error } = await getUser(token);
  if (error) return res.status(401).json({ error });

  try {
    // ── LIST ──
    if (req.method === 'GET') {
      const r = await fetch(
        `${SUPABASE_URL}/rest/v1/monitored_urls?user_id=eq.${userId}&order=created_at.desc&select=id,url,label,active,last_score,last_criticals,last_scanned_at`,
        { headers: auth }
      );
      const urls = await r.json().catch(() => []);
      return res.status(200).json({ urls: Array.isArray(urls) ? urls : [], plan });
    }

    // ── ADD ──
    if (req.method === 'POST') {
      if (plan !== 'pro' && plan !== 'team') {
        return res.status(403).json({ error: 'Continuous monitoring is a Pro feature. Upgrade to watch your live sites.', upgrade: true });
      }
      let { url, label } = req.body || {};
      if (!url || typeof url !== 'string') return res.status(400).json({ error: 'No URL provided.' });
      url = url.trim();
      if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
      try { url = new URL(url).toString(); }
      catch { return res.status(400).json({ error: 'Invalid URL.' }); }

      // Enforce per-plan limit.
      const countRes = await fetch(`${SUPABASE_URL}/rest/v1/monitored_urls?user_id=eq.${userId}&select=id`, {
        headers: { ...auth, 'Prefer': 'count=exact' },
      });
      const range = countRes.headers.get('content-range') || '*/0';
      const existing = parseInt(range.split('/')[1], 10) || 0;
      const limit = plan === 'team' ? MAX_URLS_TEAM : MAX_URLS_PRO;
      if (existing >= limit) {
        return res.status(403).json({ error: `You can watch up to ${limit} sites on the ${plan} plan.` });
      }

      const insRes = await fetch(`${SUPABASE_URL}/rest/v1/monitored_urls`, {
        method: 'POST',
        headers: { ...auth, 'Prefer': 'return=representation,resolution=merge-duplicates' },
        body: JSON.stringify({ user_id: userId, url, label: (label || '').toString().slice(0, 80) || null }),
      });
      if (!insRes.ok) {
        const t = await insRes.text();
        // Unique violation → already watching this URL.
        if (insRes.status === 409 || t.includes('duplicate')) return res.status(200).json({ ok: true, duplicate: true });
        return res.status(500).json({ error: 'Could not save. Try again.' });
      }
      const rows = await insRes.json().catch(() => []);
      return res.status(200).json({ ok: true, url: rows[0] || null });
    }

    // ── REMOVE ──
    if (req.method === 'DELETE') {
      const id = (req.body && req.body.id) || (req.query && req.query.id);
      if (!id) return res.status(400).json({ error: 'No id provided.' });
      const delRes = await fetch(`${SUPABASE_URL}/rest/v1/monitored_urls?id=eq.${encodeURIComponent(id)}&user_id=eq.${userId}`, {
        method: 'DELETE', headers: auth,
      });
      if (!delRes.ok) return res.status(500).json({ error: 'Could not remove. Try again.' });
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('monitor error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
}
