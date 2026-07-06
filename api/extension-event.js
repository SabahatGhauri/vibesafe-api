// VibeSafe extension analytics — receives privacy-safe metadata events from the
// VS Code / Cursor extension and stores them in Supabase. Never receives code.

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_hgCpN6tsYqEiCkyvJm06qQ_1Ddlvznn';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

const ALLOWED_EVENTS = new Set([
  'extension_installed', 'api_key_saved', 'extension_connected',
  'scan_started', 'scan_success', 'scan_failed',
  'invalid_api_key', 'session_expired',
  // v1.1.x funnel events
  'welcome_shown', 'connect_opened', 'offer_shown', 'offer_claimed',
  'upgrade_clicked', 'announcement_shown', 'announcement_clicked',
  'fixes_copied',
]);

// Resolve a vibesafe_sk_ key to a user id (best-effort; events still log without one).
async function resolveUserId(token) {
  if (!token || !token.startsWith('vibesafe_sk_')) return null;
  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/get_user_by_api_key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY, 'Authorization': `Bearer ${SUPABASE_ANON_KEY}` },
      body: JSON.stringify({ k: token }),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Never block the extension: if analytics isn't configured, just accept silently.
  if (!SERVICE_KEY) return res.status(200).json({ ok: true, stored: false });

  try {
    const body = req.body || {};
    const event = String(body.event || '');
    if (!ALLOWED_EVENTS.has(event)) return res.status(200).json({ ok: true, stored: false });

    const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    const userId = await resolveUserId(token);

    // Anti-inflation: scan events only count when they resolve to a real user.
    // (Real scans are recorded server-side by /api/scan; a scan_success arriving
    // here without a valid key is a spoofed/test POST — drop it silently.)
    const SCAN_EVENTS = new Set(['scan_success', 'scan_failed']);
    if (SCAN_EVENTS.has(event) && !userId) {
      return res.status(200).json({ ok: true, stored: false });
    }

    // Only metadata — hard-cap sizes and never accept code fields.
    const row = {
      user_id: userId || null,
      event,
      extension_version: body.extension_version ? String(body.extension_version).slice(0, 20) : null,
      editor: body.editor ? String(body.editor).slice(0, 30) : null,
      language: body.language ? String(body.language).slice(0, 30) : null,
      score: Number.isFinite(body.score) ? Math.max(0, Math.min(100, Math.round(body.score))) : null,
      issues: Number.isFinite(body.issues) ? Math.max(0, Math.round(body.issues)) : null,
      success: typeof body.success === 'boolean' ? body.success : null,
      error_message: body.error_message ? String(body.error_message).slice(0, 200) : null,
    };

    await fetch(`${SUPABASE_URL}/rest/v1/extension_events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SERVICE_KEY,
        'Authorization': `Bearer ${SERVICE_KEY}`,
        'Prefer': 'return=minimal',
      },
      body: JSON.stringify(row),
    });

    return res.status(200).json({ ok: true, stored: true });
  } catch (err) {
    // Analytics must never break the extension — swallow errors.
    return res.status(200).json({ ok: true, stored: false });
  }
}
