// VibeSafe URL/DAST Scanner — Vercel Serverless Function
// Fetches a live URL and checks security headers, HTTPS, exposed paths, and AI-analyses the response.

import { runDastScan } from '../lib/dast.js';

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_hgCpN6tsYqEiCkyvJm06qQ_1Ddlvznn';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const FREE_SCAN_LIMIT = 3;

// Privacy-safe analytics for live-URL scans (metadata only, never response bodies).
// MUST be awaited: on serverless, un-awaited fetches are killed when the response
// returns, silently dropping events.
async function recordScanEvent(fields) {
  if (!SERVICE_KEY) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/extension_events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}`, 'Prefer': 'return=minimal' },
      body: JSON.stringify(Object.assign({ source: 'website', scan_type: 'live_url' }, fields)),
    });
  } catch (e) {}
}

async function getUserAndCheckLimit(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return { error: 'Authentication required. Please sign in.' };

  const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { 'Authorization': `Bearer ${token}`, 'apikey': SUPABASE_ANON_KEY }
  });
  if (!userRes.ok) return { error: 'Session expired. Please sign in again.' };
  const userData = await userRes.json();
  const userId = userData.id;

  const planRes = await fetch(`${SUPABASE_URL}/rest/v1/vibesafe_plans?id=eq.${userId}&select=plan`, {
    headers: { 'Authorization': `Bearer ${token}`, 'apikey': SUPABASE_ANON_KEY }
  });
  const planData = await planRes.json();
  const plan = (planData[0] && planData[0].plan) || 'free';
  if (plan === 'pro' || plan === 'team') return { userId, plan };

  // Live website (DAST) scanning is a Pro feature — reject free accounts.
  return { userId, plan, upgrade: true, error: 'Live website scanning is a Pro feature. Upgrade to Pro to scan your deployed apps.' };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  let scanUserId = null;
  try {
    const limitCheck = await getUserAndCheckLimit(req);
    scanUserId = limitCheck.userId || null;
    if (limitCheck.error) {
      await recordScanEvent({ user_id: scanUserId, event: 'scan_failed', success: false, error_message: String(limitCheck.error).slice(0, 200) });
      return res.status(403).json({ error: limitCheck.error });
    }

    let { url } = req.body || {};
    if (!url || typeof url !== 'string') return res.status(400).json({ error: 'No URL provided.' });

    // Run the shared DAST scan (SSRF guard, fetch, path probe, AI analysis).
    let result;
    try {
      result = await runDastScan(url);
    } catch (e) {
      await recordScanEvent({ user_id: scanUserId, event: 'scan_failed', success: false, error_message: String(e.message || 'scan failed').slice(0, 200) });
      return res.status(400).json({ error: e.message || 'Scan failed.' });
    }
    url = result.url;
    const { finalUrl, headers } = result;

    // Save scan to Supabase
    const { userId } = limitCheck;
    await fetch(`${SUPABASE_URL}/rest/v1/scans`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${req.headers['authorization']?.replace('Bearer ', '')}`,
        'apikey': SUPABASE_ANON_KEY,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal',
      },
      body: JSON.stringify({
        user_id: userId,
        scan_type: 'url',
        target: url,
        score: result.score,
        issues_count: (result.issues || []).length,
        result: result,
      }),
    }).catch(() => {});

    await recordScanEvent({ user_id: scanUserId, event: 'scan_success', score: Number.isFinite(result.score) ? result.score : null, issues: (result.issues || []).length, success: true });
    return res.status(200).json({ ...result, url, finalUrl, headers });

  } catch (err) {
    console.error('scan-url error:', err);
    await recordScanEvent({ user_id: scanUserId, event: 'scan_failed', success: false, error_message: String(err.message || 'unexpected').slice(0, 200) });
    return res.status(500).json({ error: 'Internal server error.' });
  }
}
