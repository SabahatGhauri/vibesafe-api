// VibeSafe URL/DAST Scanner — Vercel Serverless Function
// Fetches a live URL and checks security headers, HTTPS, exposed paths, and AI-analyses the response.

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_hgCpN6tsYqEiCkyvJm06qQ_1Ddlvznn';
const FREE_SCAN_LIMIT = 3;

const DAST_PROMPT = `You are VibeSafe — a runtime security scanner for non-technical founders.

You have been given the results of a live HTTP scan of a deployed web application. Analyse all the data and identify security issues.

You MUST respond with valid JSON only. No markdown, no explanation outside the JSON.

Return this exact structure:
{
  "score": <number 0-100, where 100 = perfectly secure>,
  "summary": "<one sentence overall assessment of this deployment's security posture>",
  "issues": [
    {
      "id": <unique number>,
      "severity": "critical" | "warning" | "info",
      "type": "<short category>",
      "title": "<clear issue title>",
      "description": "<plain-English explanation of what the issue is and why it matters. Max 2 sentences.>",
      "impact": "<what an attacker could do — one sentence>",
      "fix": "<what the developer should do to fix this — one sentence>"
    }
  ],
  "passed": [
    "<one security check this deployment passes>",
    "<another if applicable>"
  ]
}

CHECK FOR THESE IN ORDER OF PRIORITY:
1. HTTPS — is the site served over HTTPS? HTTP only is CRITICAL.
2. Missing security headers:
   - Content-Security-Policy (CSP) — missing = WARNING
   - Strict-Transport-Security (HSTS) — missing = WARNING
   - X-Frame-Options or CSP frame-ancestors — missing = WARNING (clickjacking)
   - X-Content-Type-Options: nosniff — missing = INFO
   - Referrer-Policy — missing = INFO
   - Permissions-Policy — missing = INFO
3. Server/technology fingerprinting — Server, X-Powered-By, X-AspNet-Version headers exposing stack = WARNING
4. Cookies without Secure or HttpOnly flags — CRITICAL if session cookie, WARNING otherwise
5. Sensitive paths exposed — /admin, /.env, /api/keys, /config, /wp-admin accessible = CRITICAL
6. CORS misconfiguration — Access-Control-Allow-Origin: * on an authenticated app = WARNING
7. Mixed content — HTTPS page loading HTTP resources = WARNING
8. Caching of sensitive responses — Cache-Control missing on authenticated endpoints = WARNING
9. Rate limiting absent — no X-RateLimit headers on API endpoints = INFO

SCORING:
- Start at 100
- Subtract 20 for each critical
- Subtract 8 for each warning
- Subtract 3 for each info
- Minimum 5

Only return the JSON object. Nothing else.`;

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

  const start = new Date();
  start.setDate(1); start.setHours(0, 0, 0, 0);
  const countRes = await fetch(
    `${SUPABASE_URL}/rest/v1/scans?user_id=eq.${userId}&created_at=gte.${start.toISOString()}&select=id`,
    { headers: { 'Authorization': `Bearer ${token}`, 'apikey': SUPABASE_ANON_KEY, 'Prefer': 'count=exact' } }
  );
  const countHeader = countRes.headers.get('content-range') || '';
  const count = parseInt(countHeader.split('/')[1] || '0', 10);

  if (count >= FREE_SCAN_LIMIT) {
    return { error: `You have used all ${FREE_SCAN_LIMIT} free scans this month. Upgrade to Pro for unlimited scans.` };
  }
  return { userId, plan };
}

async function probeSensitivePaths(baseUrl) {
  const paths = ['/.env', '/admin', '/api/keys', '/config.json', '/wp-admin', '/.git/config'];
  const exposed = [];
  await Promise.all(paths.map(async (path) => {
    try {
      const r = await fetch(baseUrl + path, { method: 'HEAD', redirect: 'manual',
        signal: AbortSignal.timeout(4000) });
      if (r.status === 200) exposed.push(path);
    } catch { /* ignore */ }
  }));
  return exposed;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const limitCheck = await getUserAndCheckLimit(req);
    if (limitCheck.error) return res.status(403).json({ error: limitCheck.error });

    let { url } = req.body || {};
    if (!url || typeof url !== 'string') return res.status(400).json({ error: 'No URL provided.' });

    url = url.trim();
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

    let targetUrl;
    try { targetUrl = new URL(url); }
    catch { return res.status(400).json({ error: 'Invalid URL.' }); }

    // Block private/internal addresses
    const host = targetUrl.hostname;
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) {
      return res.status(400).json({ error: 'Cannot scan private/internal addresses.' });
    }

    // Fetch the live URL
    let httpRes;
    try {
      httpRes = await fetch(url, {
        method: 'GET',
        redirect: 'follow',
        signal: AbortSignal.timeout(10000),
        headers: { 'User-Agent': 'VibeSafe-Security-Scanner/1.0' }
      });
    } catch (err) {
      return res.status(400).json({ error: `Could not reach ${url}. Make sure the site is live and accessible.` });
    }

    // Collect headers
    const headers = {};
    httpRes.headers.forEach((val, key) => { headers[key] = val; });

    // Probe sensitive paths in parallel with body read
    const baseUrl = `${targetUrl.protocol}//${targetUrl.host}`;
    const [bodyText, exposedPaths] = await Promise.all([
      httpRes.text().then(t => t.slice(0, 8000)).catch(() => ''),
      probeSensitivePaths(baseUrl),
    ]);

    const isHttps = targetUrl.protocol === 'https:';
    const finalUrl = httpRes.url || url;
    const wasRedirectedToHttps = !isHttps && finalUrl.startsWith('https://');

    // Build scan context for Claude
    const scanContext = `
URL scanned: ${url}
Final URL after redirects: ${finalUrl}
HTTP status: ${httpRes.status}
Protocol: ${targetUrl.protocol}
Redirected to HTTPS: ${wasRedirectedToHttps}

RESPONSE HEADERS:
${Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n')}

SENSITIVE PATHS PROBED (200 = exposed):
${exposedPaths.length > 0 ? exposedPaths.map(p => `EXPOSED: ${baseUrl}${p}`).join('\n') : 'None exposed'}

RESPONSE BODY EXCERPT (first 8000 chars):
${bodyText}
`.trim();

    // Claude analysis
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 2048,
        system: DAST_PROMPT,
        messages: [{ role: 'user', content: scanContext }],
      }),
    });

    if (!anthropicRes.ok) {
      const err = await anthropicRes.json().catch(() => ({}));
      return res.status(500).json({ error: err.error?.message || 'AI analysis failed.' });
    }

    const anthropicData = await anthropicRes.json();
    const rawText = anthropicData.content?.[0]?.text || '{}';

    let result;
    try {
      result = JSON.parse(rawText);
    } catch {
      const match = rawText.match(/\{[\s\S]*\}/);
      result = match ? JSON.parse(match[0]) : { score: 0, summary: 'Parse error', issues: [], passed: [] };
    }

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

    return res.status(200).json({ ...result, url, finalUrl, headers });

  } catch (err) {
    console.error('scan-url error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
}
