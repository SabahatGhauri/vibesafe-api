// Shared live-URL (DAST) scanner. Used by api/scan-url.js (on-demand, user-facing)
// and api/monitor-scan.js (weekly cron for continuous monitoring).
// Fetches a live URL, checks headers/HTTPS/exposed paths, and AI-analyses the response.
// Never stores or returns response bodies beyond the transient scan.

import { assertPublicUrl } from './netguard.js';

export const DAST_PROMPT = `You are VibeSafe — a runtime security scanner for non-technical founders.

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

async function probeSensitivePaths(baseUrl) {
  const paths = ['/.env', '/admin', '/api/keys', '/config.json', '/wp-admin', '/.git/config'];
  const exposed = [];
  await Promise.all(paths.map(async (path) => {
    try {
      const r = await fetch(baseUrl + path, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(4000) });
      if (r.status === 200) exposed.push(path);
    } catch { /* ignore */ }
  }));
  return exposed;
}

// Runs a full DAST scan of `rawUrl`. Throws Error(message) on unreachable/blocked URLs
// or AI failure. Returns { score, summary, issues, passed, url, finalUrl, headers }.
export async function runDastScan(rawUrl) {
  let url = String(rawUrl || '').trim();
  if (!url) throw new Error('No URL provided.');
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  let targetUrl;
  try { targetUrl = new URL(url); }
  catch { throw new Error('Invalid URL.'); }

  // Block private/internal addresses (resolves DNS, checks v4+v6+metadata ranges)
  await assertPublicUrl(targetUrl);

  let httpRes;
  try {
    httpRes = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
      headers: { 'User-Agent': 'VibeSafe-Security-Scanner/1.0' },
    });
  } catch (err) {
    throw new Error(`Could not reach ${url}. Make sure the site is live and accessible.`);
  }

  const headers = {};
  httpRes.headers.forEach((val, key) => { headers[key] = val; });

  const baseUrl = `${targetUrl.protocol}//${targetUrl.host}`;
  const [bodyText, exposedPaths] = await Promise.all([
    httpRes.text().then(t => t.slice(0, 8000)).catch(() => ''),
    probeSensitivePaths(baseUrl),
  ]);

  // Re-validate after redirects — a public URL must not have bounced us to internal space.
  try {
    const finalCheck = new URL(httpRes.url || url);
    if (finalCheck.hostname !== targetUrl.hostname) await assertPublicUrl(finalCheck);
  } catch (e) {
    throw new Error('The site redirected to a private/internal address — scan blocked.');
  }

  const isHttps = targetUrl.protocol === 'https:';
  const finalUrl = httpRes.url || url;
  const wasRedirectedToHttps = !isHttps && finalUrl.startsWith('https://');

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
    throw new Error(err.error?.message || 'AI analysis failed.');
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

  return { ...result, url, finalUrl, headers };
}
