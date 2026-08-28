// Anonymous demo scan — the only endpoint that runs a real scan without an account.
//
// Why this exists: the product's pitch is "check your code in ten seconds", but
// every scan previously required signing up first. That put a registration wall
// in front of the one thing that demonstrates value, which is a hard stop for
// someone evaluating the tool.
//
// It runs the same engine as /api/scan and returns real findings — a crippled
// demo proves nothing. What it does not do is persist results, so there is no
// history, no fixes to re-open, and nothing to come back to without an account.
//
// Abuse control, in order of cheapness: method and size checks, then the junk
// guard (both free), then the IP quota (one DB round-trip), and only then the
// model call, which is the only expensive step.

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

const DEMO_SCANS_PER_DAY = 2;      // enough to try it and retry once
const MAX_DEMO_CODE_CHARS = 12000; // ~300 lines; real scans allow more

// Trimmed copy of the scan prompt. Deliberately duplicated rather than shared:
// /api/scan is live and working, and refactoring it to export internals would
// put the paying path at risk to serve the demo. If the prompt changes there in
// a way that matters, mirror it here.
const DEMO_SYSTEM_PROMPT = `You are VibeSafe — an expert code security scanner built for non-technical founders.

Analyse the submitted code and identify ALL security vulnerabilities, runtime errors, and code quality issues.

Respond with valid JSON only. No markdown, no explanation outside the JSON:
{
  "score": <0-100 safety score>,
  "summary": "<one plain-English sentence about the overall state>",
  "issues": [
    {
      "id": <number>,
      "sev": "critical" | "warning" | "info",
      "type": "<short category, e.g. Exposed Secret>",
      "title": "<short title>",
      "line": "<line reference or empty string>",
      "desc": "<plain-English explanation, max 2 sentences>",
      "impact": "<what an attacker could do>",
      "fix": "<plain-English fix in one sentence>"
    }
  ]
}

Be accurate. Do not invent issues that are not present. If the code is clean, return an empty issues array and a high score.`;

// Mirrors the guard in /api/scan: reject obvious non-code before paying for a
// model call. A single junk token with no punctuation or keyword is not code.
function looksLikeCode(code) {
  const t = String(code || '').trim();
  if (!t) return false;
  if (/[-=(){}\[\].,;:<>/\\"'`+*%!?~^|&$#@]/.test(t)) return true;
  if (/\b(function|const|let|var|def|class|import|export|from|return|if|else|for|while|public|private|async|await|print|console|select|insert|update|create)\b/i.test(t)) return true;
  return false;
}

function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.headers['x-real-ip'] || 'unknown';
}

async function hashIp(ip) {
  const crypto = await import('crypto');
  // Keyed so the table can't be reversed with a rainbow table of the IPv4 space.
  return crypto.default.createHmac('sha256', SERVICE_KEY || 'demo').update(String(ip)).digest('hex').slice(0, 40);
}

async function overQuota(ipHash) {
  if (!SERVICE_KEY) return false; // no store configured — fail open rather than block the demo
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const url = `${SUPABASE_URL}/rest/v1/demo_scan_usage?ip_hash=eq.${ipHash}&created_at=gte.${since}&select=id`;
  const r = await fetch(url, {
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, Prefer: 'count=exact' },
  });
  if (!r.ok) return false;
  const count = parseInt((r.headers.get('content-range') || '').split('/')[1] || '0', 10);
  return count >= DEMO_SCANS_PER_DAY;
}

async function recordUse(ipHash) {
  if (!SERVICE_KEY) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/demo_scan_usage`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: SERVICE_KEY,
        Authorization: `Bearer ${SERVICE_KEY}`,
      },
      body: JSON.stringify({ ip_hash: ipHash }),
    });
  } catch (err) {
    console.error('demo-scan: could not record use:', err.message);
  }
}

// Mirrors recordScanEvent in /api/scan.js — same table, no user_id since the
// demo is anonymous. `source` carries the traffic-source tag the page sent
// (utm_source, referrer host, or 'direct'), which is the only way to answer
// "which channel actually brings people who scan" without a schema change.
// MUST be awaited on serverless, and errors must never break the demo.
async function recordScanEvent(fields) {
  if (!SERVICE_KEY) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/extension_events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: SERVICE_KEY,
        Authorization: `Bearer ${SERVICE_KEY}`,
        Prefer: 'return=minimal',
      },
      body: JSON.stringify(fields),
    });
  } catch (e) { /* analytics must never throw */ }
}

function cleanSource(s) {
  return String(s || 'direct').trim().slice(0, 60) || 'direct';
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { code = '', language = '' } = req.body || {};
  const source = cleanSource(req.body && req.body.source);

  if (!code || typeof code !== 'string' || !code.trim()) {
    return res.status(400).json({ error: 'Paste some code to scan.' });
  }
  if (code.length > MAX_DEMO_CODE_CHARS) {
    return res.status(400).json({
      error: `The demo is limited to about 300 lines. Sign up free to scan larger files.`,
      signup: true,
    });
  }
  if (!looksLikeCode(code)) {
    return res.status(400).json({ error: "That doesn't look like code — paste a file and try again." });
  }

  const ipHash = await hashIp(clientIp(req));
  if (await overQuota(ipHash)) {
    await recordScanEvent({ event: 'demo_scan_blocked', source, scan_type: 'demo', success: false, error_message: 'quota_exceeded' });
    return res.status(429).json({
      error: `You've used your ${DEMO_SCANS_PER_DAY} free demo scans for today. Create a free account for 3 scans a month, history, and one-click fixes.`,
      signup: true,
    });
  }

  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'Scan engine is not configured.' });
  }

  try {
    const claude = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 3000,
        system: [{ type: 'text', text: DEMO_SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
        messages: [{
          role: 'user',
          content: `Please scan this ${language || 'code'} for security vulnerabilities and issues:\n\n\`\`\`${language || ''}\n${code}\n\`\`\``,
        }],
      }),
    });

    if (!claude.ok) {
      console.error('demo-scan: engine error', claude.status, await claude.text());
      await recordScanEvent({ event: 'demo_scan_failed', source, scan_type: 'demo', success: false, error_message: 'Scan engine unavailable' });
      return res.status(502).json({ error: 'Scan engine unavailable. Please try again in a moment.' });
    }

    const data = await claude.json();
    const raw = ((data.content || [])[0] || {}).text || '';
    let result;
    try {
      result = JSON.parse(raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim());
    } catch {
      console.error('demo-scan: parse failure');
      await recordScanEvent({ event: 'demo_scan_failed', source, scan_type: 'demo', success: false, error_message: 'Result parse failure' });
      return res.status(502).json({ error: 'Could not read the scan result. Please try again.' });
    }

    // Only counts a use once the scan actually succeeded — a failed attempt
    // shouldn't consume someone's quota.
    await recordUse(ipHash);
    await recordScanEvent({
      event: 'demo_scan_success',
      source,
      scan_type: 'demo',
      language: language || null,
      score: typeof result.score === 'number' ? result.score : null,
      issues: Array.isArray(result.issues) ? result.issues.length : null,
      success: true,
    });

    return res.status(200).json({
      score: result.score,
      summary: result.summary,
      issues: Array.isArray(result.issues) ? result.issues : [],
      demo: true,
      remaining: Math.max(0, DEMO_SCANS_PER_DAY - 1),
    });
  } catch (err) {
    console.error('demo-scan error:', err);
    await recordScanEvent({ event: 'demo_scan_failed', source, scan_type: 'demo', success: false, error_message: String(err.message || 'unexpected').slice(0, 200) });
    return res.status(500).json({ error: 'Something went wrong running the scan.' });
  }
}
