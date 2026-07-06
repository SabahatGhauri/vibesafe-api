// VibeSafe Launch Check — an AI agent visits your deployed app like a real user:
// opens pages, follows internal links, captures screenshots, console errors and
// failed requests, then Claude writes a launch-readiness report with a score.
// MVP scope: passive journey only — never submits forms or clicks destructive
// buttons on a live app. Free plan: 1 check/month. Pro/Team: unlimited.

import chromiumPkg from '@sparticuz/chromium-min';

const CHROMIUM_PACK = 'https://github.com/Sparticuz/chromium/releases/download/v131.0.1/chromium-v131.0.1-pack.tar';
import puppeteer from 'puppeteer-core';

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_hgCpN6tsYqEiCkyvJm06qQ_1Ddlvznn';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const FREE_CHECKS_PER_MONTH = 1;

export const config = { maxDuration: 60 };

async function resolveUser(token) {
  if (!token) return null;
  if (token.startsWith('vibesafe_sk_')) {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/rpc/get_user_by_api_key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY, 'Authorization': `Bearer ${SUPABASE_ANON_KEY}` },
      body: JSON.stringify({ k: token }),
    });
    if (!r.ok) return null;
    const id = await r.json();
    return id ? { id } : null;
  }
  const r = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { 'Authorization': `Bearer ${token}`, 'apikey': SUPABASE_ANON_KEY },
  });
  if (!r.ok) return null;
  const u = await r.json();
  return u && u.id ? { id: u.id } : null;
}

async function getPlan(userId) {
  if (!SERVICE_KEY) return 'free';
  const r = await fetch(`${SUPABASE_URL}/rest/v1/vibesafe_plans?id=eq.${userId}&select=plan`, {
    headers: { 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}` },
  });
  if (!r.ok) return 'free';
  const rows = await r.json();
  return (rows[0] && rows[0].plan) || 'free';
}

async function checksThisMonth(userId) {
  if (!SERVICE_KEY) return 0;
  const start = new Date(); start.setDate(1); start.setHours(0, 0, 0, 0);
  const r = await fetch(
    `${SUPABASE_URL}/rest/v1/extension_events?user_id=eq.${userId}&event=eq.launch_check&created_at=gte.${start.toISOString()}&select=id`,
    { headers: { 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}`, 'Prefer': 'count=exact' } }
  );
  const range = r.headers.get('content-range') || '';
  return parseInt(range.split('/')[1] || '0', 10);
}

async function recordCheck(userId, success) {
  if (!SERVICE_KEY) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/extension_events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}`, 'Prefer': 'return=minimal' },
      body: JSON.stringify({ user_id: userId, event: 'launch_check', source: 'website', scan_type: 'launch_check', success }),
    });
  } catch (e) { /* analytics never blocks */ }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  const user = await resolveUser(token);
  if (!user) return res.status(401).json({ error: 'Please sign in to run a Launch Check.' });

  const plan = await getPlan(user.id);
  if (plan === 'free') {
    const used = await checksThisMonth(user.id);
    if (used >= FREE_CHECKS_PER_MONTH) {
      return res.status(403).json({ error: `Free plan includes ${FREE_CHECKS_PER_MONTH} Launch Check per month. Upgrade to Pro for unlimited checks.` });
    }
  }

  let { url, goal } = req.body || {};
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'No URL provided.' });
  url = url.trim();
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  let target;
  try { target = new URL(url); } catch { return res.status(400).json({ error: 'Invalid URL.' }); }
  if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(target.hostname)) {
    return res.status(400).json({ error: 'Cannot check private/internal addresses.' });
  }
  goal = String(goal || 'General launch readiness').slice(0, 200);

  const evidence = { pages: [], consoleErrors: [], failedRequests: [], forms: 0, buttons: 0, links: 0 };
  const screenshots = [];
  let browser = null;

  try {
    // Vercel hides AWS's runtime env vars, so sparticuz skips extracting the
    // NSS system libraries. Hint the runtime so lib extraction + LD_LIBRARY_PATH kick in.
    if (!process.env.AWS_EXECUTION_ENV && !process.env.AWS_LAMBDA_JS_RUNTIME) {
      process.env.AWS_LAMBDA_JS_RUNTIME = 'nodejs22.x';
      process.env.AWS_EXECUTION_ENV = 'AWS_Lambda_nodejs22.x';
    }
    chromiumPkg.setGraphicsMode = false;
    browser = await puppeteer.launch({
      args: chromiumPkg.args,
      executablePath: await chromiumPkg.executablePath(CHROMIUM_PACK),
      headless: 'shell',
      defaultViewport: { width: 1280, height: 800 },
      env: { ...process.env, LD_LIBRARY_PATH: ['/tmp/al2023/lib', '/tmp/lib', process.env.LD_LIBRARY_PATH].filter(Boolean).join(':') },
    });
    const page = await browser.newPage();

    page.on('console', m => { if (m.type() === 'error' && evidence.consoleErrors.length < 15) evidence.consoleErrors.push(m.text().slice(0, 300)); });
    page.on('pageerror', e => { if (evidence.consoleErrors.length < 15) evidence.consoleErrors.push('Uncaught: ' + String(e.message).slice(0, 300)); });
    page.on('response', r => {
      if (r.status() >= 400 && evidence.failedRequests.length < 15) {
        evidence.failedRequests.push({ url: r.url().slice(0, 200), status: r.status() });
      }
    });
    page.on('requestfailed', r => {
      if (evidence.failedRequests.length < 15) evidence.failedRequests.push({ url: r.url().slice(0, 200), status: 'failed: ' + (r.failure()?.errorText || 'unknown') });
    });

    async function visit(pageUrl, label) {
      const info = { label, url: pageUrl.slice(0, 200), ok: false, title: '', loadMs: 0 };
      const t0 = Date.now();
      try {
        const resp = await page.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
        await new Promise(r => setTimeout(r, 2200));
        info.loadMs = Date.now() - t0;
        info.status = resp ? resp.status() : null;
        info.ok = !!resp && resp.status() < 400;
        // client-side redirects can detach the frame mid-read — guard each read
        // separately so one race doesn't poison the whole page record.
        try { info.title = (await page.title()).slice(0, 120); } catch (e) { /* keep going */ }
        try {
          const counts = await page.evaluate(() => ({
            forms: document.querySelectorAll('form').length,
            buttons: document.querySelectorAll('button, [role="button"], input[type="submit"]').length,
            links: document.querySelectorAll('a[href]').length,
            h1: (document.querySelector('h1')?.textContent || '').slice(0, 120),
            brokenImgs: [...document.images].filter(i => i.complete && i.naturalWidth === 0).length,
          }));
          Object.assign(info, counts);
          evidence.forms += counts.forms; evidence.buttons += counts.buttons; evidence.links += counts.links;
        } catch (e) { info.note = 'page redirected during inspection'; }
        try {
          if (screenshots.length < 3) {
            const buf = await page.screenshot({ type: 'jpeg', quality: 55 });
            screenshots.push({ label: label + ' — ' + (info.title || pageUrl), data: Buffer.from(buf).toString('base64') });
          }
        } catch (e) { /* screenshot is best-effort */ }
      } catch (e) {
        info.error = String(e.message).slice(0, 200);
      }
      evidence.pages.push(info);
      return info;
    }

    // 1) Home
    const home = await visit(url, 'Landing page');

    // 2) Follow up to 2 internal links a real user would click (nav/buttons first)
    if (home.ok) {
      const internal = await page.evaluate((origin) => {
        const seen = new Set(); const out = [];
        const els = [...document.querySelectorAll('nav a[href], header a[href], a[href]')];
        for (const a of els) {
          try {
            const u = new URL(a.getAttribute('href'), location.href);
            if (u.origin !== origin) continue;
            const key = u.pathname;
            if (key === location.pathname || key === '/' || seen.has(key)) continue;
            if (/logout|signout|delete|#/.test(u.href)) continue;
            seen.add(key);
            out.push({ href: u.href, text: (a.textContent || '').trim().slice(0, 40) });
            if (out.length >= 2) break;
          } catch (e) { /* skip */ }
        }
        return out;
      }, target.origin);
      for (const link of internal) {
        await visit(link.href, `Clicked "${link.text || 'link'}"`);
      }
    }

    try { await page.close(); } catch (e) { /* already gone */ }
    await browser.close(); browser = null;

    // 3) Claude writes the launch-readiness report from the evidence
    const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 2000,
        system: `You are VibeSafe Launch Check — you just browsed a founder's deployed app like a first-time user. Write a launch-readiness report for a NON-TECHNICAL founder from the evidence. Respond with valid JSON only:
{"score": <0-100>, "verdict": "<Ready to launch | Almost ready | Not ready yet>", "summary": "<2 sentences, plain English>",
"worked": ["<thing that worked>", ...],
"failed": [{"title":"<issue>","severity":"critical|warning|info","why":"<why it matters to users, 1 sentence>","fix":"<what to do, 1 sentence>"}, ...],
"next_steps": ["<ordered first fix>", "<second>", "<third>"]}
Scoring: start 100; -25 if landing page failed to load; -10 per page error/crash; -8 per console error group; -5 per failed request group; -5 slow pages (>5s); min 5. Be honest but encouraging. The user's stated goal matters — address it.`,
        messages: [{ role: 'user', content: `Goal: ${goal}\nApp: ${url}\n\nEvidence from the browsing session:\n${JSON.stringify(evidence, null, 2)}` }],
      }),
    });
    if (!claudeRes.ok) throw new Error('report generation unavailable');
    const cd = await claudeRes.json();
    const raw = cd.content?.[0]?.text || '';
    const report = JSON.parse(raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim());

    await recordCheck(user.id, true);
    return res.status(200).json({ report, evidence, screenshots, url, goal, plan });

  } catch (err) {
    if (browser) try { await browser.close(); } catch (e) {}
    let diag = '';
    try {
      const fs = await import('fs');
      diag = ' [node=' + process.version
        + ' tmp=' + fs.readdirSync('/tmp').slice(0, 12).join(',')
        + (fs.existsSync('/tmp/al2023') ? ' al2023=' + fs.readdirSync('/tmp/al2023').join(',') : ' no-al2023')
        + ' LDLP=' + (process.env.LD_LIBRARY_PATH || 'unset') + ']';
    } catch (e) { diag = ' [diag failed]'; }
    console.error('launch-check error:', err, diag);
    await recordCheck(user.id, false);
    return res.status(500).json({ error: 'Launch Check failed: ' + String(err.message).slice(0, 160) + diag.slice(0, 400) });
  }
}
