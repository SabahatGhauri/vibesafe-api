#!/usr/bin/env node
// VibeSafe health check — verifies every public surface is up and the scanner
// actually works end-to-end. Run manually or on a schedule.
//   VIBESAFE_API_KEY=vibesafe_sk_... node scripts/health-check.js
// Exits non-zero if any CRITICAL check fails (good for cron alerting).

const API = 'https://vibesafe-api.vercel.app/api';
const SITE = 'https://www.vibesafe.info';
const KEY = process.env.VIBESAFE_API_KEY || '';

const results = [];
// sev: 'critical' fails the run; 'warn' is reported but doesn't fail.
function record(name, ok, detail, sev = 'critical') {
  results.push({ name, ok, detail, sev });
  const tag = ok ? 'PASS' : (sev === 'warn' ? 'WARN' : 'FAIL');
  console.log(`  [${tag}] ${name}${detail ? ' — ' + detail : ''}`);
}

async function head(url, expect = [200]) {
  try {
    const r = await fetch(url, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(15000) });
    return { ok: expect.includes(r.status), status: r.status };
  } catch (e) { return { ok: false, status: 0, error: e.message }; }
}

async function group(title, fn) { console.log(`\n${title}`); await fn(); }

(async () => {
  console.log(`VibeSafe health check — ${new Date().toISOString()}`);

  // ── 1. WEBSITE PAGES ──
  await group('Website pages (expect 200)', async () => {
    const pages = ['/', '/dashboard.html', '/faq.html', '/user-guide.html', '/learn.html', '/login', '/how-it-works.html'];
    for (const p of pages) {
      const r = await head(SITE + p);
      record(`GET ${p}`, r.ok, r.ok ? '200' : `got ${r.status || r.error}`);
    }
    // Security headers we shipped should be present on the site.
    try {
      const r = await fetch(SITE + '/', { signal: AbortSignal.timeout(15000) });
      const xfo = r.headers.get('x-frame-options');
      record('Security headers present', !!xfo, xfo ? `X-Frame-Options: ${xfo}` : 'X-Frame-Options missing', 'warn');
    } catch (e) { record('Security headers present', false, e.message, 'warn'); }
  });

  // ── 2. API ENDPOINTS ──
  await group('API endpoints', async () => {
    // Public, no-auth endpoints
    const ann = await head(`${API}/announcement`);
    record('GET /announcement', ann.ok, ann.ok ? '200' : `got ${ann.status}`);
    const mkt = await head(`${API}/marketplace-stats`);
    record('GET /marketplace-stats', mkt.ok, mkt.ok ? '200' : `got ${mkt.status}`);

    // Auth guards should reject unauthenticated calls (401/403), NOT 404 or 500.
    try {
      const r = await fetch(`${API}/scan-url`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com' }), signal: AbortSignal.timeout(15000),
      });
      record('/scan-url auth guard', [401, 403].includes(r.status), `expected 401/403, got ${r.status}`);
    } catch (e) { record('/scan-url auth guard', false, e.message); }

    // Monitoring endpoint: 401 = deployed & guarded; 404 = not deployed yet.
    const mon = await fetch(`${API}/monitor`, { signal: AbortSignal.timeout(15000) }).then(r => r.status).catch(() => 0);
    record('/monitor deployed', mon === 401, mon === 404 ? 'NOT DEPLOYED (404) — pending Vercel deploy' : `status ${mon}`, 'warn');
  });

  // ── 3. SCANNER END-TO-END (real scan) ──
  await group('Scanner (end-to-end)', async () => {
    if (!KEY.startsWith('vibesafe_sk_')) {
      record('Code scan', false, 'VIBESAFE_API_KEY not set — skipped', 'warn');
      return;
    }
    try {
      const r = await fetch(`${API}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${KEY}` },
        body: JSON.stringify({ code: 'const k = "sk_live_ABCD1234567890";', language: 'JavaScript', source: 'health-check' }),
        signal: AbortSignal.timeout(60000), // real Claude scan + possible cold start
      });
      const data = await r.json().catch(() => ({}));
      const gotScore = r.ok && Number.isFinite(data.score);
      // A hardcoded live key should score low and flag at least one issue — proves the engine reasons, not just responds.
      const caughtIssue = (data.issues || []).length > 0;
      record('Code scan returns a score', gotScore, gotScore ? `score ${data.score}/100` : `HTTP ${r.status}: ${data.error || 'no score'}`);
      record('Code scan flags the planted secret', gotScore && caughtIssue, caughtIssue ? `${data.issues.length} issue(s)` : 'no issues detected', 'warn');
    } catch (e) { record('Code scan returns a score', false, e.message); }
  });

  // ── 4. DISTRIBUTION CHANNELS ──
  await group('Distribution channels', async () => {
    const npmMcp = await head('https://registry.npmjs.org/vibesafe-mcp');
    record('npm: vibesafe-mcp', npmMcp.ok, npmMcp.ok ? 'published' : `got ${npmMcp.status}`);
    const npmCli = await head('https://registry.npmjs.org/vibesafe-scan');
    record('npm: vibesafe-scan (CLI)', npmCli.ok, npmCli.ok ? 'published' : `got ${npmCli.status}`);

    for (const repo of ['vibesafe-scan', 'vibesafe-mcp', 'vibesafe-action']) {
      const r = await head(`https://github.com/SabahatGhauri/${repo}`);
      record(`GitHub repo: ${repo}`, r.ok, r.ok ? 'live' : `got ${r.status}`, 'warn');
    }
    const action = await head('https://github.com/marketplace/actions/vibesafe-vulnerability-scanner');
    record('GitHub Marketplace action', action.ok, action.ok ? 'listed' : `got ${action.status}`, 'warn');
    const vsm = await head('https://marketplace.visualstudio.com/items?itemName=vibesafe-info.vibesafe-scanner');
    record('VS Code Marketplace extension', vsm.ok, vsm.ok ? 'listed' : `got ${vsm.status}`, 'warn');
    const ovsx = await head('https://open-vsx.org/api/vibesafe-info/vibesafe-scanner');
    record('Open VSX extension', ovsx.ok, ovsx.ok ? 'listed' : `got ${ovsx.status}`, 'warn');
  });

  // ── SUMMARY ──
  const fails = results.filter(r => !r.ok && r.sev === 'critical');
  const warns = results.filter(r => !r.ok && r.sev === 'warn');
  const passed = results.filter(r => r.ok).length;
  console.log(`\n${'─'.repeat(48)}`);
  console.log(`SUMMARY: ${passed}/${results.length} passed · ${fails.length} critical fail · ${warns.length} warning`);
  if (fails.length) {
    console.log('CRITICAL FAILURES:');
    fails.forEach(f => console.log(`  ✗ ${f.name} — ${f.detail}`));
    process.exitCode = 1;
  } else {
    console.log('All critical checks passed ✔');
  }
})();
