// VibeSafe Continuous Monitoring — weekly Vercel Cron (see vercel.json).
// Re-scans every active watched URL (Pro/Team) via the shared DAST scanner,
// compares against the stored baseline, and emails the owner ONLY when security
// degrades (score drops or a new critical appears). First scan just sets the
// baseline silently. All writes use the service role key (bypasses RLS).

import { runDastScan } from '../lib/dast.js';

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

function svc(extra = {}) {
  return { 'Content-Type': 'application/json', 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}`, ...extra };
}

function alertEmailHtml({ url, label, score, criticals, prevScore, prevCriticals, topIssues }) {
  const name = label || url;
  const scoreColor = score >= 75 ? '#10B981' : score >= 50 ? '#F59E0B' : '#EF4444';
  const issuesList = (topIssues || []).slice(0, 4).map(i =>
    `<li style="margin-bottom:6px;"><strong style="color:#F1F5F9;">${(i.title || 'Issue').replace(/</g, '&lt;')}</strong>${i.fix ? ` &mdash; <span style="color:#94A3B8;">${(i.fix).replace(/</g, '&lt;')}</span>` : ''}</li>`
  ).join('');
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#080C18;font-family:'Inter',Arial,sans-serif;">
  <div style="max-width:520px;margin:40px auto;background:#0F1624;border:1px solid #1E2D42;border-radius:16px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#EF4444,#7C3AED);padding:3px 0 0;"></div>
    <div style="padding:36px 40px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:24px;">
        <div style="width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#00D4FF,#7C3AED);display:flex;align-items:center;justify-content:center;font-size:18px;">&#128737;&#65039;</div>
        <span style="font-size:1.2rem;font-weight:700;color:#F1F5F9;">VibeSafe Monitoring</span>
      </div>
      <h1 style="font-size:1.25rem;font-weight:700;color:${scoreColor};margin:0 0 10px;">Security dropped on ${name.replace(/</g, '&lt;')}</h1>
      <p style="color:#94A3B8;font-size:0.95rem;line-height:1.6;margin:0 0 18px;">
        Your watched site's security score went from <strong style="color:#CBD5E1;">${Number.isFinite(prevScore) ? prevScore : '—'}/100</strong>
        to <strong style="color:${scoreColor};">${score}/100</strong>${criticals > (prevCriticals || 0) ? ` and now has <strong style="color:#EF4444;">${criticals} critical issue${criticals > 1 ? 's' : ''}</strong>` : ''}.
      </p>
      ${issuesList ? `<ul style="color:#CBD5E1;font-size:0.9rem;line-height:1.6;margin:0 0 22px;padding-left:20px;">${issuesList}</ul>` : ''}
      <a href="https://www.vibesafe.info/dashboard.html?launch=1" style="display:inline-block;background:linear-gradient(135deg,#00D4FF,#0891B2);color:#080C18;font-weight:700;font-size:0.95rem;padding:14px 28px;border-radius:9px;text-decoration:none;">
        Review &amp; fix &rarr;
      </a>
      <p style="color:#475569;font-size:0.78rem;margin:26px 0 0;line-height:1.5;">
        You're receiving this because you're watching <a href="${url}" style="color:#00D4FF;">${url.replace(/</g, '&lt;')}</a> in VibeSafe continuous monitoring. Remove it anytime from your dashboard.
      </p>
    </div>
  </div>
</body>
</html>`;
}

async function sendAlert(to, data) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.RESEND_API_KEY}` },
    body: JSON.stringify({
      from: process.env.RESEND_FROM_EMAIL || 'VibeSafe <onboarding@resend.dev>',
      to: [to],
      subject: `⚠️ Security dropped to ${data.score}/100 on ${data.label || data.url}`,
      html: alertEmailHtml(data),
    }),
  });
  if (!r.ok) throw new Error(`Resend ${r.status}: ${await r.text()}`);
}

async function updateRow(id, fields) {
  await fetch(`${SUPABASE_URL}/rest/v1/monitored_urls?id=eq.${id}`, {
    method: 'PATCH',
    headers: svc({ 'Prefer': 'return=minimal' }),
    body: JSON.stringify(fields),
  });
}

export default async function handler(req, res) {
  // Cron guard: if CRON_SECRET is configured, require it.
  const secret = process.env.CRON_SECRET;
  if (secret && (req.headers['authorization'] || '') !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (!SERVICE_KEY) return res.status(200).json({ scanned: 0, reason: 'no service key' });

  const dry = req.query && (req.query.dry === '1' || req.query.dry === 'true');

  const listRes = await fetch(`${SUPABASE_URL}/rest/v1/rpc/get_urls_to_monitor`, {
    method: 'POST', headers: svc(), body: '{}',
  });
  if (!listRes.ok) return res.status(200).json({ scanned: 0, reason: 'candidate query failed' });
  const targets = (await listRes.json()) || [];

  if (dry) return res.status(200).json({ dry: true, count: targets.length, targets: targets.map(t => ({ url: t.url, email: t.email, last_score: t.last_score })) });

  // Stay within the 60s function budget: stop starting new scans near the limit
  // so we always exit cleanly. Unprocessed URLs stay "due" and are picked up next run.
  const startedAt = Date.now();
  const TIME_BUDGET_MS = 50000;

  let scanned = 0, alerted = 0, failed = 0, skipped = 0;
  for (const t of targets) {
    if (Date.now() - startedAt > TIME_BUDGET_MS) { skipped = targets.length - (scanned + failed); break; }
    try {
      const result = await runDastScan(t.url);
      const score = Number.isFinite(result.score) ? result.score : 0;
      const criticals = (result.issues || []).filter(i => i.severity === 'critical').length;
      const hadBaseline = t.last_score !== null && t.last_score !== undefined;
      const degraded = hadBaseline && (score < t.last_score || criticals > (t.last_criticals || 0));

      const fields = { last_score: score, last_criticals: criticals, last_scanned_at: new Date().toISOString() };

      if (degraded && process.env.RESEND_API_KEY && t.email) {
        const topIssues = (result.issues || []).filter(i => i.severity === 'critical')
          .concat((result.issues || []).filter(i => i.severity === 'warning'));
        await sendAlert(t.email, {
          url: t.url, label: t.label, score, criticals,
          prevScore: t.last_score, prevCriticals: t.last_criticals, topIssues,
        });
        fields.last_alert_at = new Date().toISOString();
        alerted++;
      }
      await updateRow(t.id, fields);
      scanned++;
    } catch (e) {
      console.error('monitor-scan failed for', t.url, e.message);
      // Still stamp last_scanned_at so an unreachable site doesn't get re-hammered.
      await updateRow(t.id, { last_scanned_at: new Date().toISOString() }).catch(() => {});
      failed++;
    }
  }
  return res.status(200).json({ scanned, alerted, failed, skipped, candidates: targets.length });
}
