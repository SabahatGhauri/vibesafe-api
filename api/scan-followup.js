// VibeSafe scan follow-up — daily cron. Emails free users the day after their
// first scan: their score, what to fix first, and the founding offer.
// Idempotent: each user is emailed at most once (followup_emails table).
// Trigger: Vercel Cron (see vercel.json). Supports ?dry=1 to preview without sending.

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

function emailHtml({ score, issues }) {
  const hasStats = Number.isFinite(score);
  const headline = hasStats
    ? `Your app scored ${score}/100${Number.isFinite(issues) && issues > 0 ? ` — ${issues} issue${issues > 1 ? 's' : ''} to fix` : ''}`
    : `Your security scan results are waiting`;
  const scoreColor = !hasStats ? '#00D4FF' : score >= 75 ? '#10B981' : score >= 50 ? '#F59E0B' : '#EF4444';

  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#080C18;font-family:'Inter',Arial,sans-serif;">
  <div style="max-width:520px;margin:40px auto;background:#0F1624;border:1px solid #1E2D42;border-radius:16px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#00D4FF,#7C3AED);padding:3px 0 0;"></div>
    <div style="padding:36px 40px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:28px;">
        <div style="width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#00D4FF,#7C3AED);display:flex;align-items:center;justify-content:center;font-size:18px;">&#128737;&#65039;</div>
        <span style="font-size:1.2rem;font-weight:700;color:#F1F5F9;">VibeSafe</span>
      </div>
      <h1 style="font-size:1.3rem;font-weight:700;color:${scoreColor};margin:0 0 12px;">${headline}</h1>
      <p style="color:#94A3B8;font-size:0.95rem;line-height:1.6;margin:0 0 20px;">
        You ran your first VibeSafe scan yesterday. Most AI-built apps we scan share the same critical risks &mdash; here's what to fix first, in order:
      </p>
      <ol style="color:#CBD5E1;font-size:0.9rem;line-height:1.8;margin:0 0 24px;padding-left:20px;">
        <li><strong style="color:#F1F5F9;">Exposed API keys</strong> &mdash; move any hardcoded keys to environment variables and rotate them</li>
        <li><strong style="color:#F1F5F9;">Open database rules</strong> &mdash; enable Row-Level Security on every Supabase/Firebase table</li>
        <li><strong style="color:#F1F5F9;">Unsafe inputs</strong> &mdash; anything a user types must be validated before it touches your database</li>
      </ol>
      <p style="color:#94A3B8;font-size:0.95rem;line-height:1.6;margin:0 0 24px;">
        Re-scan after each fix to watch your score climb. And as an early user, you can lock in unlimited scans + one-click fixes at <strong style="color:#10B981;">50% off &mdash; $14.50/mo</strong>.
      </p>
      <a href="https://www.vibesafe.info/dashboard.html" style="display:inline-block;background:linear-gradient(135deg,#00D4FF,#0891B2);color:#080C18;font-weight:700;font-size:0.95rem;padding:14px 28px;border-radius:9px;text-decoration:none;margin-right:10px;">
        Re-scan my app &rarr;
      </a>
      <a href="https://www.vibesafe.info/claim-offer.html" style="display:inline-block;color:#00D4FF;font-weight:600;font-size:0.9rem;padding:14px 4px;text-decoration:none;">
        Claim 50% off
      </a>
      <p style="color:#475569;font-size:0.78rem;margin:28px 0 0;line-height:1.5;">
        You're receiving this because you scanned your code on <a href="https://vibesafe.info" style="color:#00D4FF;">vibesafe.info</a>. This is a one-time email &mdash; we won't nag you.
      </p>
    </div>
  </div>
</body>
</html>`;
}

function welcomeHtml() {
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#080C18;font-family:'Inter',Arial,sans-serif;">
  <div style="max-width:520px;margin:40px auto;background:#0F1624;border:1px solid #1E2D42;border-radius:16px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#00D4FF,#7C3AED);padding:3px 0 0;"></div>
    <div style="padding:36px 40px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:28px;">
        <div style="width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#00D4FF,#7C3AED);display:flex;align-items:center;justify-content:center;font-size:18px;">&#128737;&#65039;</div>
        <span style="font-size:1.2rem;font-weight:700;color:#F1F5F9;">VibeSafe</span>
      </div>
      <h1 style="font-size:1.3rem;font-weight:700;color:#F1F5F9;margin:0 0 12px;">Welcome to VibeSafe &#128075;</h1>
      <p style="color:#94A3B8;font-size:0.95rem;line-height:1.6;margin:0 0 20px;">
        You now have a safety net for your AI-built app. Here's how to get the most out of it, in order:
      </p>
      <ol style="color:#CBD5E1;font-size:0.9rem;line-height:1.8;margin:0 0 24px;padding-left:20px;">
        <li><strong style="color:#F1F5F9;">Run your first scan</strong> &mdash; paste your code or your live URL on the dashboard. Takes under a minute, results in plain English.</li>
        <li><strong style="color:#F1F5F9;">Put VibeSafe in your editor</strong> &mdash; install the <a href="https://marketplace.visualstudio.com/items?itemName=vibesafe-info.vibesafe-scanner" style="color:#00D4FF;">VS Code / Cursor extension</a> and connect it in one click &mdash; then scan any file with Ctrl+Shift+V.</li>
        <li><strong style="color:#F1F5F9;">Before you launch</strong> &mdash; run Launch Check so an AI agent tests your deployed app like a real user would.</li>
      </ol>
      <a href="https://www.vibesafe.info/dashboard.html" style="display:inline-block;background:linear-gradient(135deg,#00D4FF,#0891B2);color:#080C18;font-weight:700;font-size:0.95rem;padding:14px 28px;border-radius:9px;text-decoration:none;">
        Run your first scan &rarr;
      </a>
      <p style="color:#475569;font-size:0.78rem;margin:28px 0 0;line-height:1.5;">
        You're receiving this one-time email because you created an account on <a href="https://vibesafe.info" style="color:#00D4FF;">vibesafe.info</a>. Questions? Just reply &mdash; a human reads these.
      </p>
    </div>
  </div>
</body>
</html>`;
}

async function sendWelcome(to) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.RESEND_API_KEY}` },
    body: JSON.stringify({
      from: process.env.RESEND_FROM_EMAIL || 'VibeSafe <onboarding@resend.dev>',
      to: [to],
      subject: 'Welcome to VibeSafe — your first scan takes under a minute',
      html: welcomeHtml(),
    }),
  });
  if (!r.ok) throw new Error(`Resend ${r.status}: ${await r.text()}`);
}

async function sendEmail(to, score, issues) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM_EMAIL || 'VibeSafe <onboarding@resend.dev>',
      to: [to],
      subject: Number.isFinite(score)
        ? `Your app scored ${score}/100 — here's what to fix first`
        : `Your VibeSafe scan — what to fix first`,
      html: emailHtml({ score, issues }),
    }),
  });
  if (!r.ok) throw new Error(`Resend ${r.status}: ${await r.text()}`);
}

export default async function handler(req, res) {
  // Cron guard: if CRON_SECRET is configured, require it.
  const secret = process.env.CRON_SECRET;
  if (secret && (req.headers['authorization'] || '') !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (!SERVICE_KEY) return res.status(200).json({ sent: 0, reason: 'no service key' });

  const dry = req.query && (req.query.dry === '1' || req.query.dry === 'true');

  const svcHeaders = { 'Content-Type': 'application/json', 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}` };

  const candRes = await fetch(`${SUPABASE_URL}/rest/v1/rpc/get_followup_candidates`, {
    method: 'POST', headers: svcHeaders, body: '{}',
  });
  if (!candRes.ok) return res.status(200).json({ sent: 0, reason: 'candidate query failed' });
  const candidates = await candRes.json() || [];

  // New signups who haven't been welcomed yet (see welcome-emails-setup.sql).
  let welcomeCandidates = [];
  try {
    const wRes = await fetch(`${SUPABASE_URL}/rest/v1/rpc/get_welcome_candidates`, {
      method: 'POST', headers: svcHeaders, body: '{}',
    });
    if (wRes.ok) welcomeCandidates = (await wRes.json()) || [];
  } catch (e) { /* welcome must never break the followup run */ }

  if (dry) {
    return res.status(200).json({
      dry: true,
      candidates: candidates.map(c => ({ email: c.email, score: c.last_score, issues: c.last_issues })),
      welcome_candidates: welcomeCandidates.map(w => w.email),
    });
  }
  if (!process.env.RESEND_API_KEY) {
    return res.status(200).json({ sent: 0, candidates: candidates.length, reason: 'RESEND_API_KEY not set' });
  }

  let sent = 0, failed = 0;
  for (const c of candidates) {
    try {
      await sendEmail(c.email, c.last_score, c.last_issues);
      await fetch(`${SUPABASE_URL}/rest/v1/followup_emails`, {
        method: 'POST',
        headers: { ...svcHeaders, 'Prefer': 'return=minimal' },
        body: JSON.stringify({ user_id: c.user_id }),
      });
      sent++;
    } catch (e) {
      console.error('followup failed for', c.email, e.message);
      failed++;
    }
  }

  let welcomed = 0, welcomeFailed = 0;
  for (const w of welcomeCandidates) {
    try {
      await sendWelcome(w.email);
      await fetch(`${SUPABASE_URL}/rest/v1/welcome_emails`, {
        method: 'POST',
        headers: { ...svcHeaders, 'Prefer': 'return=minimal' },
        body: JSON.stringify({ user_id: w.user_id }),
      });
      welcomed++;
    } catch (e) {
      console.error('welcome failed for', w.email, e.message);
      welcomeFailed++;
    }
  }

  return res.status(200).json({ sent, failed, candidates: candidates.length, welcomed, welcome_failed: welcomeFailed, welcome_candidates: welcomeCandidates.length });
}
