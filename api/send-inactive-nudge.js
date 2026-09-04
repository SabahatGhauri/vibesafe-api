// Weekly nudge for accounts that signed up and never scanned.
//
// The existing lifecycle covers everyone except this group:
//   get_welcome_candidates  -> signed up in the last 7 days
//   get_followup_candidates -> requires a completed scan
// Someone who signs up and never scans got one welcome and then nothing, ever.
// That is 18 of 26 accounts, including every signup since 7 August.
//
// Runs from Vercel Cron weekly. Vercel injects CRON_SECRET on cron paths, so
// this needs no manual trigger. Add ?dry=1 to see who would be mailed without
// sending anything.
//
// Safety, all enforced in get_inactive_candidates():
//   - only accounts older than 3 days
//   - only accounts with no scan_success from any source
//   - free plans only
//   - anyone on email_optout is excluded
//   - at most one nudge per person per 30 days
//   - 50 per run
// Every message carries a working unsubscribe link and the List-Unsubscribe
// headers mail clients use for one-click opt-out -- unlike scan-followup.js,
// which predates that and sends without either.

import { unsubToken } from './unsubscribe.js';

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const SITE = 'https://www.vibesafe.info';

// Keep in step with FREE_SCAN_LIMIT in api/scan.js.
const FREE_SCAN_LIMIT = 10;

const POSTAL = process.env.CAMPAIGN_POSTAL_ADDRESS
  || 'VibeSafe &mdash; SG Digital Ventures LLC, Wyoming, USA &middot; <a href="mailto:contact@vibesafe.info" style="color:#64748B;">contact@vibesafe.info</a>';

function html(unsubUrl) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#F6F7F9;font-family:-apple-system,Segoe UI,Arial,sans-serif;">
  <div style="max-width:520px;margin:32px auto;padding:0 20px;">
    <div style="font-size:1.05rem;font-weight:700;color:#111827;margin-bottom:22px;">VibeSafe</div>

    <p style="color:#374151;font-size:0.97rem;line-height:1.65;margin:0 0 16px;">
      Your account has <strong style="color:#00695C;">${FREE_SCAN_LIMIT} free scans</strong> this month and none of them have been used yet. A scan takes about twenty seconds &mdash; paste code, or let VibeSafe scan an example first so you can see what a report looks like before using one of your own.
    </p>

    <p style="color:#374151;font-size:0.97rem;line-height:1.65;margin:0 0 8px;">VibeSafe reads code written by AI tools and tells you, in plain English, what a stranger could do with it:</p>
    <ul style="color:#374151;font-size:0.94rem;line-height:1.75;margin:0 0 20px;padding-left:20px;">
      <li>API keys left in code that ships to the browser</li>
      <li>Admin routes with no login check on them</li>
      <li>Database tables every user can read</li>
      <li>Vulnerable and hallucinated packages</li>
    </ul>

    <a href="${SITE}/dashboard" style="display:inline-block;background:#0F766E;color:#FFFFFF;font-weight:600;font-size:0.95rem;padding:12px 24px;border-radius:8px;text-decoration:none;">Run a scan</a>

    <!-- Launch Check is free (1/month, api/launch-check.js). Live URL scanning
         is Pro-only, so it is deliberately not offered here. -->
    <div style="border-top:1px solid #E5E7EB;margin:26px 0 0;padding-top:20px;">
      <p style="color:#111827;font-size:0.95rem;font-weight:600;margin:0 0 8px;">Already deployed? Check the site itself</p>
      <p style="color:#374151;font-size:0.94rem;line-height:1.65;margin:0 0 14px;">
        Your plan also includes <strong style="color:#0F766E;">one free Launch Check a month</strong>. Give it your URL and VibeSafe opens the app in a real browser, clicks through it the way a first-time visitor would, and reports what actually breaks &mdash; dead pages, console errors, failed requests &mdash; with screenshots and a readiness score.
      </p>
      <a href="${SITE}/dashboard" style="display:inline-block;border:1px solid #0F766E;color:#0F766E;font-weight:600;font-size:0.92rem;padding:10px 20px;border-radius:8px;text-decoration:none;">Run a Launch Check</a>
    </div>

    <p style="color:#6B7280;font-size:0.88rem;line-height:1.6;margin:22px 0 0;">
      Prefer to scan from VS Code or Cursor? <a href="${SITE}/user-guide#vscode" style="color:#0F766E;">Here is how to connect your editor</a> &mdash; it takes about a minute.
    </p>

    <p style="color:#9CA3AF;font-size:0.78rem;line-height:1.5;margin:26px 0 0;border-top:1px solid #E5E7EB;padding-top:14px;">
      Don't want these? <a href="${unsubUrl}" style="color:#6B7280;">Unsubscribe</a>.
      You will still get account email like receipts and security alerts.
    </p>
    <p style="color:#9CA3AF;font-size:0.72rem;line-height:1.5;margin:10px 0 0;">${POSTAL}</p>
  </div>
</body></html>`;
}

export default async function handler(req, res) {
  // Cron guard: Vercel injects this header on scheduled invocations.
  const secret = process.env.CRON_SECRET;
  if (secret && (req.headers['authorization'] || '') !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (!SERVICE_KEY) return res.status(200).json({ sent: 0, reason: 'no service key' });

  const dry = req.query && (req.query.dry === '1' || req.query.dry === 'true');
  const svcHeaders = {
    'Content-Type': 'application/json',
    apikey: SERVICE_KEY,
    Authorization: `Bearer ${SERVICE_KEY}`,
  };

  let candidates = [];
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/rpc/get_inactive_candidates`, {
      method: 'POST', headers: svcHeaders, body: '{}',
    });
    if (!r.ok) return res.status(200).json({ sent: 0, reason: `candidate query failed: ${r.status}` });
    candidates = (await r.json()) || [];
  } catch (err) {
    return res.status(200).json({ sent: 0, reason: String(err.message).slice(0, 200) });
  }

  if (dry) {
    const sample = (candidates[0] && candidates[0].email) || 'someone@example.com';
    return res.status(200).json({
      dryRun: true,
      note: 'Nothing was sent. Remove ?dry=1 to deliver.',
      count: candidates.length,
      candidates: candidates.map(c => ({ email: c.email, signed_up: c.signed_up })),
      subject: `Your ${FREE_SCAN_LIMIT} free scans are waiting`,
      previewHtml: html(`${SITE}/api/unsubscribe?email=${encodeURIComponent(sample)}&t=${await unsubToken(sample)}`),
    });
  }

  const results = { sent: 0, failed: 0, errors: [] };
  let first = true;
  for (const c of candidates) {
    if (!c.email) continue;
    // Resend allows 10 requests/second; 150ms keeps us under it.
    if (!first) await new Promise(r => setTimeout(r, 150));
    first = false;

    const unsubUrl = `${SITE}/api/unsubscribe?email=${encodeURIComponent(c.email)}&t=${await unsubToken(c.email)}`;
    try {
      const r = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        },
        body: JSON.stringify({
          from: process.env.RESEND_FROM_EMAIL || 'VibeSafe <onboarding@resend.dev>',
          to: [c.email],
          subject: `Your ${FREE_SCAN_LIMIT} free scans are waiting`,
          html: html(unsubUrl),
          headers: {
            'List-Unsubscribe': `<${unsubUrl}>`,
            'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
          },
        }),
      });
      if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);

      // Record only after a confirmed send, so a Resend failure does not burn
      // this person's 30-day cooldown.
      await fetch(`${SUPABASE_URL}/rest/v1/inactive_nudge_emails`, {
        method: 'POST',
        headers: { ...svcHeaders, Prefer: 'resolution=merge-duplicates,return=minimal' },
        body: JSON.stringify({ user_id: c.user_id, sent_at: new Date().toISOString() }),
      });
      results.sent++;
    } catch (err) {
      results.failed++;
      results.errors.push({ email: c.email, error: String(err.message).slice(0, 200) });
    }
  }
  return res.status(200).json(results);
}
