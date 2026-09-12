// One-off campaign: the 400-app study, sent to registered free users.
//
// Why this exists rather than a second usage nudge: the nudge went to 25
// people on 5 September and moved nobody. 18 of them still have not run a
// scan, and the 7 who have scanned last did it on 1 September, before that
// email. Sending the same message again would be the third contact for
// people who ignored the first two, which is how a 30-person list starts
// marking mail as spam.
//
// So this is content, not a reminder: a real finding from our own research,
// with the free scan as the action rather than the subject.
//
// SAFETY: dry-run by default, like send-usage-nudge.js. Delivers only on
// {"send": true}, or on a Vercel cron GET (the only way to run this without
// a human reading the Sensitive CRON_SECRET). Excludes paying customers,
// anyone on email_optout, anyone already in study_email_sends, and anyone
// emailed in the last 3 days -- that last rule keeps the four people mailed
// on 12 September from getting two campaigns in one week.

import { unsubToken } from './unsubscribe.js';

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const SITE = 'https://www.vibesafe.info';
const POST_URL = `${SITE}/blog/we-scanned-400-ai-built-apps`;

// Don't mail anyone who received another campaign within this many days.
const QUIET_DAYS = 3;

const POSTAL = process.env.CAMPAIGN_POSTAL_ADDRESS
  || 'VibeSafe &mdash; SG Digital Ventures LLC, Wyoming, USA &middot; <a href="mailto:contact@vibesafe.info" style="color:#64748B;">contact@vibesafe.info</a>';

async function sb(path) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` },
  });
  if (!r.ok) throw new Error(`Supabase ${path}: ${r.status} ${await r.text()}`);
  return r.json();
}

// `onlyEmail` is for test sends: that person only, skipping every exclusion so
// the copy can be reviewed even by a paying customer.
async function recipients(onlyEmail) {
  const usersRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users?page=1&per_page=200`, {
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` },
  });
  if (!usersRes.ok) throw new Error(`auth admin: ${usersRes.status}`);
  const body = await usersRes.json();
  const users = body.users || (Array.isArray(body) ? body : []);

  const plans = await sb('vibesafe_plans?select=id,plan');
  const paying = new Set(plans.filter(p => p.plan === 'pro' || p.plan === 'team').map(p => p.id));

  const optouts = await sb('email_optout?select=email');
  const opted = new Set(optouts.map(o => String(o.email).toLowerCase()));

  let alreadySent = new Set();
  try {
    const prior = await sb('study_email_sends?select=user_id');
    alreadySent = new Set(prior.map(r => r.user_id));
  } catch (e) { /* table missing -> treat as nobody sent */ }

  // Anyone contacted very recently by the other campaign.
  const cutoff = new Date(Date.now() - QUIET_DAYS * 86400000).toISOString();
  let recentlyMailed = new Set();
  try {
    const recent = await sb(`usage_nudge_emails?select=user_id&sent_at=gte.${cutoff}`);
    recentlyMailed = new Set(recent.map(r => r.user_id));
  } catch (e) { /* ignore */ }

  const everEvents = await sb('extension_events?event=eq.scan_success&select=user_id');
  const everScanned = new Set(everEvents.map(e => e.user_id).filter(Boolean));

  const target = onlyEmail ? String(onlyEmail).trim().toLowerCase() : null;

  const seen = new Set();
  const out = [];
  for (const u of users) {
    const email = String(u.email || '').trim().toLowerCase();
    if (!email || seen.has(email)) continue;

    if (target) {
      if (email !== target) continue;
    } else {
      if (paying.has(u.id)) continue;
      if (opted.has(email)) continue;
      if (alreadySent.has(u.id)) continue;
      if (recentlyMailed.has(u.id)) continue;
    }
    seen.add(email);
    out.push({ user_id: u.id, email, scanned: everScanned.has(u.id) });
  }
  return out;
}

const SUBJECT = 'We scanned 400 AI-built apps. 18.5% had published their .env';

function html(r, unsubUrl) {
  // One closing line differs: people who have scanned are told their scans
  // reset monthly; people who never have are told what a first scan involves.
  const closing = r.scanned
    ? `Your free scans reset on the 1st of each month, so there are some waiting on your account now.`
    : `Your account has free scans on it that have never been used. A scan takes about twenty seconds &mdash; paste a file, or let VibeSafe scan an example first so you can see what a report looks like.`;

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#F6F7F9;font-family:-apple-system,Segoe UI,Arial,sans-serif;">
  <div style="max-width:520px;margin:32px auto;padding:0 20px;">
    <div style="font-size:1.05rem;font-weight:700;color:#111827;margin-bottom:22px;">VibeSafe</div>

    <p style="color:#374151;font-size:0.97rem;line-height:1.65;margin:0 0 16px;">
      Everyone has an opinion on whether AI-built apps are safe. Almost nobody has counted, so we did.
    </p>

    <p style="color:#374151;font-size:0.97rem;line-height:1.65;margin:0 0 16px;">
      We built a frozen list of 400 public repositories genuinely built with Lovable, Bolt and v0 &mdash; chosen by the build files those tools leave behind, not by repos that merely mention them. Then we scanned them.
    </p>

    <div style="background:#FFFFFF;border:1px solid #E5E7EB;border-radius:10px;padding:18px 20px;margin:0 0 20px;">
      <p style="color:#111827;font-size:0.95rem;line-height:1.7;margin:0;">
        <strong style="color:#0F766E;">18.5%</strong> had a <code style="background:#F3F4F6;padding:1px 5px;border-radius:4px;">.env</code> file committed into the repository<br>
        <strong style="color:#0F766E;">59%</strong> of the repos we scanned had at least one critical issue<br>
        <strong style="color:#0F766E;">2%</strong> of files came back with nothing wrong at all
      </p>
    </div>

    <p style="color:#374151;font-size:0.97rem;line-height:1.65;margin:0 0 16px;">
      A committed <code style="background:#F3F4F6;padding:1px 5px;border-radius:4px;">.env</code> is the whole set of keys in one file: database, payments, AI provider. Nobody adds it deliberately. It happens because the generated project shipped without a rule to ignore it, and the founder ran <code style="background:#F3F4F6;padding:1px 5px;border-radius:4px;">git add .</code> exactly as every tutorial says to.
    </p>

    <p style="color:#374151;font-size:0.97rem;line-height:1.65;margin:0 0 20px;">
      The biggest single category of critical findings was not an exotic exploit. It was out-of-date packages with known holes, pulled in by the generator and never checked.
    </p>

    <a href="${POST_URL}?utm_source=study_email" style="display:inline-block;background:#0F766E;color:#FFFFFF;font-weight:600;font-size:0.95rem;padding:12px 24px;border-radius:8px;text-decoration:none;">Read the full findings</a>

    <div style="border-top:1px solid #E5E7EB;margin:26px 0 0;padding-top:20px;">
      <p style="color:#111827;font-size:0.95rem;font-weight:600;margin:0 0 8px;">Where does your app sit in those numbers?</p>
      <p style="color:#374151;font-size:0.94rem;line-height:1.65;margin:0 0 14px;">${closing}</p>
      <a href="${SITE}/dashboard" style="display:inline-block;border:1px solid #0F766E;color:#0F766E;font-weight:600;font-size:0.92rem;padding:10px 20px;border-radius:8px;text-decoration:none;">Scan your app</a>
    </div>

    <p style="color:#6B7280;font-size:0.88rem;line-height:1.6;margin:22px 0 0;">
      One quick check you can run without us: <code style="background:#F3F4F6;padding:1px 5px;border-radius:4px;">git ls-files | grep .env</code> in your project. If anything comes back, those keys are public and need rotating.
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
  const isCron = req.method === 'GET';
  if (req.method !== 'POST' && !isCron) return res.status(405).json({ error: 'Method not allowed' });

  const secret = process.env.CRON_SECRET;
  if (!secret || (req.headers['authorization'] || '') !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (!SERVICE_KEY) return res.status(500).json({ error: 'SUPABASE_SERVICE_ROLE_KEY not set' });

  const send = isCron || !!(req.body && req.body.send === true);
  const only = (!isCron && req.body && typeof req.body.only === 'string') ? req.body.only : null;

  let list;
  try {
    list = await recipients(only);
  } catch (err) {
    return res.status(500).json({ error: String(err.message).slice(0, 300) });
  }

  if (only && list.length === 0) {
    return res.status(404).json({ error: `No account found for ${only}. Test send aborted.` });
  }

  if (!send) {
    const sample = list[0] || { email: 'someone@example.com', scanned: false };
    const unsubUrl = `${SITE}/api/unsubscribe?email=${encodeURIComponent(sample.email)}&t=${await unsubToken(sample.email)}`;
    return res.status(200).json({
      dryRun: true,
      note: only
        ? `Nothing was sent. POST {"send":true,"only":"${only}"} to deliver this single test.`
        : 'Nothing was sent. POST {"send":true} to actually deliver.',
      testMode: !!only,
      recipientCount: list.length,
      hasScanned: list.filter(r => r.scanned).length,
      neverScanned: list.filter(r => !r.scanned).length,
      recipients: list,
      preview: { subject: SUBJECT, html: html(sample, unsubUrl) },
    });
  }

  const results = { sent: 0, failed: 0, errors: [], testMode: !!only, recipients: list.map(r => r.email) };
  let first = true;
  for (const r of list) {
    if (!first) await new Promise(x => setTimeout(x, 150)); // Resend: 10 req/s
    first = false;
    const unsubUrl = `${SITE}/api/unsubscribe?email=${encodeURIComponent(r.email)}&t=${await unsubToken(r.email)}`;
    try {
      const resp = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        },
        body: JSON.stringify({
          from: process.env.RESEND_FROM_EMAIL || 'VibeSafe <onboarding@resend.dev>',
          to: [r.email],
          subject: SUBJECT,
          html: html(r, unsubUrl),
          headers: {
            'List-Unsubscribe': `<${unsubUrl}>`,
            'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
          },
        }),
      });
      if (!resp.ok) throw new Error(`${resp.status} ${await resp.text()}`);

      // Logged only after Resend confirms, and never for a test send.
      if (!only && r.user_id) {
        await fetch(`${SUPABASE_URL}/rest/v1/study_email_sends`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', apikey: SERVICE_KEY,
                     Authorization: `Bearer ${SERVICE_KEY}`,
                     Prefer: 'resolution=merge-duplicates,return=minimal' },
          body: JSON.stringify({ user_id: r.user_id, email: r.email, sent_at: new Date().toISOString() }),
        });
      }
      results.sent++;
    } catch (err) {
      results.failed++;
      results.errors.push({ email: r.email, error: String(err.message).slice(0, 200) });
    }
  }
  return res.status(200).json(results);
}
