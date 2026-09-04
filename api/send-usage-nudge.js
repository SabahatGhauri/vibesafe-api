// Usage nudge for registered users — leads with the free scans they have left.
//
// Written after looking at the numbers: 20 of 26 accounts have never run a
// single scan, and everyone who did scan did it on day one. Nobody comes back
// later on their own. This is the message that tells them what is waiting.
//
// SAFETY: dry-run by default, exactly like send-campaign.js. It only delivers
// when the body says {"send": true}; a bare call returns the recipient list
// with each person's remaining scans and a rendered preview of both variants.
//
// Guarded by CRON_SECRET. Excludes paying customers (they have no limit to
// report) and anyone on email_optout. Every send carries a working unsubscribe
// link plus the List-Unsubscribe headers mail clients use for one-click opt-out.
//
// Deliberately NOT a discount pitch. Discount language ("50% off") is one of
// the strongest signals Gmail uses to file mail under Promotions, and this
// message needs to reach people who have not engaged yet. Plain layout, no
// offer, no urgency.

import { unsubToken } from './unsubscribe.js';

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const SITE = 'https://www.vibesafe.info';

// Keep in step with FREE_SCAN_LIMIT in api/scan.js.
const FREE_SCAN_LIMIT = 10;

const POSTAL = process.env.CAMPAIGN_POSTAL_ADDRESS
  || 'VibeSafe &mdash; SG Digital Ventures LLC, Wyoming, USA &middot; <a href="mailto:contact@vibesafe.info" style="color:#64748B;">contact@vibesafe.info</a>';

async function sb(path) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` },
  });
  if (!r.ok) throw new Error(`Supabase ${path}: ${r.status} ${await r.text()}`);
  return r.json();
}

// Everyone with an account, minus paying customers, minus opt-outs — each with
// the number of free scans they have left this month.
//
// `onlyEmail` is for test sends: it returns just that person, and skips the
// paying/opt-out/quota exclusions so the test still works if the tester is a
// paying customer or has already used the month's scans. Their scan counts are
// still the real ones, so the test shows the copy they would genuinely receive.
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

  // Same rows the limit is enforced against: scan_success, every source.
  const start = new Date();
  start.setDate(1); start.setHours(0, 0, 0, 0);
  const events = await sb(
    `extension_events?event=eq.scan_success&created_at=gte.${start.toISOString()}&select=user_id`
  );
  const usedBy = new Map();
  for (const e of events) {
    if (!e.user_id) continue;
    usedBy.set(e.user_id, (usedBy.get(e.user_id) || 0) + 1);
  }

  // Has this account ever scanned at all? Drives which variant they get.
  const everEvents = await sb('extension_events?event=eq.scan_success&select=user_id');
  const everScanned = new Set(everEvents.map(e => e.user_id).filter(Boolean));

  const target = onlyEmail ? String(onlyEmail).trim().toLowerCase() : null;

  const seen = new Set();
  const out = [];
  for (const u of users) {
    const email = String(u.email || '').trim().toLowerCase();
    if (!email || seen.has(email)) continue;

    if (target) {
      if (email !== target) continue;     // test send: this person only
    } else {
      if (paying.has(u.id)) continue;
      if (opted.has(email)) continue;
    }
    seen.add(email);

    const used = usedBy.get(u.id) || 0;
    const left = Math.max(0, FREE_SCAN_LIMIT - used);
    // A test send still goes out at 0 left so the copy can be reviewed; a real
    // campaign skips those people, since there is nothing encouraging to say.
    if (left === 0 && !target) continue;
    out.push({ email, left: target ? Math.max(left, 1) : left, newcomer: !everScanned.has(u.id) });
  }
  return out;
}

function subjectFor(r) {
  return r.newcomer
    ? `Your ${r.left} free scans are waiting`
    : `You have ${r.left} free ${r.left === 1 ? 'scan' : 'scans'} left this month`;
}

function html(r, unsubUrl) {
  const lead = r.newcomer
    ? `Your account has <strong style="color:#00D4FF;">${r.left} free scans</strong> this month and none of them have been used yet. A scan takes about twenty seconds &mdash; paste code, or let VibeSafe scan an example so you can see what a report looks like first.`
    : `You have <strong style="color:#00D4FF;">${r.left} free ${r.left === 1 ? 'scan' : 'scans'}</strong> left this month. They reset on the 1st and do not roll over.`;

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#F6F7F9;font-family:-apple-system,Segoe UI,Arial,sans-serif;">
  <div style="max-width:520px;margin:32px auto;padding:0 20px;">
    <div style="font-size:1.05rem;font-weight:700;color:#111827;margin-bottom:22px;">VibeSafe</div>

    <p style="color:#374151;font-size:0.97rem;line-height:1.65;margin:0 0 16px;">${lead}</p>

    <p style="color:#374151;font-size:0.97rem;line-height:1.65;margin:0 0 8px;">VibeSafe reads code written by AI tools and tells you, in plain English, what a stranger could do with it:</p>
    <ul style="color:#374151;font-size:0.94rem;line-height:1.75;margin:0 0 20px;padding-left:20px;">
      <li>API keys left in code that ships to the browser</li>
      <li>Admin routes with no login check on them</li>
      <li>Database tables every user can read</li>
      <li>Vulnerable and hallucinated packages</li>
    </ul>

    <a href="${SITE}/dashboard" style="display:inline-block;background:#0F766E;color:#FFFFFF;font-weight:600;font-size:0.95rem;padding:12px 24px;border-radius:8px;text-decoration:none;">Run a scan</a>

    <!-- Launch Check is included on the free plan (1 per month, enforced in
         api/launch-check.js). Live URL scanning is NOT - it is Pro-only - so it
         is deliberately absent here: every recipient is on the free plan and
         would hit a 403. -->
    <div style="border-top:1px solid #E5E7EB;margin:26px 0 0;padding-top:20px;">
      <p style="color:#111827;font-size:0.95rem;font-weight:600;margin:0 0 8px;">Already deployed? Check the site itself</p>
      <p style="color:#374151;font-size:0.94rem;line-height:1.65;margin:0 0 14px;">
        Your plan also includes <strong style="color:#0F766E;">one free Launch Check a month</strong>. Give it your URL and VibeSafe opens the app in a real browser, clicks through it the way a first-time visitor would, and reports what actually breaks &mdash; dead pages, console errors, failed requests &mdash; with screenshots and a readiness score.
      </p>
      <a href="${SITE}/dashboard" style="display:inline-block;border:1px solid #0F766E;color:#0F766E;font-weight:600;font-size:0.92rem;padding:10px 20px;border-radius:8px;text-decoration:none;">Run a Launch Check</a>
    </div>

    <p style="color:#6B7280;font-size:0.88rem;line-height:1.6;margin:22px 0 0;">
      Scanning from VS Code or Cursor instead? <a href="${SITE}/user-guide#vscode" style="color:#0F766E;">Here is how to connect your editor</a> &mdash; it takes about a minute.
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
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const secret = process.env.CRON_SECRET;
  if (!secret || (req.headers['authorization'] || '') !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (!SERVICE_KEY) return res.status(500).json({ error: 'SUPABASE_SERVICE_ROLE_KEY not set' });

  const send = !!(req.body && req.body.send === true);
  // {"only":"you@example.com"} restricts the run to one address. Combined with
  // {"send":true} that is a test send; on its own it is still a dry run.
  const only = (req.body && typeof req.body.only === 'string') ? req.body.only : null;

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
    const sampleNew = list.find(r => r.newcomer) || { email: 'someone@example.com', left: FREE_SCAN_LIMIT, newcomer: true };
    const sampleRet = list.find(r => !r.newcomer) || { email: 'someone@example.com', left: 7, newcomer: false };
    const tok = async (e) => `${SITE}/api/unsubscribe?email=${encodeURIComponent(e)}&t=${await unsubToken(e)}`;
    return res.status(200).json({
      dryRun: true,
      note: only
        ? `Nothing was sent. POST {"send":true,"only":"${only}"} to deliver this single test.`
        : 'Nothing was sent. POST {"send":true} to actually deliver.',
      testMode: !!only,
      recipientCount: list.length,
      neverScanned: list.filter(r => r.newcomer).length,
      returning: list.filter(r => !r.newcomer).length,
      recipients: list,
      previews: {
        newcomer: { subject: subjectFor(sampleNew), html: html(sampleNew, await tok(sampleNew.email)) },
        returning: { subject: subjectFor(sampleRet), html: html(sampleRet, await tok(sampleRet.email)) },
      },
    });
  }

  const results = { sent: 0, failed: 0, errors: [], testMode: !!only, recipients: list.map(r => r.email) };
  let first = true;
  for (const r of list) {
    // Resend allows 10 requests/second; 150ms keeps us comfortably under it.
    if (!first) await new Promise(x => setTimeout(x, 150));
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
          subject: subjectFor(r),
          html: html(r, unsubUrl),
          headers: {
            'List-Unsubscribe': `<${unsubUrl}>`,
            'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
          },
        }),
      });
      if (!resp.ok) throw new Error(`${resp.status} ${await resp.text()}`);
      results.sent++;
    } catch (err) {
      results.failed++;
      results.errors.push({ email: r.email, error: String(err.message).slice(0, 200) });
    }
  }
  return res.status(200).json(results);
}
