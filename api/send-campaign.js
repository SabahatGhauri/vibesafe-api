// One-off marketing campaign sender (founding-offer promo).
//
// SAFETY: dry-run by default. It only sends when the request body explicitly
// says {"send": true} — a bare call returns the recipient list and a rendered
// preview so the campaign can be inspected before anything leaves the server.
//
// Guarded by CRON_SECRET so it can't be triggered by anyone who finds the URL.
// Recipients exclude paying customers (nothing to upsell) and anyone on the
// email_optout list. Every send carries a working unsubscribe link plus the
// List-Unsubscribe headers that mail clients use for one-click opt-out.

import { unsubToken } from './unsubscribe.js';

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const SITE = 'https://www.vibesafe.info';

// Sender identification shown in the footer. CAN-SPAM asks for a physical
// postal address on commercial email; the owner chose to identify the sender
// by legal entity + contact address instead. Set CAMPAIGN_POSTAL_ADDRESS to
// add a street address to this line without a code change.
const POSTAL = process.env.CAMPAIGN_POSTAL_ADDRESS
  || 'VibeSafe &mdash; SG Digital Ventures LLC, Wyoming, USA &middot; <a href="mailto:contact@vibesafe.info" style="color:#64748B;">contact@vibesafe.info</a>';

async function sb(path) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` },
  });
  if (!r.ok) throw new Error(`Supabase ${path}: ${r.status} ${await r.text()}`);
  return r.json();
}

async function recipients() {
  // Everyone with an account, minus paying customers, minus opt-outs.
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

  const seen = new Set();
  const out = [];
  for (const u of users) {
    const email = String(u.email || '').trim().toLowerCase();
    if (!email || seen.has(email)) continue;
    if (paying.has(u.id)) continue;
    if (opted.has(email)) continue;
    seen.add(email);
    out.push(email);
  }
  return out;
}

function html(unsubUrl) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#080C18;font-family:'Inter',Arial,sans-serif;">
  <div style="max-width:520px;margin:40px auto;background:#0F1624;border:1px solid #1E2D42;border-radius:16px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#00D4FF,#7C3AED);padding:3px 0 0;"></div>
    <div style="padding:36px 40px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:26px;">
        <div style="width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#00D4FF,#7C3AED);display:flex;align-items:center;justify-content:center;font-size:18px;">&#128737;&#65039;</div>
        <span style="font-size:1.2rem;font-weight:700;color:#F1F5F9;">VibeSafe</span>
      </div>

      <h1 style="font-size:1.3rem;font-weight:700;color:#F1F5F9;margin:0 0 12px;">Founding offer: 50% off your first 3 months</h1>
      <p style="color:#94A3B8;font-size:0.95rem;line-height:1.65;margin:0 0 18px;">
        You have been scanning on the free plan &mdash; 3 scans a month. The founding
        offer takes VibeSafe Pro to <strong style="color:#10B981;">$14.50/mo for your
        first 3 months</strong> (then $29/mo, cancel any time).
      </p>

      <ul style="color:#CBD5E1;font-size:0.9rem;line-height:1.8;margin:0 0 22px;padding-left:20px;">
        <li>Unlimited security scans</li>
        <li>One-click AI fixes for every issue found</li>
        <li>Live website scanning &mdash; headers, exposed paths, HTTPS</li>
        <li>GitHub file scanning and priority support</li>
      </ul>

      <a href="${SITE}/claim-offer.html" style="display:inline-block;background:linear-gradient(135deg,#00D4FF,#0891B2);color:#080C18;font-weight:700;font-size:0.95rem;padding:14px 28px;border-radius:9px;text-decoration:none;">
        Claim 50% off &rarr;
      </a>

      <p style="color:#64748B;font-size:0.8rem;line-height:1.5;margin:26px 0 0;">
        Not interested in offers? <a href="${unsubUrl}" style="color:#94A3B8;">Unsubscribe</a>.
        You will still get account email like receipts and security alerts.
      </p>
      <p style="color:#475569;font-size:0.72rem;line-height:1.5;margin:12px 0 0;">${POSTAL}</p>
    </div>
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

  if (send && !process.env.RESEND_API_KEY) {
    return res.status(500).json({ error: 'RESEND_API_KEY not set' });
  }

  let list;
  try {
    list = await recipients();
  } catch (err) {
    return res.status(500).json({ error: 'Could not build recipient list: ' + err.message });
  }

  if (!send) {
    const sample = list[0] || 'someone@example.com';
    return res.status(200).json({
      dryRun: true,
      note: 'Nothing was sent. POST {"send":true} to actually deliver.',
      recipientCount: list.length,
      recipients: list,
      postalAddressSet: !!POSTAL,
      subject: 'Your founding offer: 50% off VibeSafe Pro for 3 months',
      previewHtml: html(`${SITE}/api/unsubscribe?email=${encodeURIComponent(sample)}&t=${await unsubToken(sample)}`),
    });
  }

  const results = { sent: 0, failed: 0, errors: [] };
  for (const email of list) {
    const unsubUrl = `${SITE}/api/unsubscribe?email=${encodeURIComponent(email)}&t=${await unsubToken(email)}`;
    try {
      const r = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        },
        body: JSON.stringify({
          from: process.env.RESEND_FROM_EMAIL || 'VibeSafe <onboarding@resend.dev>',
          to: [email],
          subject: 'Your founding offer: 50% off VibeSafe Pro for 3 months',
          html: html(unsubUrl),
          headers: {
            'List-Unsubscribe': `<${unsubUrl}>`,
            'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
          },
        }),
      });
      if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
      results.sent++;
    } catch (err) {
      results.failed++;
      results.errors.push({ email, error: String(err.message).slice(0, 200) });
    }
  }
  return res.status(200).json(results);
}
