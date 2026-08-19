// One-click unsubscribe for marketing email.
// Linked from every promotional send; transactional mail (receipts, security
// alerts) is deliberately NOT gated on this list.
//
// The token is an HMAC of the address keyed on the service-role key, so a link
// can't be forged for an arbitrary address and no opt-out state has to be
// guessable from the URL.

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

export async function unsubToken(email) {
  const crypto = await import('crypto');
  return crypto.default
    .createHmac('sha256', SERVICE_KEY)
    .update(String(email).trim().toLowerCase())
    .digest('hex')
    .slice(0, 32);
}

function page(title, body) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · VibeSafe</title></head>
<body style="margin:0;background:#080C18;color:#F1F5F9;font-family:Inter,Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;">
<div style="max-width:440px;padding:36px;text-align:center;">
<div style="font-size:2rem;margin-bottom:12px;">&#128737;&#65039;</div>
<h1 style="font-size:1.25rem;margin:0 0 10px;">${title}</h1>
<p style="color:#94A3B8;font-size:0.95rem;line-height:1.6;margin:0 0 20px;">${body}</p>
<a href="https://www.vibesafe.info" style="color:#00D4FF;text-decoration:none;font-size:0.9rem;">Back to VibeSafe &rarr;</a>
</div></body></html>`;
}

export default async function handler(req, res) {
  const email = String((req.query && req.query.email) || '').trim().toLowerCase();
  const token = String((req.query && req.query.t) || '').trim();

  if (!email || !token) {
    res.setHeader('Content-Type','text/html; charset=utf-8'); return res.status(400).send(page('Invalid link', 'This unsubscribe link is incomplete. Please use the link from the bottom of the email.'));
  }
  if (!SERVICE_KEY) {
    res.setHeader('Content-Type','text/html; charset=utf-8'); return res.status(500).send(page('Not available', 'Unsubscribe is not configured on this server. Email contact@vibesafe.info and we will remove you manually.'));
  }
  if (token !== (await unsubToken(email))) {
    res.setHeader('Content-Type','text/html; charset=utf-8'); return res.status(403).send(page('Invalid link', 'This unsubscribe link is not valid. Email contact@vibesafe.info and we will remove you manually.'));
  }

  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/email_optout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SERVICE_KEY,
        'Authorization': `Bearer ${SERVICE_KEY}`,
        'Prefer': 'resolution=merge-duplicates',
      },
      body: JSON.stringify({ email, reason: 'one-click' }),
    });
    if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  } catch (err) {
    console.error('Unsubscribe failed:', err.message);
    res.setHeader('Content-Type','text/html; charset=utf-8'); return res.status(500).send(page('Something went wrong', 'We could not record that just now. Email contact@vibesafe.info and we will remove you manually.'));
  }

  res.setHeader('Content-Type','text/html; charset=utf-8'); return res.status(200).send(page(
    'You are unsubscribed',
    `<strong>${email}</strong> will no longer receive VibeSafe offers or product updates. You will still get essential account email like payment receipts and security alerts.`
  ));
}
