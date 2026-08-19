// VibeSafe Stripe Webhook Handler
// Listens for Stripe checkout and subscription events → updates vibesafe_plans in Supabase
// Set webhook endpoint in Stripe Dashboard → https://vibesafe-api.vercel.app/api/stripe-webhook
// Events to send: checkout.session.completed, customer.subscription.updated, customer.subscription.deleted

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY; // service role key — bypasses RLS

// Map Stripe price IDs to plan names.
// Price IDs are not secrets (they appear in checkout), so they're hardcoded;
// env vars can override/extend them if prices are ever rotated.
const PRICE_TO_PLAN = {
  // Old Stripe account — kept so subscribers who checked out before the
  // 2026-08-10 account migration don't lose their plan on renewal/cancel.
  'price_1TivyfRo8j5JUlBnRmvWu5Iv': 'pro',   // VibeSafe Pro (monthly)
  'price_1Tpb97Ro8j5JUlBnHepa3ud6': 'pro',   // VibeSafe Pro founding offer ($14.50/mo)
  'price_1Tiw10Ro8j5JUlBnTFrmPdf7': 'pro',   // VibeSafe Pro (annual)
  'price_1Tiw2LRo8j5JUlBnpS0ydcCY': 'team',  // VibeSafe Team (monthly)
  'price_1Tiw4oRo8j5JUlBnXc3appvc': 'team',  // VibeSafe Team (annual)
  // New Stripe account (created 2026-08-10)
  'price_1U2msDLEpu5fZeudRQNe4EGz': 'pro',   // VibeSafe Pro (monthly) — $29/mo
  'price_1U2n1pLEpu5fZeudNofg8esR': 'pro',   // VibeSafe Pro (annual) — $22/mo, billed $264/yr
  'price_1U2n6BLEpu5fZeudEOepFHek': 'team',  // VibeSafe Team (monthly) — $99/mo
  'price_1U2n7ULEpu5fZeud0z0Wj668': 'team',  // VibeSafe Team (annual) — $74/mo, billed $888/yr
  [process.env.STRIPE_PRICE_PRO_MONTHLY]:    'pro',
  [process.env.STRIPE_PRICE_PRO_ANNUAL]:     'pro',
  [process.env.STRIPE_PRICE_TEAM_MONTHLY]:   'team',
  [process.env.STRIPE_PRICE_TEAM_ANNUAL]:    'team',
};
delete PRICE_TO_PLAN.undefined; // drop unset env keys

function activationEmailHtml(plan) {
  const planName = plan === 'team' ? 'Team' : 'Pro';
  const perks = plan === 'team'
    ? ['Unlimited security scans across your whole team', 'One-click AI fixes for every issue found', 'Shared team dashboard with per-member activity', 'Priority support']
    : ['Unlimited security scans', 'One-click AI fixes for every issue found', 'All scan types: code, GitHub, live URL', 'Priority support'];
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#080C18;font-family:'Inter',Arial,sans-serif;">
  <div style="max-width:520px;margin:40px auto;background:#0F1624;border:1px solid #1E2D42;border-radius:16px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#00D4FF,#7C3AED);padding:3px 0 0;"></div>
    <div style="padding:36px 40px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:28px;">
        <img src="https://www.vibesafe.info/favicon-96.png" alt="VibeSafe" width="36" height="36" style="width:36px;height:36px;border-radius:8px;display:block;border:0;">
        <span style="font-size:1.2rem;font-weight:700;color:#F1F5F9;">VibeSafe</span>
      </div>
      <h1 style="font-size:1.3rem;font-weight:700;color:#10B981;margin:0 0 12px;">You're on VibeSafe ${planName} &#127881;</h1>
      <p style="color:#94A3B8;font-size:0.95rem;line-height:1.6;margin:0 0 20px;">
        Your upgrade is active right now &mdash; here's what's unlocked:
      </p>
      <ul style="color:#CBD5E1;font-size:0.9rem;line-height:1.8;margin:0 0 24px;padding-left:20px;">
        ${perks.map(p => `<li>${p}</li>`).join('')}
      </ul>
      <a href="https://www.vibesafe.info/dashboard.html" style="display:inline-block;background:linear-gradient(135deg,#00D4FF,#0891B2);color:#080C18;font-weight:700;font-size:0.95rem;padding:14px 28px;border-radius:9px;text-decoration:none;">
        Open my dashboard &rarr;
      </a>
      <p style="color:#475569;font-size:0.78rem;margin:28px 0 0;line-height:1.5;">
        Manage or cancel your subscription any time from your dashboard. Billing questions? Just reply &mdash; a human reads these.
      </p>
    </div>
  </div>
</body>
</html>`;
}

async function sendActivationEmail(to, plan) {
  if (!process.env.RESEND_API_KEY || !to) return; // best-effort — must never break plan activation
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: process.env.RESEND_FROM_EMAIL || 'VibeSafe <onboarding@resend.dev>',
        to: [to],
        subject: `You're on VibeSafe ${plan === 'team' ? 'Team' : 'Pro'} — here's what's unlocked`,
        html: activationEmailHtml(plan),
      }),
    });
    if (!r.ok) console.error(`Activation email failed: ${r.status} ${await r.text()}`);
  } catch (err) {
    console.error('Activation email send error:', err.message);
  }
}

async function upsertPlan(userId, plan) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/vibesafe_plans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Prefer': 'resolution=merge-duplicates',
    },
    body: JSON.stringify({ id: userId, plan, updated_at: new Date().toISOString() }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Supabase upsert failed: ${res.status} ${text}`);
  }
}

async function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function verifyStripeSignature(rawBody, sigHeader, secret) {
  // Manual HMAC verification — avoids importing stripe SDK
  const crypto = await import('crypto');
  const parts = sigHeader.split(',');
  const tPart = parts.find(p => p.startsWith('t='));
  const v1Part = parts.find(p => p.startsWith('v1='));
  if (!tPart || !v1Part) throw new Error('Invalid Stripe-Signature header');
  const timestamp = tPart.slice(2);
  const signature = v1Part.slice(3);
  const payload = `${timestamp}.${rawBody.toString('utf8')}`;
  const expected = crypto.default
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  if (expected !== signature) throw new Error('Stripe signature mismatch');
  // Reject events older than 5 minutes
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp, 10)) > 300) {
    throw new Error('Stripe event timestamp too old');
  }
}

export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) {
    console.error('STRIPE_WEBHOOK_SECRET not set');
    return res.status(500).json({ error: 'Webhook not configured' });
  }

  let rawBody;
  try {
    rawBody = await getRawBody(req);
  } catch (err) {
    return res.status(400).json({ error: 'Could not read body' });
  }

  const sigHeader = req.headers['stripe-signature'];
  try {
    await verifyStripeSignature(rawBody, sigHeader, webhookSecret);
  } catch (err) {
    console.error('Signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  let event;
  try {
    event = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  console.log('Stripe event:', event.type);

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      let userId = session.client_reference_id;
      // Captured here (not just inside the email-fallback branch below) so it's
      // available for the activation email regardless of which path found the user.
      const payerEmail = ((session.customer_details && session.customer_details.email) || session.customer_email || '').toLowerCase();

      // Fallback: no client_reference_id (customer opened the payment link
      // directly) — match their VibeSafe account by checkout email instead.
      if (!userId) {
        if (payerEmail && SUPABASE_SERVICE_KEY) {
          // Page through auth users to find the account with this email.
          // (The GoTrue admin list API's email filter isn't reliable across versions.)
          for (let page = 1; page <= 10 && !userId; page++) {
            const lookupRes = await fetch(
              `${SUPABASE_URL}/auth/v1/admin/users?page=${page}&per_page=200`,
              { headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` } }
            );
            if (!lookupRes.ok) break;
            const found = await lookupRes.json();
            const users = found.users || (Array.isArray(found) ? found : []);
            if (!users.length) break;
            const match = users.find(u => (u.email || '').toLowerCase() === payerEmail);
            if (match) {
              userId = match.id;
              console.log(`Matched payer by email: ${payerEmail} -> ${userId}`);
            }
            if (users.length < 200) break; // last page
          }
          if (!userId) console.warn(`No account found for checkout email: ${payerEmail}`);
        }
      }
      if (!userId) {
        console.warn('checkout.session.completed — no client_reference_id and no email match');
        return res.status(200).json({ received: true });
      }

      // Determine plan from line items or subscription.
      // IMPORTANT: this account also processes checkouts for other products
      // (e.g. VibeSafe Builder) — a checkout with an unrecognized price is NOT
      // necessarily a VibeSafe purchase, and must never be defaulted to 'pro'.
      // Doing that previously let a completely unrelated product's checkout
      // (matched only by the buyer's email already having a VibeSafe account)
      // silently grant free VibeSafe Pro access. Only upgrade when the price
      // is positively identified as a VibeSafe price — by ID, or by amount as
      // a fallback since `line_items` isn't reliably present on the raw event.
      const priceId = session.metadata?.price_id ||
        (session.line_items?.data?.[0]?.price?.id);
      let plan = priceId ? PRICE_TO_PLAN[priceId] : undefined;
      if (!plan && session.currency === 'usd' && typeof session.amount_total === 'number') {
        // cents — matches the known VibeSafe price points only.
        const AMOUNT_TO_PLAN = { 2900: 'pro', 26400: 'pro', 1450: 'pro', 9900: 'team', 88800: 'team' };
        plan = AMOUNT_TO_PLAN[session.amount_total];
      }
      if (!plan) {
        console.warn(`checkout.session.completed — unrecognized price/amount (priceId=${priceId}, amount=${session.amount_total}), not a VibeSafe plan — skipping (user=${userId})`);
        return res.status(200).json({ received: true });
      }
      // If we have a subscription ID, fetch it to get the price
      if (session.subscription && SUPABASE_SERVICE_KEY) {
        // Store subscription_id for future cancellation handling
        await fetch(`${SUPABASE_URL}/rest/v1/vibesafe_plans`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'apikey': SUPABASE_SERVICE_KEY,
            'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
            'Prefer': 'resolution=merge-duplicates',
          },
          body: JSON.stringify({
            id: userId,
            plan,
            stripe_subscription_id: session.subscription,
            stripe_customer_id: session.customer,
            updated_at: new Date().toISOString(),
          }),
        });
      } else {
        await upsertPlan(userId, plan);
      }
      console.log(`Plan updated: user=${userId} plan=${plan}`);
      // Best-effort — a failed email must never undo the activation above.
      await sendActivationEmail(payerEmail, plan);
    }

    else if (event.type === 'customer.subscription.updated') {
      const sub = event.data.object;
      const priceId = sub.items?.data?.[0]?.price?.id;
      const plan = PRICE_TO_PLAN[priceId];
      const status = sub.status;

      if (!plan) {
        console.warn('Unknown price ID in subscription.updated:', priceId);
        return res.status(200).json({ received: true });
      }

      // Find user by stripe_customer_id
      const userRes = await fetch(
        `${SUPABASE_URL}/rest/v1/vibesafe_plans?stripe_customer_id=eq.${sub.customer}&select=id`,
        { headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` } }
      );
      const users = await userRes.json();
      if (users && users[0]) {
        const activePlan = ['active', 'trialing'].includes(status) ? plan : 'free';
        await upsertPlan(users[0].id, activePlan);
        console.log(`Subscription updated: user=${users[0].id} plan=${activePlan} status=${status}`);
      }
    }

    else if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      const userRes = await fetch(
        `${SUPABASE_URL}/rest/v1/vibesafe_plans?stripe_customer_id=eq.${sub.customer}&select=id`,
        { headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` } }
      );
      const users = await userRes.json();
      if (users && users[0]) {
        await upsertPlan(users[0].id, 'free');
        console.log(`Subscription cancelled: user=${users[0].id} → free`);
      }
    }

    return res.status(200).json({ received: true });

  } catch (err) {
    console.error('Webhook handler error:', err);
    return res.status(500).json({ error: 'Webhook processing failed' });
  }
}
