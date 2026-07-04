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
  'price_1TivyfRo8j5JUlBnRmvWu5Iv': 'pro',   // VibeSafe Pro (monthly)
  'price_1Tpb97Ro8j5JUlBnHepa3ud6': 'pro',   // VibeSafe Pro founding offer ($14.50/mo)
  'price_1Tiw10Ro8j5JUlBnTFrmPdf7': 'pro',   // VibeSafe Pro (annual)
  'price_1Tiw2LRo8j5JUlBnpS0ydcCY': 'team',  // VibeSafe Team (monthly)
  'price_1Tiw4oRo8j5JUlBnXc3appvc': 'team',  // VibeSafe Team (annual)
  [process.env.STRIPE_PRICE_PRO_MONTHLY]:    'pro',
  [process.env.STRIPE_PRICE_PRO_ANNUAL]:     'pro',
  [process.env.STRIPE_PRICE_TEAM_MONTHLY]:   'team',
  [process.env.STRIPE_PRICE_TEAM_ANNUAL]:    'team',
};
delete PRICE_TO_PLAN.undefined; // drop unset env keys

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

      // Fallback: no client_reference_id (customer opened the payment link
      // directly) — match their VibeSafe account by checkout email instead.
      if (!userId) {
        const payerEmail = (session.customer_details && session.customer_details.email) || session.customer_email || '';
        if (payerEmail && SUPABASE_SERVICE_KEY) {
          const lookupRes = await fetch(
            `${SUPABASE_URL}/auth/v1/admin/users?page=1&per_page=1&email=${encodeURIComponent(payerEmail)}`,
            { headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` } }
          );
          if (lookupRes.ok) {
            const found = await lookupRes.json();
            const users = found.users || found || [];
            const match = Array.isArray(users)
              ? users.find(u => (u.email || '').toLowerCase() === payerEmail.toLowerCase())
              : null;
            if (match) {
              userId = match.id;
              console.log(`Matched payer by email: ${payerEmail} -> ${userId}`);
            }
          }
        }
      }
      if (!userId) {
        console.warn('checkout.session.completed — no client_reference_id and no email match');
        return res.status(200).json({ received: true });
      }

      // Determine plan from line items or subscription
      let plan = 'pro'; // default upgrade
      const priceId = session.metadata?.price_id ||
        (session.line_items?.data?.[0]?.price?.id);
      if (priceId && PRICE_TO_PLAN[priceId]) {
        plan = PRICE_TO_PLAN[priceId];
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
