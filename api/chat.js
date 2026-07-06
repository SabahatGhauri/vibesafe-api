// VibeSafe homepage assistant — server-side proxy so the Anthropic key never
// touches the browser. Fixed system prompt (clients can't override it), tight
// input validation, and a simple per-instance rate limit.

const SYSTEM_PROMPT = `You are the VibeSafe AI Assistant on vibesafe.info. VibeSafe scans AI-generated code for security vulnerabilities, exposed secrets, and bugs, and suggests fixes in plain English. It also offers Launch Check, which tests a deployed app like a real user and gives a launch-readiness score.
Pricing: Free plan 3 scans per month (and 1 Launch Check) forever, Pro plan $29/month with a 15-day free trial (unlimited scans and Launch Checks), Team plan $99/month for up to 10 people.
Privacy: code is scanned in memory and never stored.
For complaints or anything you cannot resolve, direct users to contact@vibesafe.info (24h response).
Keep answers short, warm, and at most 3-4 sentences. Only discuss VibeSafe.`;

// naive per-instance rate limit: 8 requests/min per IP
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear();
  return arr.length > 8;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  if (limited(ip)) return res.status(429).json({ error: 'Too many messages — please slow down.' });

  const raw = (req.body && req.body.messages) || [];
  if (!Array.isArray(raw) || raw.length === 0) return res.status(400).json({ error: 'No messages.' });

  // Strict shape: last 12 turns, user/assistant only, short strings only.
  const messages = raw.slice(-12)
    .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
    .map(m => ({ role: m.role, content: m.content.slice(0, 600) }));
  if (!messages.length || messages[messages.length - 1].role !== 'user') {
    return res.status(400).json({ error: 'Invalid conversation.' });
  }

  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 300,
        system: SYSTEM_PROMPT,
        messages,
      }),
    });
    if (!r.ok) throw new Error('assistant unavailable');
    const data = await r.json();
    const reply = data.content?.[0]?.text || '';
    if (!reply) throw new Error('empty reply');
    return res.status(200).json({ reply });
  } catch (err) {
    return res.status(200).json({ reply: '' }); // client falls back to canned answers
  }
}
