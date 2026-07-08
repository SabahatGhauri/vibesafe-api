// VibeSafe Team Invite — sends email via Resend (free tier: 100 emails/day)
// Env vars needed in Vercel: RESEND_API_KEY
// Get a free key at resend.com — takes 2 minutes, no card required

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_hgCpN6tsYqEiCkyvJm06qQ_1Ddlvznn';

async function getUserFromToken(token) {
  const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { 'Authorization': `Bearer ${token}`, 'apikey': SUPABASE_ANON_KEY }
  });
  if (!res.ok) return null;
  return res.json();
}

async function sendInviteEmail({ to, inviterEmail, teamName, inviteToken }) {
  const acceptUrl = `https://vibesafe.info/accept-invite.html?token=${inviteToken}`;

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#080C18;font-family:'Inter',Arial,sans-serif;">
  <div style="max-width:520px;margin:40px auto;background:#0F1624;border:1px solid #1E2D42;border-radius:16px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#00D4FF,#7C3AED);padding:3px 0 0;"></div>
    <div style="padding:36px 40px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:28px;">
        <div style="width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#00D4FF,#7C3AED);display:flex;align-items:center;justify-content:center;font-size:18px;">🛡️</div>
        <span style="font-size:1.2rem;font-weight:700;color:#F1F5F9;">VibeSafe</span>
      </div>
      <h1 style="font-size:1.35rem;font-weight:700;color:#F1F5F9;margin:0 0 12px;">You've been invited to a team</h1>
      <p style="color:#94A3B8;font-size:0.95rem;line-height:1.6;margin:0 0 8px;">
        <strong style="color:#F1F5F9;">${inviterEmail}</strong> has invited you to join their VibeSafe team.
      </p>
      <p style="color:#94A3B8;font-size:0.95rem;line-height:1.6;margin:0 0 28px;">
        Once you accept, you'll be able to run security scans and see your team's shared scan history.
      </p>
      <a href="${acceptUrl}" style="display:inline-block;background:linear-gradient(135deg,#00D4FF,#0891B2);color:#080C18;font-weight:700;font-size:0.95rem;padding:14px 28px;border-radius:9px;text-decoration:none;">
        Accept invite →
      </a>
      <p style="color:#475569;font-size:0.78rem;margin:24px 0 0;line-height:1.5;">
        If you weren't expecting this, you can ignore this email.<br>
        This invite was sent from <a href="https://vibesafe.info" style="color:#00D4FF;">vibesafe.info</a>
      </p>
    </div>
  </div>
</body>
</html>`;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM_EMAIL || 'VibeSafe <onboarding@resend.dev>',
      to: [to],
      subject: `${inviterEmail} invited you to their VibeSafe team`,
      html,
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Resend error: ${res.status} ${err}`);
  }
  return res.json();
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  const user = await getUserFromToken(token);
  if (!user) return res.status(401).json({ error: 'Session expired' });

  const { email, teamId, inviteToken } = req.body || {};
  if (!email || !teamId || !inviteToken) {
    return res.status(400).json({ error: 'Missing email, teamId, or inviteToken' });
  }

  if (!process.env.RESEND_API_KEY) {
    // Graceful degradation — Resend not configured yet, invite was still recorded in DB
    console.warn('RESEND_API_KEY not set — invite recorded but email not sent');
    return res.status(200).json({ sent: false, reason: 'email_not_configured' });
  }

  try {
    await sendInviteEmail({
      to: email,
      inviterEmail: user.email,
      teamName: 'your team',
      inviteToken,
    });
    return res.status(200).json({ sent: true });
  } catch (err) {
    console.error('Invite email failed:', err.message);
    // Don't fail the whole invite flow if email fails
    return res.status(200).json({ sent: false, reason: err.message });
  }
}
