// TEMPORARY DIAGNOSTIC — delete once the cron secret is confirmed working.
//
// Repeated 401s from /api/send-usage-nudge after a fresh production deploy
// leave two possibilities that look identical from outside:
//   1. CRON_SECRET is not reaching the function at all (wrong environment,
//      or saved but never picked up), in which case the guard
//      `if (!secret || ...)` returns 401 no matter what is sent.
//   2. It is set, but to a different value than the one being typed.
//
// This reports presence and length only. It never returns the value, and a
// length alone is not usable to authenticate. Open it in a browser.
export default function handler(req, res) {
  const names = ['CRON_SECRET', 'SUPABASE_SERVICE_ROLE_KEY', 'RESEND_API_KEY', 'RESEND_FROM_EMAIL'];
  const out = {};
  for (const n of names) {
    const v = process.env[n];
    out[n] = v
      ? { present: true, length: v.length, startsWith: v.slice(0, 3) }
      : { present: false };
  }
  // RESEND_FROM_EMAIL is not a secret, so show it in full: if it still reads
  // onboarding@resend.dev the mail is going out from Resend's shared test
  // domain rather than vibesafe.info.
  out.RESEND_FROM_EMAIL_value = process.env.RESEND_FROM_EMAIL || '(not set — code falls back to onboarding@resend.dev)';
  out.vercelEnv = process.env.VERCEL_ENV || '(unknown)';
  res.status(200).json(out);
}
