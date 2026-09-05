// VibeSafe Scan API — Vercel Serverless Function (Node.js)
// Your Anthropic API key is stored securely in Vercel environment variables.
// Users never see it. Their code is never stored.

const SCAN_SYSTEM_PROMPT = `You are VibeSafe — an expert code security scanner built for non-technical founders.

Analyse the submitted code and identify ALL security vulnerabilities, runtime errors, and code quality issues.

You MUST respond with valid JSON only. No markdown, no explanation outside the JSON.

Return this exact structure:
{
  "language": "detected language name",
  "score": <number 0-100, where 100 = perfectly safe>,
  "summary": "<one sentence summary of overall code health>",
  "issues": [
    {
      "id": <unique number>,
      "severity": "critical" | "warning" | "info",
      "type": "<short category e.g. SQL Injection, Exposed Secret, Missing Await>",
      "title": "<clear issue title>",
      "line": "<e.g. Line 5 or Lines 5-8>",
      "description": "<plain-English explanation of what the issue is and why it is dangerous. Max 2 sentences.>",
      "impact": "<what happens if this is ignored — one sentence>",
      "before": "<the exact problematic code snippet, single line>",
      "after": "<the fixed version of that line>",
      "fix_explanation": "<plain-English explanation of the fix in one sentence>"
    }
  ],
  "passed": [
    "<one thing the code does well>",
    "<another positive if applicable>"
  ]
}

PRIORITISE THESE VIBE-CODING VULNERABILITIES (the ones that cause real breaches):
1. Missing Row-Level Security (RLS) — Supabase/Postgres tables without RLS policies, or app-level-only filtering where the database itself does not enforce that user A cannot read user B's data. This is the #1 cause of vibe-coded app breaches. Flag as CRITICAL — BUT only when the CODE ITSELF shows evidence of it: a table/policy definition created without RLS, or queries that rely solely on client-side filtering. Do NOT flag this just because client code uses a public anon/publishable key — a public key WITH RLS enabled is the correct, secure Supabase pattern, and you cannot see the database configuration from client-side code. Never report "no evidence of RLS" as a finding; you cannot verify backend config you cannot see.
2. Open or misconfigured databases — Supabase/Firebase with public read/write, no auth on database access. Flag as CRITICAL.
3. Exposed SECRET credentials — hardcoded values meant to stay server-side only: service_role keys (sb_secret_, SUPABASE_SERVICE_ROLE_KEY), secret API keys (sk_live_, sk_test_, private tokens), database passwords, JWT SIGNING secrets, cloud provider secret keys. Flag as CRITICAL.
   IMPORTANT — PUBLIC client keys are NOT secrets and must NOT be flagged critical: Supabase anon/publishable keys (sb_publishable_, the public anon JWT), Firebase apiKey config, PUBLISHABLE Stripe keys (pk_live_ / pk_test_), and anything prefixed NEXT_PUBLIC_ / VITE_ / PUBLIC_ are DESIGNED to be shipped in the browser and appear in the client of every Supabase/Lovable/Bolt/Replit app. Do NOT report these as exposed secrets. At most, mention as a single INFO reminding the user to ensure database RLS is enabled. Flagging a public anon/publishable key as critical is a FALSE POSITIVE.
4. Broken authentication & access control — missing auth checks, client-side-only authorization, inverted access logic. Flag as CRITICAL.
5. Hallucinated or non-existent packages — imports of packages that do not exist (slopsquatting risk). Flag as WARNING.
6. SQL injection, XSS, path traversal. Flag as CRITICAL.
7. Prompt-injection risks — if the code reads external content (READMEs, issues, user input, fetched web pages) and passes it to an AI/LLM API without sanitisation, flag it. Indirect prompt injection has an 85% success rate and almost no tool checks for it. Flag as CRITICAL.
8. Logic errors — code that runs but does the wrong thing: inverted conditions, off-by-one errors, wrong comparison operators, incorrect access-control logic. Founders cannot spot these because they did not write the code. Flag as WARNING.
9. Code bloat — dead code, duplicated logic, unnecessary complexity, fake/stubbed implementations that look real but do nothing. Flag as INFO.
10. Missing state handling — a stateful flow (payment, order, subscription, invite, upload, webhook) that only implements the success path, with no branch for the realistic failure states: payment failed, payment pending, webhook retried/duplicated, expired, cancelled, empty/zero-result list. AI-generated code is prone to this because it optimises for "the demo works," not "the demo works when Stripe calls back twice." Flag as WARNING. Only flag when the code shows a real stateful flow with an actual gap — do not require a full state machine for a simple CRUD form, and do not flag a flow that already handles its realistic failure case even if it skips rarer ones. If the missing state is itself a security gap (e.g. an unhandled webhook retry that could double-charge or duplicate a row), flag it as CRITICAL under the relevant existing category instead of here.

SEVERITY RULES:
- critical: RLS issues, open databases, exposed secrets, auth bypass, SQL injection, XSS, path traversal — anything causing data breach
- warning: missing error handling, missing await, null risks, weak comparisons, hallucinated packages, logic bugs, missing state handling
- info: code quality, best practices, performance

SCORING:
- Start at 100
- Subtract 18 for each critical issue
- Subtract 8 for each warning
- Subtract 2 for each info
- Minimum score is 5
- If no issues found, score is 100

AVOID FALSE POSITIVES — a scanner that cries wolf loses trust. Do NOT over-flag:
- Public config is NOT a vulnerability: the Supabase project URL / project ref, publishable/anon keys, Firebase config, and publishable Stripe keys are public by design. Do not flag them, and NEVER report the same public value (e.g. a URL + its key) as multiple separate issues.
- innerHTML / XSS: only flag when USER-CONTROLLED or EXTERNAL data (URL params, form input, fetched content, database values) flows into innerHTML / document.write / dangerouslySetInnerHTML. Do NOT flag innerHTML that only assigns static, developer-authored strings.
- CSRF: APIs that send credentials via an Authorization/Bearer header (fetch/XHR, Supabase, most SPAs) are NOT vulnerable to classic CSRF. Do not ask for CSRF tokens there. Only raise CSRF for cookie-session form posts.
- OAuth redirects built from window.location.origin are fine when the provider validates redirect URLs against an allow-list (Supabase, Auth0, etc.). Do not flag as critical.
- Missing Content-Security-Policy is INFO at most, and may already be set via an HTTP header you cannot see. Never critical.
- Weak-but-present controls (e.g. a 6-char minimum password) are WARNING or INFO, not critical.
- Missing state handling: do not flag every payment/order flow just for existing. Only flag when the code plausibly reaches a real failure state (calls a payment/webhook API, has a multi-step flow) and visibly has no branch for it. A single-page contact form or static content has no "states" to miss.
- When torn between two severities, choose the LOWER one. Under-flagging a nitpick is far better than raising a false critical. Every "critical" must be a change that, ignored, plausibly leads to a real breach.

FIX QUALITY RULES — the before/after pair is applied to the user's file automatically, so a bad fix ships broken code:
- \`after\` must be a DROP-IN replacement for \`before\` that leaves the file valid. Do not introduce \`await\` unless the enclosing function is already \`async\`. Do not change a line's statement type in a way that breaks the surrounding block.
- Do not reference identifiers the submitted code does not already have. If the correct fix needs a new import, library or helper (bcrypt, an auth middleware, a Stripe client), then either keep \`after\` self-contained, or OMIT \`before\`/\`after\` entirely and explain the change in \`fix_explanation\`. A suggestion the user applies by hand is far better than a replacement that throws ReferenceError.
- Use the escaping that matches the OUTPUT CONTEXT. HTML output needs HTML-entity escaping — \`encodeURIComponent\` is URL encoding, and using it for HTML both corrupts the displayed text and signals the wrong fix. For SQL use parameterised queries; for shell use argument arrays.
- If the replacement can throw (signature verification, JSON parsing, network calls), include the error handling that makes it correct, or omit \`before\`/\`after\` and describe the full change.
- When an issue is about something MISSING (an unhandled state, an absent check), a one-line substitution usually cannot express it. Omit \`before\`/\`after\` and explain what to add instead of forcing a misleading one-liner.
- Never emit a \`before\`/\`after\` pair you are not confident keeps the code running. Omitting them is always the safer answer.

Be thorough but precise. A non-technical founder is trusting you — an accurate, calm report builds more trust than an inflated, scary one.
Only return the JSON object. Nothing else.`;

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_hgCpN6tsYqEiCkyvJm06qQ_1Ddlvznn';
const FREE_SCAN_LIMIT = 10;

const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// Resolve the caller to a Supabase user id from either:
//  - a Supabase session JWT (the website holds one), or
//  - a long-lived VibeSafe API key `vibesafe_sk_...` (the VS Code extension).
// Returns { userId, readAuth } where readAuth is the header pair to use for
// follow-up plan/scan-count reads.
async function resolveUser(token) {
  if (token.startsWith('vibesafe_sk_')) {
    // API key path — resolve to a user id via the SECURITY DEFINER function.
    const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/get_user_by_api_key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY, 'Authorization': `Bearer ${SUPABASE_ANON_KEY}` },
      body: JSON.stringify({ k: token }),
    });
    if (!res.ok) return { error: 'Invalid API key. Generate a new one at vibesafe.info.' };
    const userId = await res.json();
    if (!userId) return { error: 'Invalid API key. Generate a new one at vibesafe.info.' };
    // Reads for an API-key caller need the service role (no user JWT to satisfy RLS).
    const readAuth = SERVICE_KEY
      ? { 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}` }
      : null;
    return { userId, readAuth, source: 'vscode_extension' };
  }

  // Supabase session JWT path (website).
  const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { 'Authorization': `Bearer ${token}`, 'apikey': SUPABASE_ANON_KEY }
  });
  if (!userRes.ok) return { error: 'Session expired. Please sign in again.' };
  const userData = await userRes.json();
  return { userId: userData.id, readAuth: { 'apikey': SUPABASE_ANON_KEY, 'Authorization': `Bearer ${token}` }, source: 'website' };
}

// Maps the model's free-text issue type onto a fixed taxonomy so the stored
// corpus can be counted. Ordered: the first pattern that matches wins, so more
// specific rules must come before broader ones ("Missing Row-Level Security"
// before the generic auth rule, since both mention access).
const CATEGORY_RULES = [
  // Ordered: first match wins, so specific patterns precede general ones.
  // The security entries below the RLS rule were previously falling through to
  // 'Other' -- they existed in OWASP_TYPE_RULES but had no category of their
  // own, so a finding could read "A01 Broken Access Control" while its category
  // said "Other". 54 of the 147 'Other' issues were critical.
  [/row[- ]?level security|\brls\b/i,                      'Missing Row-Level Security'],
  [/path traversal|directory traversal|local file inclusion|\blfi\b/i, 'Path Traversal'],
  [/\bidor\b|insecure direct object/i,                     'Insecure Direct Object Reference'],
  [/open redirect/i,                                       'Open Redirect'],
  [/\bssrf\b|server[- ]side request forgery/i,             'Server-Side Request Forgery'],
  [/\bcors\b|cross[- ]origin/i,                            'CORS Misconfiguration'],
  [/unverified webhook|webhook.*(signature|verif)|signature verification/i, 'Unverified Webhook'],
  [/plaintext password|password.*(compar|stored|storage)|weak hash|\bmd5\b|\bsha1\b|unencrypted/i,
                                                           'Insecure Password Handling'],
  [/prompt injection|command injection|template injection|code injection|\beval\(/i, 'Code Injection'],
  [/rate limit/i,                                          'Missing Rate Limiting'],
  [/cookie.*(flag|secure|httponly|samesite)|insecure cookie/i,  'Insecure Cookie'],
  [/exposed secret|hardcoded|api key|credential|token/i,   'Exposed Secret'],
  [/information (leak|disclos)|error detail|sensitive data|data exposure|stack trace|verbose error|debug mode/i,
                                                           'Information Disclosure'],
  [/sql injection|sqli/i,                                  'SQL Injection'],
  [/xss|cross[- ]site scripting|unsafe html|css injection|innerhtml/i, 'Cross-Site Scripting'],
  [/csrf|cross[- ]site request/i,                          'CSRF'],
  [/auth|access control|permission|authoriz/i,             'Broken Authentication & Access Control'],
  [/await|async/i,                                         'Missing Await'],
  [/input validation|sanitiz|unvalidated|missing validation/i, 'Missing Input Validation'],
  [/missing state|unhandled state|payment failed|payment pending|webhook retr/i, 'Missing State Handling'],
  [/error handling|exception handling|unhandled|try.?catch|error parameter|error variable|missing error response|return on error/i,
                                                           'Missing Error Handling'],
  [/dependency|package|cve|vulnerable lib/i,               'Vulnerable Dependency'],
  [/security header|\bcsp\b|content[- ]security|subresource integrity|referrer policy|x-content-type|noopener/i,
                                                           'Missing Security Header'],
  // Not a finding about the user's app -- the scanner could not read the input.
  // Kept separate so parse failures never inflate a published issue rate.
  [/invalid code|parse error|truncated|incomplete code|malformed|wrong language|invalid submission|line ending|inconsistent syntax/i,
                                                           'Unscannable Input'],
  [/syntax error/i,                                        'Syntax Error'],
  [/logic error|assignment instead/i,                      'Logic Error'],
  [/undefined variable|not invoked|invocation|parenthes|missing (function )?argument|semicolon|declaration|implicit global|out.?of.?bounds|type mismatch|runtime error|array index|null reference|dead code|no-?op|non-deterministic|missing interface field/i,
                                                           'Runtime Defect'],
  [/accessibility|\ba11y\b|aria[- ]|screen reader/i,        'Accessibility'],
  [/code quality|readability|maintainab|code style|best practice|code structure|duplicate (id|css|class|animation)|conflicting @keyframes|mixed quote|type safety|placeholder data|approximate/i,
                                                           'Code Quality'],
];


function canonicalCategory(type) {
  const t = String(type || '').trim();
  if (!t) return 'Other';
  for (const [re, label] of CATEGORY_RULES) if (re.test(t)) return label;
  return 'Other';
}

// Maps our canonical category onto OWASP Top 10:2025 (owasp.org/Top10/2025).
// Deliberately partial: reliability problems like a missing await or a logic bug
// are real defects but are NOT OWASP application-security risks, so they map to
// null rather than being forced into a bucket to make coverage look complete.
const OWASP_2025 = {
  'Missing Row-Level Security':             { id: 'A01', name: 'Broken Access Control' },
  'Path Traversal':                         { id: 'A01', name: 'Broken Access Control' },
  'Insecure Direct Object Reference':       { id: 'A01', name: 'Broken Access Control' },
  'Open Redirect':                          { id: 'A01', name: 'Broken Access Control' },
  'Server-Side Request Forgery':            { id: 'A01', name: 'Broken Access Control' },
  'CORS Misconfiguration':                  { id: 'A02', name: 'Security Misconfiguration' },
  'Insecure Cookie':                        { id: 'A02', name: 'Security Misconfiguration' },
  'Information Disclosure':                 { id: 'A02', name: 'Security Misconfiguration' },
  'Missing Rate Limiting':                  { id: 'A02', name: 'Security Misconfiguration' },
  'Insecure Password Handling':             { id: 'A04', name: 'Cryptographic Failures' },
  'Code Injection':                         { id: 'A05', name: 'Injection' },
  'Unverified Webhook':                     { id: 'A08', name: 'Software and Data Integrity Failures' },
  'Broken Authentication & Access Control': { id: 'A01', name: 'Broken Access Control' },
  'CSRF':                                   { id: 'A01', name: 'Broken Access Control' },
  'Missing Security Header':                { id: 'A02', name: 'Security Misconfiguration' },
  'Vulnerable Dependency':                  { id: 'A03', name: 'Software Supply Chain Failures' },
  'SQL Injection':                          { id: 'A05', name: 'Injection' },
  'Cross-Site Scripting':                   { id: 'A05', name: 'Injection' },
  'Missing Input Validation':               { id: 'A05', name: 'Injection' },
  'Exposed Secret':                         { id: 'A07', name: 'Authentication Failures' },
  'Missing Error Handling':                 { id: 'A10', name: 'Mishandling of Exceptional Conditions' },
  'Missing State Handling':                 { id: 'A10', name: 'Mishandling of Exceptional Conditions' },
  // Intentionally unmapped: Missing Await, Logic Error, Syntax Error, Code Quality, Other
};

// Checked against the model's raw issue type BEFORE the category map, because the
// canonical taxonomy is coarser than OWASP: it lumps authentication in with access
// control, and has no bucket at all for CORS, path traversal or webhook verification.
// Ordered — first match wins, so specific patterns come before general ones.
const OWASP_TYPE_RULES = [
  [/path traversal|directory traversal|local file inclusion|\blfi\b/i, 'A01', 'Broken Access Control'],
  [/\bssrf\b|server[- ]side request forgery/i,                          'A01', 'Broken Access Control'],
  [/\bidor\b|insecure direct object/i,                                  'A01', 'Broken Access Control'],
  [/\bcors\b|cross[- ]origin/i,                                         'A02', 'Security Misconfiguration'],
  [/debug mode|verbose error|stack trace exposed|directory listing/i,   'A02', 'Security Misconfiguration'],
  [/hallucinat|slopsquat|does not exist|non-existent package/i,         'A03', 'Software Supply Chain Failures'],
  [/plaintext password|password.*(compar|stored)|weak hash|\bmd5\b|\bsha1\b|unencrypted/i,
                                                                        'A04', 'Cryptographic Failures'],
  [/prompt injection|command injection|template injection/i,            'A05', 'Injection'],
  [/broken authentication|authentication failure|weak password|missing authentication/i,
                                                                        'A07', 'Authentication Failures'],
  [/unverified webhook|webhook.*(signature|verif)|signature verification|integrity check/i,
                                                                        'A08', 'Software and Data Integrity Failures'],
  [/logging|monitoring|audit trail|alerting/i,                          'A09', 'Security Logging and Alerting Failures'],
];

function owaspFor(category, type) {
  const t = String(type || '');
  for (const [re, id, name] of OWASP_TYPE_RULES) {
    if (re.test(t)) return { id, name };
  }
  return OWASP_2025[category] || null;
}

async function getUserAndCheckLimit(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return { error: 'Authentication required. Please sign in.' };

  const resolved = await resolveUser(token);
  if (resolved.error) return resolved;
  const { userId, readAuth, source } = resolved;

  // If we couldn't get read credentials (API key but no service role configured),
  // allow the scan — the extension user is the account owner. Limit enforcement
  // still applies on the website path.
  if (!readAuth) return { userId, plan: 'unknown', source };

  const planRes = await fetch(`${SUPABASE_URL}/rest/v1/vibesafe_plans?id=eq.${userId}&select=plan`, {
    headers: readAuth
  });
  const planData = await planRes.json();
  const plan = (planData[0] && planData[0].plan) || 'free';
  if (plan === 'pro' || plan === 'team') return { userId, plan, source };

  const start = new Date();
  start.setDate(1); start.setHours(0, 0, 0, 0);
  // Count from the server-recorded events table (covers BOTH website and
  // extension scans) — the client-written `scans` table misses extension scans,
  // which let extension users bypass the free limit.
  let count = 0;
  if (SERVICE_KEY) {
    const countRes = await fetch(
      `${SUPABASE_URL}/rest/v1/extension_events?user_id=eq.${userId}&event=eq.scan_success&created_at=gte.${start.toISOString()}&select=id`,
      { headers: { 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}`, 'Prefer': 'count=exact' } }
    );
    count = parseInt((countRes.headers.get('content-range') || '').split('/')[1] || '0', 10);
  } else {
    const countRes = await fetch(
      `${SUPABASE_URL}/rest/v1/scans?user_id=eq.${userId}&created_at=gte.${start.toISOString()}&select=id`,
      { headers: { ...readAuth, 'Prefer': 'count=exact' } }
    );
    count = parseInt((countRes.headers.get('content-range') || '').split('/')[1] || '0', 10);
  }

  if (count >= FREE_SCAN_LIMIT) {
    return { error: `You have used all ${FREE_SCAN_LIMIT} free scans this month. Upgrade to Pro for unlimited scans.`, code: 'limit_reached', userId, source };
  }
  return { userId, plan, source };
}

// Privacy-safe analytics: record a scan event server-side (metadata only, never code).
// MUST be awaited: on serverless, un-awaited fetches are killed when the response
// returns, silently dropping events. Errors are swallowed so it never breaks a scan.
async function recordScanEvent(fields) {
  if (!SERVICE_KEY) return;
  // Synthetic traffic (scheduled health checks, calibration runs) must not
  // pollute the analytics that drive the admin dashboard.
  if (['health-check', 'calibration-test'].includes(fields.source)) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/extension_events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SERVICE_KEY,
        'Authorization': `Bearer ${SERVICE_KEY}`,
        'Prefer': 'return=minimal',
      },
      body: JSON.stringify(fields),
    });
  } catch (e) { /* analytics must never throw */ }
}

// ── GITHUB CODE FETCHER ──
async function fetchGitHubCode(url, githubToken) {
  const trimmed = url.trim();

  // SECURITY: restrict to GitHub's own hosts before doing anything else. The
  // fallback branch below used to fetch `trimmed` verbatim whenever it didn't
  // match the github.com/.../blob/... pattern — any other URL (including
  // internal/link-local/metadata addresses) was fetched server-side with no
  // validation. Fixed 2026-08-14.
  let requestedHost;
  try {
    requestedHost = new URL(trimmed).hostname.toLowerCase();
  } catch {
    throw new Error('That doesn\'t look like a valid URL.');
  }
  if (requestedHost !== 'github.com' && requestedHost !== 'raw.githubusercontent.com') {
    throw new Error('Please paste a link to a file on github.com (e.g. .../blob/main/app.js).');
  }

  const isBareRepo = /github\.com\/[^\/]+\/[^\/]+\/?$/.test(trimmed);
  if (isBareRepo) {
    throw new Error('Please paste a link to a specific file (e.g. .../blob/main/app.js), not the whole repo.');
  }

  // Parse owner/repo/ref/path from github.com URL
  const blobMatch = trimmed.match(/github\.com\/([^\/]+)\/([^\/]+)\/blob\/([^\/]+)\/(.+)/);

  let fetchedCode;
  let resolvedUrl = trimmed;

  if (blobMatch && githubToken) {
    // Use GitHub API — supports private repos
    const [, owner, repo, ref, path] = blobMatch;
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}?ref=${ref}`;
    const apiRes = await fetch(apiUrl, {
      headers: {
        'Authorization': `Bearer ${githubToken}`,
        'Accept': 'application/vnd.github.raw+json',
        'User-Agent': 'VibeSafe-Scanner',
        'X-GitHub-Api-Version': '2022-11-28',
      }
    });
    if (!apiRes.ok) {
      const msg = apiRes.status === 404
        ? 'File not found. Check the URL and that you have access to this repository.'
        : 'Could not access that file via GitHub API.';
      throw new Error(msg);
    }
    fetchedCode = await apiRes.text();
    resolvedUrl = path;
  } else {
    // Fallback: raw.githubusercontent.com for public repos
    let rawUrl = trimmed;
    if (rawUrl.includes('github.com') && rawUrl.includes('/blob/')) {
      rawUrl = rawUrl.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/');
    }
    const headers = { 'User-Agent': 'VibeSafe-Scanner' };
    if (githubToken) headers['Authorization'] = `Bearer ${githubToken}`;
    const res = await fetch(rawUrl, { headers });
    if (!res.ok) {
      throw new Error('Could not access that file. Make sure the URL points to a specific file in a repository you have access to.');
    }
    fetchedCode = await res.text();
    resolvedUrl = rawUrl;
  }

  if (!fetchedCode || fetchedCode.length < 5) {
    throw new Error('That file appears to be empty.');
  }

  let language = 'code';
  if (resolvedUrl.endsWith('.js') || resolvedUrl.endsWith('.jsx')) language = 'JavaScript';
  else if (resolvedUrl.endsWith('.ts') || resolvedUrl.endsWith('.tsx')) language = 'TypeScript';
  else if (resolvedUrl.endsWith('.py')) language = 'Python';
  else if (resolvedUrl.endsWith('.java')) language = 'Java';
  else if (resolvedUrl.endsWith('.cs')) language = '.NET / C#';

  return { code: fetchedCode, language };
}

// ── CVE PACKAGE CHECKER (OSV.dev — free, no auth) ──
function extractPackages(code, language) {
  const packages = new Set();
  const lang = (language || '').toLowerCase();

  if (lang === 'python') {
    // import X, from X import Y
    const matches = [...code.matchAll(/^\s*(?:import|from)\s+([a-zA-Z0-9_\-]+)/gm)];
    matches.forEach(m => {
      const name = m[1].split('.')[0];
      if (!['os','sys','re','json','math','time','datetime','pathlib','typing','collections','itertools','functools','io','abc','copy','enum','logging','threading','subprocess','socket','hashlib','base64','urllib','http','email','html','xml','csv','sqlite3','pickle','struct','random','string','traceback','warnings','contextlib','dataclasses','uuid','hmac','secrets','gc','inspect','ast','dis'].includes(name))
        packages.add({ name, ecosystem: 'PyPI' });
    });
  } else {
    // JS/TS: import X from 'pkg', require('pkg'), from 'pkg'
    const matches = [...code.matchAll(/(?:import\s+.*?\s+from\s+|require\s*\(\s*)['"]([^'"./][^'"]*)['"]/g)];
    matches.forEach(m => {
      let name = m[1];
      if (name.startsWith('@')) name = name.split('/').slice(0, 2).join('/');
      else name = name.split('/')[0];
      if (!['react','react-dom','next','vue','svelte','express','path','fs','http','https','crypto','os','url','util','stream','events','buffer','child_process','cluster','net','dns','tls','zlib','querystring','string_decoder','timers','console','process','module','__dirname','__filename'].includes(name))
        packages.add({ name, ecosystem: 'npm' });
    });
  }
  return [...packages].slice(0, 20); // cap at 20 packages per scan
}

async function checkCVEs(packages) {
  if (!packages.length) return [];
  try {
    const queries = packages.map(p => ({ package: { name: p.name, ecosystem: p.ecosystem } }));
    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    const findings = [];
    (data.results || []).forEach((result, i) => {
      const vulns = result.vulns || [];
      if (vulns.length > 0) {
        const pkg = packages[i];
        const topVuln = vulns[0];
        const aliases = (topVuln.aliases || []).filter(a => a.startsWith('CVE-'));
        const cveId = aliases[0] || topVuln.id;
        const severity = topVuln.database_specific?.severity || 'HIGH';
        const isHigh = ['CRITICAL','HIGH'].includes(severity.toUpperCase());
        findings.push({
          id: 9000 + i,
          severity: isHigh ? 'critical' : 'warning',
          type: 'Vulnerable Dependency',
          title: `${pkg.name} has known ${severity} vulnerabilities (${cveId})`,
          line: 'Import / dependency',
          description: `The package "${pkg.name}" has ${vulns.length} known vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} including ${cveId}. ${topVuln.summary || ''}`,
          impact: `Attackers can exploit this known vulnerability in your dependency. Update to the latest patched version immediately.`,
          before: `"${pkg.name}": "<current version>"`,
          after: `"${pkg.name}": "<latest patched version>" // run: ${pkg.ecosystem === 'PyPI' ? 'pip install --upgrade ' + pkg.name : 'npm update ' + pkg.name}`,
          fix_explanation: `Update ${pkg.name} to its latest version to patch ${cveId}.`,
          cve: cveId,
          vuln_count: vulns.length,
        });
      }
    });
    return findings;
  } catch {
    return []; // CVE check failure is non-fatal
  }
}

// Cheap pre-flight guard: does this input plausibly look like code/config, or is it
// junk (e.g. "sfgjghry")? Rejecting junk before the AI call saves cost and doesn't
// burn a user's free scan. Deliberately lenient — real code virtually always has
// punctuation, a keyword, or multiple tokens, so false positives are near-zero.
function looksLikeCode(code) {
  const t = (code || '').trim();
  if (!t) return false;
  if (/[-=(){}\[\].,;:<>/\\"'`+*%!?~^|&$#@]/.test(t)) return true;  // code/config punctuation or operators
  if (/\b(function|const|let|var|def|class|import|export|from|return|if|else|for|while|public|private|async|await|print|console|select|insert|update|create)\b/i.test(t)) return true;
  if (/\s/.test(t) && t.split(/\s+/).filter(Boolean).length >= 3) return true; // 3+ words (prose/config/markup)
  return false;                                                     // single junk token, no code signal (e.g. "sfgjghry")
}

// ── MAIN HANDLER (Node.js serverless) ──
export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const body = req.body || {};
  // A caller may declare its source (e.g. a GitHub Action sends 'github_action').
  // Otherwise it's inferred: extension keys => vscode_extension, JWT => website.
  //
  // SECURITY: recordScanEvent deliberately skips writing an event for the
  // synthetic sources below, and the free-scan limit is enforced by counting
  // those events. Since `source` arrives in the request body, a caller that
  // declared one of those names would run scans that were never recorded and
  // therefore never counted -- unlimited free scans. Those names are reserved
  // for internal tooling and are rejected from client input.
  const RESERVED_SOURCES = ['health-check', 'calibration-test'];
  const rawSource = typeof body.source === 'string' ? body.source.slice(0, 40) : null;
  const declaredSource = (rawSource && !RESERVED_SOURCES.includes(rawSource)) ? rawSource : null;
  const scanType = body.githubUrl ? 'github_url' : 'code';
  let scanUserId = null;
  let scanSource = declaredSource || 'website';

  try {
    const limitCheck = await getUserAndCheckLimit(req);
    scanUserId = limitCheck.userId || null;
    scanSource = declaredSource || limitCheck.source || 'website';
    if (limitCheck.error) {
      await recordScanEvent({
        user_id: scanUserId,
        event: 'scan_failed',
        source: scanSource,
        scan_type: scanType,
        success: false,
        error_message: String(limitCheck.error).slice(0, 200),
      });
      return res.status(403).json({ error: limitCheck.error, code: limitCheck.code });
    }

    let { code, language, githubUrl, githubToken } = body;

    // GitHub URL scanning
    if (githubUrl && typeof githubUrl === 'string') {
      try {
        const fetched = await fetchGitHubCode(githubUrl, githubToken || null);
        code = fetched.code;
        language = language || fetched.language;
      } catch (ghErr) {
        await recordScanEvent({ user_id: scanUserId, event: 'scan_failed', source: scanSource, scan_type: 'github_url', success: false, error_message: 'GitHub fetch failed' });
        return res.status(400).json({ error: ghErr.message || 'Could not fetch code from that GitHub URL.' });
      }
    }

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'No code provided' });
    }

    // Reject obvious non-code before spending an AI call or a free scan.
    if (!looksLikeCode(code)) {
      return res.status(422).json({ error: "That doesn't look like valid code — it looks like random text. Paste real code or a file to scan." });
    }

    if (code.length > 50000) {
      code = code.slice(0, 50000);
    }

    // Kick off the CVE dependency lookup NOW so it overlaps the Claude call
    // (OSV can take up to 5s). We await it after Claude returns.
    const cvePromise = checkCVEs(extractPackages(code, language));

    // Call Claude API securely. The system prompt is cached (5-min TTL) so
    // repeat scans skip re-processing it — faster and cheaper.
    const claudeResponse = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 4000,
        system: [
          { type: 'text', text: SCAN_SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } },
        ],
        messages: [
          {
            role: 'user',
            content: `Please scan this ${language || 'code'} for security vulnerabilities and issues:\n\n\`\`\`${language || ''}\n${code}\n\`\`\``,
          },
        ],
      }),
    });

    if (!claudeResponse.ok) {
      const errText = await claudeResponse.text();
      console.error('Claude API error:', errText);
      await recordScanEvent({ user_id: scanUserId, event: 'scan_failed', source: scanSource, scan_type: scanType, success: false, error_message: 'Scan engine unavailable' });
      return res.status(502).json({ error: 'Scan service temporarily unavailable. Please try again.' });
    }

    const claudeData = await claudeResponse.json();
    const rawText = claudeData.content && claudeData.content[0] && claudeData.content[0].text;

    if (!rawText) {
      await recordScanEvent({ user_id: scanUserId, event: 'scan_failed', source: scanSource, scan_type: scanType, success: false, error_message: 'Empty scan engine response' });
      return res.status(500).json({ error: 'No response from scan engine' });
    }

    let scanResult;
    try {
      const cleaned = rawText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      scanResult = JSON.parse(cleaned);
    } catch (parseErr) {
      console.error('Parse error:', parseErr, 'Raw:', rawText);
      await recordScanEvent({ user_id: scanUserId, event: 'scan_failed', source: scanSource, scan_type: scanType, success: false, error_message: 'Result parse failure' });
      return res.status(500).json({ error: 'Failed to parse scan results. Please try again.' });
    }

    // The model writes issue types as free text, so the same finding arrives
    // under several labels ("Broken Authentication" vs "Broken Authentication &
    // Access Control", "Missing Await" vs "Missing Async/Await"). That is fine
    // for a single report the user reads, but it makes the stored corpus
    // unanalysable — frequency counts split across spellings and understate
    // every category. `category` is a normalised label written alongside the
    // model's original `type`, which is preserved untouched for display.
    if (Array.isArray(scanResult.issues)) {
      for (const issue of scanResult.issues) {
        issue.category = canonicalCategory(issue.type);
        issue.owasp = owaspFor(issue.category, issue.type); // null when not an OWASP risk
      }
    }

    // CVE dependency check — started before the Claude call above, awaited here.
    const cveIssues = await cvePromise;
    if (cveIssues.length > 0) {
      scanResult.issues = [...(scanResult.issues || []), ...cveIssues];
      // Adjust score: -18 per critical CVE, -8 per warning CVE
      const cvePenalty = cveIssues.reduce((sum, i) => sum + (i.severity === 'critical' ? 18 : 8), 0);
      scanResult.score = Math.max(5, (scanResult.score || 100) - cvePenalty);
    }

    await recordScanEvent({
      user_id: scanUserId,
      event: 'scan_success',
      source: scanSource,
      scan_type: scanType,
      language: (language || scanResult.language || '').slice(0, 30),
      score: Number.isFinite(scanResult.score) ? scanResult.score : null,
      issues: (scanResult.issues || []).length,
      extension_version: body.extension_version ? String(body.extension_version).slice(0, 20) : null,
      success: true,
    });
    return res.status(200).json(scanResult);

  } catch (err) {
    console.error('Scan error:', err);
    await recordScanEvent({ user_id: scanUserId, event: 'scan_failed', source: scanSource, scan_type: scanType, success: false, error_message: String(err.message || 'unexpected').slice(0, 200) });
    return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
}
