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
1. Missing Row-Level Security (RLS) — Supabase/Postgres tables without RLS policies, or app-level-only filtering where the database itself does not enforce that user A cannot read user B's data. This is the #1 cause of vibe-coded app breaches. Flag as CRITICAL.
2. Open or misconfigured databases — Supabase/Firebase with public read/write, no auth on database access. Flag as CRITICAL.
3. Exposed secrets — hardcoded API keys, tokens, database passwords, JWT secrets. Flag as CRITICAL.
4. Broken authentication & access control — missing auth checks, client-side-only authorization, inverted access logic. Flag as CRITICAL.
5. Hallucinated or non-existent packages — imports of packages that do not exist (slopsquatting risk). Flag as WARNING.
6. SQL injection, XSS, path traversal. Flag as CRITICAL.
7. Prompt-injection risks — if the code reads external content (READMEs, issues, user input, fetched web pages) and passes it to an AI/LLM API without sanitisation, flag it. Indirect prompt injection has an 85% success rate and almost no tool checks for it. Flag as CRITICAL.
8. Logic errors — code that runs but does the wrong thing: inverted conditions, off-by-one errors, wrong comparison operators, incorrect access-control logic. Founders cannot spot these because they did not write the code. Flag as WARNING.
9. Code bloat — dead code, duplicated logic, unnecessary complexity, fake/stubbed implementations that look real but do nothing. Flag as INFO.

SEVERITY RULES:
- critical: RLS issues, open databases, exposed secrets, auth bypass, SQL injection, XSS, path traversal — anything causing data breach
- warning: missing error handling, missing await, null risks, weak comparisons, hallucinated packages, logic bugs
- info: code quality, best practices, performance

SCORING:
- Start at 100
- Subtract 18 for each critical issue
- Subtract 8 for each warning
- Subtract 2 for each info
- Minimum score is 5
- If no issues found, score is 100

Be thorough. A non-technical founder is trusting you with the security of their product.
Only return the JSON object. Nothing else.`;

const SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_hgCpN6tsYqEiCkyvJm06qQ_1Ddlvznn';
const FREE_SCAN_LIMIT = 3;

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
    return { error: `You have used all ${FREE_SCAN_LIMIT} free scans this month. Upgrade to Pro for unlimited scans.`, userId, source };
  }
  return { userId, plan, source };
}

// Privacy-safe analytics: record a scan event server-side (metadata only, never code).
// MUST be awaited: on serverless, un-awaited fetches are killed when the response
// returns, silently dropping events. Errors are swallowed so it never breaks a scan.
async function recordScanEvent(fields) {
  if (!SERVICE_KEY) return;
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
  const declaredSource = typeof body.source === 'string' ? body.source : null;
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
      return res.status(403).json({ error: limitCheck.error });
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
