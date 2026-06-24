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
      "fix_explanation": "<plain-English explanation of the fix in one sentence>",
      "owasp": "<the OWASP Top 10 (2021) category this maps to, e.g. 'A01:2021 Broken Access Control', 'A03:2021 Injection', 'A07:2021 Identification & Authentication Failures'. Use empty string if it is not a security issue.>"
    }
  ],
  "passed": [
    "<one thing the code does well>",
    "<another positive if applicable>"
  ],
  "fixedCode": "<the COMPLETE corrected version of the submitted code with ALL issues fixed together as one coherent file>"
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

SCORING (security-focused — the score means "is this safe to ship", not "is this stylistically perfect"):
- Start at 100
- Subtract 22 for each critical issue (real breach risk: secrets, injection, auth bypass, RLS)
- Subtract 7 for each warning (will break or misbehave: missing error handling, missing await, logic bugs)
- Do NOT reduce the score for info items. Best-practice / style / minor suggestions are listed for the user but must NOT lower the score.
- So: code with no criticals and no warnings scores 100, even if it has info suggestions.
- Minimum score is 5
- If no issues found, score is 100
- Do NOT manufacture trivial issues to pad the list. Only report genuine security, correctness, or reliability problems. If the code is secure and works, say so with a high score.

FIXED CODE (the "fixedCode" field) — THIS IS CRITICAL:
- Return the COMPLETE corrected file, ready to paste and run — never snippets or partial code.
- Fix EVERY critical and warning issue you listed, plus any other obvious security or quality problem, in one coherent rewrite.
- The fixedCode MUST be clean enough to pass a fresh security scan with a score of 95 or higher. If you would still flag the fixedCode for a critical or warning, fix that too before returning it.
- Leave NO critical or warning unresolved. Only minor best-practice (info) items may remain.
- Keep the same programming language and overall structure; change only what is necessary.
- For secrets, replace hardcoded values with environment-variable reads (e.g. process.env.X / os.environ.get('X')).
- Add proper error handling, awaits, input validation, and parameterised queries wherever the issues require it.
- Output the fixedCode as a normal JSON string (escape newlines as \\n). Do NOT wrap it in markdown code fences.
- If the code has no issues, set "fixedCode" to the original code unchanged.

MULTI-FILE / WHOLE-REPO SCANS:
- If the code contains "// ===== FILE: <path> =====" markers, it is a whole repository made of several files.
- In the "line" field, include the file path, e.g. "src/api/users.js: Line 12".
- Look for cross-file problems too (e.g. a secret defined in one file and used insecurely in another).
- For "fixedCode", return only the single most important corrected file (the one with the worst issue), not every file.

Be thorough. A non-technical founder is trusting you with the security of their product.
Only return the JSON object. Nothing else.`;

// ── GITHUB HELPERS ──
function ghHeaders() {
  const h = { 'User-Agent': 'VibeSafe-Scanner', 'Accept': 'application/vnd.github+json' };
  if (process.env.GITHUB_TOKEN) h['Authorization'] = 'Bearer ' + process.env.GITHUB_TOKEN;
  return h;
}

function langFromPath(p) {
  if (/\.(jsx?|mjs|cjs)$/i.test(p)) return 'JavaScript';
  if (/\.(tsx?)$/i.test(p)) return 'TypeScript';
  if (/\.py$/i.test(p)) return 'Python';
  if (/\.java$/i.test(p)) return 'Java';
  if (/\.cs$/i.test(p)) return '.NET / C#';
  return 'code';
}

// ── WHOLE-REPO FETCHER (#7) ──
// Lists a public repo's files via the GitHub API, then pulls the relevant
// source + dependency-manifest files (capped) and concatenates them with file
// markers so the scanner sees the whole project at once.
async function fetchGitHubRepo(owner, repo, branch) {
  // resolve default branch if not given
  if (!branch) {
    const meta = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers: ghHeaders() });
    if (meta.status === 403) throw new Error('GitHub rate limit reached. Please try again in a few minutes.');
    if (!meta.ok) throw new Error('Could not access that repository. Make sure it is public.');
    branch = (await meta.json()).default_branch || 'main';
  }

  const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, { headers: ghHeaders() });
  if (!treeRes.ok) throw new Error('Could not read the repository file list. Make sure it is public.');
  const treeData = await treeRes.json();
  const tree = treeData.tree || [];

  const CODE_EXT = /\.(jsx?|mjs|cjs|tsx?|py|java|cs|go|rb|php)$/i;
  const MANIFEST = /(^|\/)(package\.json|requirements\.txt|Pipfile|composer\.json|Gemfile)$/i;
  const SKIP_DIR = /(^|\/)(node_modules|dist|build|out|vendor|\.next|\.git|coverage|__pycache__|\.venv|venv|migrations)\//i;

  const candidates = tree.filter(function (f) {
    return f.type === 'blob' && f.size && f.size < 60000 && !SKIP_DIR.test(f.path)
      && (CODE_EXT.test(f.path) || MANIFEST.test(f.path));
  });
  // manifests first (cheap + needed for dependency scan), then smaller files
  candidates.sort(function (a, b) {
    const am = MANIFEST.test(a.path) ? 0 : 1, bm = MANIFEST.test(b.path) ? 0 : 1;
    if (am !== bm) return am - bm;
    return a.size - b.size;
  });

  const MAX_TOTAL = 45000, MAX_FILES = 25;
  let combined = '', total = 0, used = 0;
  const manifests = [];
  const langs = {};

  for (const f of candidates) {
    if (total >= MAX_TOTAL || used >= MAX_FILES) break;
    const raw = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${f.path}`, { headers: { 'User-Agent': 'VibeSafe-Scanner' } });
    if (!raw.ok) continue;
    let content = await raw.text();
    if (!content || content.length < 3) continue;
    if (content.length > 12000) content = content.slice(0, 12000) + '\n// …(truncated)…';
    if (MANIFEST.test(f.path)) manifests.push({ path: f.path, content: content });
    combined += `\n\n// ===== FILE: ${f.path} =====\n` + content;
    total += content.length; used++;
    const l = langFromPath(f.path); if (l !== 'code') langs[l] = (langs[l] || 0) + 1;
  }

  if (!combined) throw new Error('No scannable code files found in that repository.');
  const language = Object.keys(langs).sort(function (a, b) { return langs[b] - langs[a]; })[0] || 'multiple';
  return { code: combined.slice(0, 50000), language: language, filesScanned: used, manifests: manifests };
}

// ── GITHUB CODE FETCHER ──
async function fetchGitHubCode(url) {
  let rawUrl = url.trim();

  // Whole-repo URL (no /blob/ file) → scan the entire project (#7)
  const repoMatch = rawUrl.match(/github\.com\/([^\/]+)\/([^\/]+?)(?:\/tree\/([^\/]+?))?\/?$/i);
  if (repoMatch && !rawUrl.includes('/blob/')) {
    const owner = repoMatch[1];
    const repo = repoMatch[2].replace(/\.git$/, '');
    const branch = repoMatch[3] || null;
    return await fetchGitHubRepo(owner, repo, branch);
  }

  if (rawUrl.includes('github.com') && rawUrl.includes('/blob/')) {
    rawUrl = rawUrl
      .replace('github.com', 'raw.githubusercontent.com')
      .replace('/blob/', '/');
  }

  const res = await fetch(rawUrl, { headers: { 'User-Agent': 'VibeSafe-Scanner' } });
  if (!res.ok) {
    throw new Error('Could not access that file. Make sure the repository is public and the URL points to a specific file.');
  }

  const fetchedCode = await res.text();
  if (!fetchedCode || fetchedCode.length < 5) {
    throw new Error('That file appears to be empty.');
  }

  return { code: fetchedCode, language: langFromPath(rawUrl), manifests: [] };
}

// ── DEPENDENCY VULNERABILITY SCAN (#8) ──
// Parses package.json / requirements.txt and asks OSV.dev (free, no key) whether
// any pinned dependency has a published security advisory. Returns scan issues.
function cleanVersion(v) {
  if (typeof v !== 'string') return '';
  const m = v.match(/[0-9]+\.[0-9]+(?:\.[0-9]+)?/);
  return m ? m[0] : '';
}

async function scanDependencies(manifests) {
  const deps = [];
  for (const m of manifests) {
    if (/package\.json$/i.test(m.path)) {
      try {
        const pkg = JSON.parse(m.content);
        const all = Object.assign({}, pkg.dependencies, pkg.devDependencies);
        for (const name in all) deps.push({ name: name, version: cleanVersion(all[name]), ecosystem: 'npm', file: m.path });
      } catch (e) { /* malformed package.json — skip */ }
    } else if (/requirements\.txt$/i.test(m.path)) {
      m.content.split('\n').forEach(function (line) {
        const mt = line.match(/^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)/);
        if (mt) deps.push({ name: mt[1], version: cleanVersion(mt[2]), ecosystem: 'PyPI', file: m.path });
      });
    }
  }
  if (!deps.length) return [];

  const capped = deps.slice(0, 80);
  let osv;
  try {
    const r = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: capped.map(function (d) {
          return d.version
            ? { package: { name: d.name, ecosystem: d.ecosystem }, version: d.version }
            : { package: { name: d.name, ecosystem: d.ecosystem } };
        })
      })
    });
    if (!r.ok) return [];
    osv = await r.json();
  } catch (e) { return []; }

  const results = (osv && osv.results) || [];
  const issues = [];
  let id = 9000;
  for (let i = 0; i < results.length; i++) {
    const vulns = results[i] && results[i].vulns;
    if (vulns && vulns.length) {
      const d = capped[i];
      const ids = vulns.map(function (v) { return v.id; }).slice(0, 4).join(', ');
      const n = vulns.length;
      issues.push({
        id: id++,
        severity: 'critical',
        type: 'Vulnerable Dependency',
        title: 'Known vulnerability in ' + d.name + (d.version ? ' ' + d.version : ''),
        line: d.file,
        description: d.name + (d.version ? ' ' + d.version : '') + ' has ' + n + ' known security ' + (n > 1 ? 'advisories' : 'advisory') + ' (' + ids + ').',
        impact: 'A published exploit for this package could let an attacker compromise your app.',
        before: '"' + d.name + '": "' + (d.version || '*') + '"',
        after: 'Update ' + d.name + ' to the latest patched version.',
        fix_explanation: 'Upgrade ' + d.name + ' (e.g. npm update / pip install -U) to a version with no known advisories.',
        owasp: 'A06:2021 Vulnerable and Outdated Components'
      });
    }
  }
  return issues;
}

// ── MAIN HANDLER (Node.js serverless) ──
export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = req.body || {};
    let { code, language, githubUrl } = body;
    let manifests = [];
    let filesScanned = 0;

    // GitHub URL scanning
    if (githubUrl && typeof githubUrl === 'string') {
      try {
        const fetched = await fetchGitHubCode(githubUrl);
        code = fetched.code;
        language = language || fetched.language;
        manifests = fetched.manifests || [];
        filesScanned = fetched.filesScanned || 0;
      } catch (ghErr) {
        return res.status(400).json({ error: ghErr.message || 'Could not fetch code from that GitHub URL.' });
      }
    }

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'No code provided' });
    }

    // Detect a pasted dependency manifest so we can vuln-scan it too (#8)
    if (manifests.length === 0) {
      if (code.trim().startsWith('{') && /"dependencies"\s*:/.test(code)) {
        manifests.push({ path: 'package.json', content: code });
      } else if (/^\s*[A-Za-z0-9_.\-]+\s*==\s*[0-9]/m.test(code)) {
        manifests.push({ path: 'requirements.txt', content: code });
      }
    }

    if (code.length > 50000) {
      code = code.slice(0, 50000);
    }

    // Call Claude API securely
    const claudeResponse = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 16000, // raised from 4000 so the full fixedCode file isn't truncated (which would break JSON parsing)
        temperature: 0.2,  // low temperature → consistent scans (less re-flagging of new minor issues each pass, so auto-fix converges)
        system: SCAN_SYSTEM_PROMPT,
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
      return res.status(502).json({ error: 'Scan service temporarily unavailable. Please try again.' });
    }

    const claudeData = await claudeResponse.json();
    const rawText = claudeData.content && claudeData.content[0] && claudeData.content[0].text;

    if (!rawText) {
      return res.status(500).json({ error: 'No response from scan engine' });
    }

    let scanResult;
    try {
      const cleaned = rawText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      scanResult = JSON.parse(cleaned);
    } catch (parseErr) {
      console.error('Parse error:', parseErr, 'Raw:', rawText);
      return res.status(500).json({ error: 'Failed to parse scan results. Please try again.' });
    }

    // #8 merge real dependency vulnerabilities (OSV) into the results
    try {
      const depIssues = await scanDependencies(manifests);
      if (depIssues.length) {
        scanResult.issues = (scanResult.issues || []).concat(depIssues);
        scanResult.score = Math.max(5, (typeof scanResult.score === 'number' ? scanResult.score : 100) - depIssues.length * 22);
        scanResult.summary = (scanResult.summary || '') + ' ' + depIssues.length + ' vulnerable ' + (depIssues.length > 1 ? 'dependencies' : 'dependency') + ' detected.';
      }
    } catch (e) { console.error('Dependency scan error:', e); }

    // #7 surface how many files were scanned (whole-repo mode)
    if (filesScanned) scanResult.filesScanned = filesScanned;

    return res.status(200).json(scanResult);

  } catch (err) {
    console.error('Scan error:', err);
    return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
}
