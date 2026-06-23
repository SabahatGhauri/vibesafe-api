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

SCORING:
- Start at 100
- Subtract 18 for each critical issue
- Subtract 8 for each warning
- Subtract 2 for each info
- Minimum score is 5
- If no issues found, score is 100

FIXED CODE (the "fixedCode" field):
- Return the COMPLETE corrected file, ready to paste and run — never snippets or partial code.
- Apply EVERY issue's fix together in one coherent rewrite so overlapping fixes do not conflict.
- Keep the same programming language and overall structure; change only what is necessary to fix the issues.
- For secrets, replace hardcoded values with environment-variable reads (e.g. process.env.X / os.environ.get('X')).
- Output the fixedCode as a normal JSON string (escape newlines as \\n). Do NOT wrap it in markdown code fences.
- If the code has no issues, set "fixedCode" to the original code unchanged.

Be thorough. A non-technical founder is trusting you with the security of their product.
Only return the JSON object. Nothing else.`;

// ── GITHUB CODE FETCHER ──
async function fetchGitHubCode(url) {
  let rawUrl = url.trim();

  if (rawUrl.includes('github.com') && rawUrl.includes('/blob/')) {
    rawUrl = rawUrl
      .replace('github.com', 'raw.githubusercontent.com')
      .replace('/blob/', '/');
  }

  const isBareRepo = /github\.com\/[^\/]+\/[^\/]+\/?$/.test(rawUrl);
  if (isBareRepo) {
    throw new Error('Please paste a link to a specific file (e.g. .../blob/main/app.js), not the whole repo. Full-repo scanning is coming soon.');
  }

  const res = await fetch(rawUrl, { headers: { 'User-Agent': 'VibeSafe-Scanner' } });
  if (!res.ok) {
    throw new Error('Could not access that file. Make sure the repository is public and the URL points to a specific file.');
  }

  const fetchedCode = await res.text();
  if (!fetchedCode || fetchedCode.length < 5) {
    throw new Error('That file appears to be empty.');
  }

  let language = 'code';
  if (rawUrl.endsWith('.js') || rawUrl.endsWith('.jsx')) language = 'JavaScript';
  else if (rawUrl.endsWith('.ts') || rawUrl.endsWith('.tsx')) language = 'TypeScript';
  else if (rawUrl.endsWith('.py')) language = 'Python';
  else if (rawUrl.endsWith('.java')) language = 'Java';
  else if (rawUrl.endsWith('.cs')) language = '.NET / C#';

  return { code: fetchedCode, language: language };
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

    // GitHub URL scanning
    if (githubUrl && typeof githubUrl === 'string') {
      try {
        const fetched = await fetchGitHubCode(githubUrl);
        code = fetched.code;
        language = language || fetched.language;
      } catch (ghErr) {
        return res.status(400).json({ error: ghErr.message || 'Could not fetch code from that GitHub URL.' });
      }
    }

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'No code provided' });
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

    return res.status(200).json(scanResult);

  } catch (err) {
    console.error('Scan error:', err);
    return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
}
