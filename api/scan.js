// VibeSafe Scan API — Vercel Edge Function
// Your Anthropic API key is stored securely in Vercel environment variables
// Users never see it. Their code is never stored.

export const config = { runtime: 'edge' };

const ALLOWED_ORIGIN = 'https://www.vibesafe.info';

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

SEVERITY RULES:
- critical: security vulnerabilities, exposed secrets, SQL injection, XSS, path traversal, auth bypass, anything that could cause data breach or hack
- warning: missing error handling, missing await on async calls, null pointer risks, weak comparisons, deprecated functions, logic bugs
- info: code quality improvements, best practices, performance suggestions

SCORING:
- Start at 100
- Subtract 18 for each critical issue
- Subtract 8 for each warning
- Subtract 2 for each info
- Minimum score is 5
- If no issues found, score is 100

Be thorough. A non-technical founder is trusting you with the security of their product.
Only return the JSON object. Nothing else.`;

export default async function handler(req) {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400',
      },
    });
  }

  // Only allow POST
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: corsHeaders(),
    });
  }

  try {
    const body = await req.json();
    const { code, language } = body;

    // Basic validation
    if (!code || typeof code !== 'string') {
      return new Response(JSON.stringify({ error: 'No code provided' }), {
        status: 400,
        headers: corsHeaders(),
      });
    }

    if (code.length > 50000) {
      return new Response(JSON.stringify({ error: 'Code too large. Maximum 50,000 characters.' }), {
        status: 400,
        headers: corsHeaders(),
      });
    }

    // Call Claude API securely from the server
    const claudeResponse = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 4000,
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
      const err = await claudeResponse.text();
      console.error('Claude API error:', err);
      return new Response(JSON.stringify({ error: 'Scan service temporarily unavailable. Please try again.' }), {
        status: 502,
        headers: corsHeaders(),
      });
    }

    const claudeData = await claudeResponse.json();
    const rawText = claudeData.content?.[0]?.text;

    if (!rawText) {
      return new Response(JSON.stringify({ error: 'No response from scan engine' }), {
        status: 500,
        headers: corsHeaders(),
      });
    }

    // Parse the JSON response from Claude
    let scanResult;
    try {
      // Strip any accidental markdown fences
      const cleaned = rawText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      scanResult = JSON.parse(cleaned);
    } catch (parseErr) {
      console.error('Parse error:', parseErr, 'Raw:', rawText);
      return new Response(JSON.stringify({ error: 'Failed to parse scan results. Please try again.' }), {
        status: 500,
        headers: corsHeaders(),
      });
    }

    // Return results — code is never stored
    return new Response(JSON.stringify(scanResult), {
      status: 200,
      headers: {
        ...corsHeaders(),
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store', // Never cache — each scan is unique
      },
    });

  } catch (err) {
    console.error('Scan error:', err);
    return new Response(JSON.stringify({ error: 'An unexpected error occurred. Please try again.' }), {
      status: 500,
      headers: corsHeaders(),
    });
  }
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };
}
