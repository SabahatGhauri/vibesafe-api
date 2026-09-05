#!/usr/bin/env python3
"""
Phase 2 of the AI-generated-code security study: scan the frozen corpus and
store the findings.

    VIBESAFE_API_KEY=vibesafe_sk_...  \
    SUPABASE_SERVICE_ROLE_KEY=eyJ...  \
    python scripts/corpus-scan.py corpus-2026-09-05.json --limit 25

Start with --limit. Every scan is a model call, so measure the cost of 25
before committing to ~1,200. Reruns are free to repeat: each (run, repo, file)
is stored once and already-scanned files are skipped.

WHAT IS AND IS NOT STORED
-------------------------
Findings, score, language and file path go to corpus_scans. The source code
does not, and neither does anything read out of a .env. The scanner already
discards code after analysing it; this keeps that true for the study.

RUN THIS ON A PRO ACCOUNT
-------------------------
The free tier is 10 scans/month and the `source` bypass was closed, so a free
key will start returning 403 almost immediately. That is the limit working
correctly, not a bug to route around.
"""

import argparse, json, os, sys, time, urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SUPABASE_URL = 'https://uxsmmpujxbzdgxxburxr.supabase.co'
SCAN_API     = 'https://vibesafe-api.vercel.app/api/scan'
SOURCE_TAG   = 'corpus-study'      # keeps these out of customer analytics

# Cap what is sent per file. Bounds cost, and matches the size the scanner is
# tuned for. Truncation is recorded so it can be reported rather than hidden.
MAX_CHARS = 40_000

API_KEY = os.environ.get('VIBESAFE_API_KEY', '').strip()
SERVICE = os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '').strip()

EXT_LANG = {'.ts': 'typescript', '.tsx': 'typescript', '.js': 'javascript',
            '.jsx': 'javascript', '.sql': 'sql', '.py': 'python', '.go': 'go'}


def http(url, data=None, headers=None, timeout=120):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode() if data is not None else None,
        headers=headers or {},
        method='POST' if data is not None else 'GET')
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode('utf-8', 'replace')
    return json.loads(body) if body.strip().startswith(('{', '[')) else body


def sb(path, method='GET', payload=None, prefer=None):
    h = {'apikey': SERVICE, 'Authorization': f'Bearer {SERVICE}',
         'Content-Type': 'application/json'}
    if prefer:
        h['Prefer'] = prefer
    req = urllib.request.Request(f'{SUPABASE_URL}/rest/v1/{path}',
                                 data=json.dumps(payload).encode() if payload else None,
                                 headers=h, method=method)
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read().decode('utf-8', 'replace')
    return json.loads(body) if body.strip().startswith(('{', '[')) else body


def already_scanned(run):
    """(repo, path) pairs already stored, so a rerun resumes rather than repeats."""
    done, offset = set(), 0
    while True:
        rows = sb(f'corpus_scans?corpus_run=eq.{run}&select=repo,file_path'
                  f'&limit=1000&offset={offset}')
        if not rows:
            break
        done |= {(r['repo'], r['file_path']) for r in rows}
        if len(rows) < 1000:
            break
        offset += 1000
    return done


def fetch_raw(repo, branch, path):
    url = f'https://raw.githubusercontent.com/{repo}/{branch}/{urllib.parse.quote(path)}'
    req = urllib.request.Request(url, headers={'User-Agent': 'vibesafe-corpus-study'})
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read().decode('utf-8', 'replace')


def scan_one(job):
    repo, builder, branch, path = job['repo'], job['builder'], job['branch'], job['path']
    rec = {'corpus_run': job['run'], 'repo': repo, 'builder': builder,
           'file_path': path, 'truncated': False}
    try:
        code = fetch_raw(repo, branch, path)
    except Exception as e:
        rec['error'] = f'fetch: {str(e)[:150]}'
        return rec

    rec['file_bytes'] = len(code)
    if len(code) > MAX_CHARS:
        code = code[:MAX_CHARS]
        rec['truncated'] = True

    ext = '.' + path.rsplit('.', 1)[-1].lower()
    try:
        res = http(SCAN_API,
                   data={'code': code,
                         'language': EXT_LANG.get(ext, 'javascript'),
                         'source': SOURCE_TAG},
                   headers={'Content-Type': 'application/json',
                            'Authorization': f'Bearer {API_KEY}'})
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', 'replace')[:200]
        rec['error'] = f'scan {e.code}: {detail}'
        return rec
    except Exception as e:
        rec['error'] = f'scan: {str(e)[:150]}'
        return rec

    if not isinstance(res, dict):
        rec['error'] = 'unexpected response'
        return rec

    rec['score']       = res.get('score')
    rec['language']    = (res.get('language') or '')[:40]
    rec['issue_count'] = len(res.get('issues') or [])
    # Findings only. The submitted code is never written back.
    rec['results']     = {'issues': res.get('issues') or [],
                          'summary': res.get('summary'),
                          'passed':  res.get('passed')}
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('corpus')
    ap.add_argument('--limit', type=int, default=0, help='scan only N files (pilot run)')
    ap.add_argument('--workers', type=int, default=3)
    args = ap.parse_args()

    if not API_KEY:
        sys.exit('VIBESAFE_API_KEY is not set (must belong to a Pro/Team account).')
    if not SERVICE:
        sys.exit('SUPABASE_SERVICE_ROLE_KEY is not set.')

    data = json.load(open(args.corpus))
    run = os.path.basename(args.corpus).replace('.json', '')
    print(f'run: {run}   repos: {len(data["repos"])}')

    done = already_scanned(run)
    print(f'already scanned: {len(done)}')

    jobs = [{'run': run, 'repo': r['full_name'], 'builder': r.get('builder'),
             'branch': r['branch'], 'path': p}
            for r in data['repos'] for p in r['files']
            if (r['full_name'], p) not in done]
    if args.limit:
        jobs = jobs[:args.limit]
    print(f'queued: {len(jobs)} files\n')
    if not jobs:
        return

    ok = failed = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(scan_one, j): j for j in jobs}
        for i, fut in enumerate(as_completed(futures), 1):
            rec = fut.result()
            try:
                sb('corpus_scans', 'POST', rec,
                   prefer='resolution=merge-duplicates,return=minimal')
            except Exception as e:
                print(f'  store failed for {rec["repo"]}: {str(e)[:90]}')
            if rec.get('error'):
                failed += 1
                if failed <= 5:
                    print(f'  ! {rec["repo"]}: {rec["error"][:110]}')
                # A quota 403 means the key is not on an unlimited plan; stop
                # rather than burn through hundreds of identical failures.
                if '403' in str(rec.get('error')) and 'limit' in str(rec.get('error')).lower():
                    print('\n  STOPPING: the API key hit its scan limit. '
                          'Use a Pro/Team key.')
                    break
            else:
                ok += 1
            if i % 10 == 0 or i == len(jobs):
                rate = i / max(1, time.time() - t0)
                print(f'  {i}/{len(jobs)}  ok={ok} failed={failed}  '
                      f'{rate:.2f}/s  eta {int((len(jobs)-i)/max(rate,0.01)/60)}m',
                      flush=True)

    print(f'\ndone: {ok} scanned, {failed} failed, {time.time()-t0:.0f}s')
    print('\nNext: measure the Anthropic cost of this run before scaling up.')
    print("Then analyse with:  select i->>'category', count(distinct repo) "
          "from corpus_scans, lateral jsonb_array_elements(results->'issues') i "
          f"where corpus_run='{run}' group by 1 order by 2 desc;")


if __name__ == '__main__':
    main()
