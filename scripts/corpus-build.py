#!/usr/bin/env python3
"""
Phase 1 of the AI-generated-code security study: build a frozen, reproducible
corpus of public repositories that were genuinely built with an AI app builder.

    GITHUB_TOKEN=ghp_... python scripts/corpus-build.py

Writes corpus-<date>.json — the artefact published alongside the findings, so a
reader can rebuild the same list and check the numbers.

WHY THE HARD FINGERPRINT
------------------------
Searching README text for "lovable.dev" returns ~288,000 repos, but sampling 30
of them showed only half carry an actual Lovable artefact — the rest are
tutorials, articles and people who merely mention it. Selecting on a build
artefact (.lovable, lovable-tagger in package.json, .bolt/) instead of on prose
is the difference between "repos built with the tool" and "repos that talk
about it", and the study only means something if it is the former.

DECISIONS FIXED BEFORE ANY DATA WAS SEEN
----------------------------------------
Changing these after seeing results is how an honest study becomes a dishonest
one, so they live here as constants and are copied into the output file.

  * one repo per OWNER          - a single prolific builder cannot dominate
  * forks excluded              - one popular template would otherwise count many times
  * MIN_ROOT_ENTRIES            - empty scaffolds are not applications
  * fixed file-selection rule   - files are never hand-picked after looking
  * fixed RANDOM_SEED           - the sample is reproducible

WHAT THIS SCRIPT DOES NOT DO
----------------------------
It never reads file CONTENTS, only names and sizes. Committed .env files are
recorded as present/absent and nothing more: those are strangers' live
credentials, and there is no version of reading them that is defensible. The
same rule applies to the published results — aggregate numbers only, never a
repository name, path or snippet.
"""

import json, os, random, sys, time, urllib.parse, urllib.request
from datetime import datetime, timezone

# ── Fixed study parameters ────────────────────────────────────────────────────
QUERIES = [
    ('lovable', '"lovable-tagger" in:file filename:package.json'),
    ('lovable', 'filename:.lovable'),
    ('bolt',    'filename:config.json path:.bolt'),
    ('v0',      '"Generated with v0" in:file filename:README.md'),
]
TARGET_REPOS        = 400          # size of the final frozen corpus
MAX_FILES_PER_REPO  = 3
MIN_ROOT_ENTRIES    = 8            # below this it is a scaffold, not an app
RANDOM_SEED         = 20260905

# Server-side and config files, where security findings actually live. A
# client-only component is not where a leaked service key or a missing auth
# check shows up. Ordered by directory, then largest first.
FILE_DIR_HINTS  = ('api/', 'server/', 'routes/', 'lib/', 'src/pages/api/',
                   'supabase/', 'functions/', 'backend/')
FILE_EXTENSIONS = ('.ts', '.js', '.tsx', '.jsx', '.sql', '.py', '.go')
SKIP_PATH_PARTS = ('node_modules/', '/dist/', '/build/', '.min.',
                   'test', 'spec', '__mocks__', '/public/')

GH = 'https://api.github.com'
TOKEN = os.environ.get('GITHUB_TOKEN', '').strip()
CACHE_PATH = 'corpus-cache.json'


def api(path, params=None):
    """One authenticated GitHub call, with rate-limit handling."""
    url = GH + path + ('?' + urllib.parse.urlencode(params) if params else '')
    req = urllib.request.Request(url, headers={
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {TOKEN}',
        'User-Agent': 'vibesafe-corpus-study',
        'X-GitHub-Api-Version': '2022-11-28',
    })
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                remaining = r.headers.get('X-RateLimit-Remaining')
                if remaining is not None and int(remaining) < 3:
                    reset = int(r.headers.get('X-RateLimit-Reset', 0))
                    wait = max(5, reset - int(time.time()) + 2)
                    print(f'    rate limit reached, waiting {wait}s', flush=True)
                    time.sleep(wait)
                return json.loads(r.read().decode('utf-8', 'replace'))
        except urllib.error.HTTPError as e:
            if e.code in (401,):
                sys.exit('GitHub rejected the token (401). Check GITHUB_TOKEN — '
                         'a classic PAT is ~40 chars and starts ghp_.')
            if e.code in (403, 429):        # secondary rate limit
                wait = 20 * (attempt + 1)
                print(f'    throttled ({e.code}), waiting {wait}s', flush=True)
                time.sleep(wait)
                continue
            if e.code == 404:
                return None
            raise
        except Exception:
            time.sleep(5)
    return None


def search_candidates():
    """Code search on build artefacts. Returns {full_name: builder}."""
    found, calls = {}, 0
    for builder, q in QUERIES:
        print(f'  searching [{builder}]: {q}', flush=True)
        for page in range(1, 11):            # code search caps at 1000 results
            d = api('/search/code', {'q': q, 'per_page': 100, 'page': page})
            calls += 1
            if d is None and page == 1:
                # Distinguish an auth/permission failure from a genuine empty
                # result. Treating the first as the second is how a broken run
                # silently reports zero candidates.
                sys.exit('GitHub code search failed on the first page. The token is '
                         'probably invalid or expired — verify $env:GITHUB_TOKEN.')
            if not d or not d.get('items'):
                break
            for item in d['items']:
                repo = item.get('repository', {})
                name = repo.get('full_name')
                if name and not repo.get('fork') and name not in found:
                    found[name] = builder
            print(f'    page {page}: running total {len(found)}', flush=True)
            if len(d['items']) < 100:
                break
            time.sleep(2.5)                  # code search: 30 req/min
    return found, calls


def pick_files(tree):
    """Fixed selection rule. Never varied per repo, never chosen by eye."""
    cands = []
    for n in tree:
        p = n.get('path', '')
        if n.get('type') != 'blob':
            continue
        low = p.lower()
        if any(s in low for s in SKIP_PATH_PARTS):
            continue
        if not low.endswith(FILE_EXTENSIONS):
            continue
        size = n.get('size', 0)
        if size < 200 or size > 120_000:     # trivial, or too big to scan
            continue
        in_hint = any(h in low for h in FILE_DIR_HINTS)
        cands.append((0 if in_hint else 1, -size, p))
    cands.sort()
    return [p for _, _, p in cands[:MAX_FILES_PER_REPO]]


def main():
    if not TOKEN:
        sys.exit('GITHUB_TOKEN is not set. Create a read-only token with '
                 'public_repo scope and export it before running.')

    started = datetime.now(timezone.utc)
    print('Phase 1 — building corpus\n')

    cache = {}
    if os.path.exists(CACHE_PATH):
        cache = json.load(open(CACHE_PATH))
        print(f'  resuming: {len(cache)} repos already inspected\n')

    candidates, search_calls = search_candidates()
    print(f'\n  candidate repos from code search: {len(candidates)}\n')

    # One repo per owner, chosen deterministically so a rerun picks the same one.
    by_owner = {}
    for full in sorted(candidates):
        by_owner.setdefault(full.split('/')[0], full)
    one_per_owner = sorted(by_owner.values())
    print(f'  after one-per-owner: {len(one_per_owner)}')

    random.seed(RANDOM_SEED)
    random.shuffle(one_per_owner)

    corpus, excluded = [], {'too_small': 0, 'no_files': 0, 'unreachable': 0}
    repo_calls = 0

    for full in one_per_owner:
        if len(corpus) >= TARGET_REPOS:
            break
        if full in cache:
            rec = cache[full]
        else:
            meta = api(f'/repos/{full}')
            repo_calls += 1
            if not meta or meta.get('archived'):
                excluded['unreachable'] += 1
                continue
            branch = meta.get('default_branch', 'main')
            tree = api(f'/repos/{full}/git/trees/{branch}', {'recursive': '1'})
            repo_calls += 1
            if not tree or 'tree' not in tree:
                excluded['unreachable'] += 1
                continue
            nodes = tree['tree']
            root = [n['path'] for n in nodes if '/' not in n.get('path', '')]
            rec = {
                'full_name': full,
                'builder': candidates[full],
                'branch': branch,
                'stars': meta.get('stargazers_count', 0),
                'pushed_at': meta.get('pushed_at'),
                'root_entries': len(root),
                # Presence only. Contents are never fetched.
                'env_committed': '.env' in root,
                'has_supabase': any(n.get('path', '').startswith('supabase/') for n in nodes),
                'files': pick_files(nodes),
            }
            cache[full] = rec
            if len(cache) % 25 == 0:
                json.dump(cache, open(CACHE_PATH, 'w'), indent=1)
                print(f'    …{len(corpus)} accepted / {len(cache)} inspected', flush=True)
            time.sleep(0.8)

        if rec['root_entries'] < MIN_ROOT_ENTRIES:
            excluded['too_small'] += 1
            continue
        if not rec['files']:
            excluded['no_files'] += 1
            continue
        corpus.append(rec)

    json.dump(cache, open(CACHE_PATH, 'w'), indent=1)

    out = {
        'generated_at': started.isoformat(),
        'method': {
            'queries': [q for _, q in QUERIES],
            'selection': 'build artefact present, not README text',
            'one_repo_per_owner': True,
            'forks_excluded': True,
            'min_root_entries': MIN_ROOT_ENTRIES,
            'max_files_per_repo': MAX_FILES_PER_REPO,
            'file_rule': f'dirs {FILE_DIR_HINTS} first, then largest; '
                         f'ext {FILE_EXTENSIONS}; skip {SKIP_PATH_PARTS}',
            'random_seed': RANDOM_SEED,
        },
        'counts': {
            'candidates_from_search': len(candidates),
            'after_one_per_owner': len(one_per_owner),
            'inspected': len(cache),
            'excluded': excluded,
            'corpus_size': len(corpus),
        },
        'api_calls': {'search': search_calls, 'repo': repo_calls},
        'repos': corpus,
    }
    name = f"corpus-{started.strftime('%Y-%m-%d')}.json"
    if not corpus:
        sys.exit(f'Refusing to write {name}: the corpus is empty. '
                 'The cache is intact, so nothing was lost — fix the token and rerun.')
    if os.path.exists(name):
        prev = json.load(open(name))
        if len(prev.get('repos', [])) > len(corpus):
            os.replace(name, name + '.bak')
            print(f'  existing {name} was larger; kept as {name}.bak')
    json.dump(out, open(name, 'w'), indent=1)

    env_n = sum(1 for r in corpus if r['env_committed'])
    sup_n = sum(1 for r in corpus if r['has_supabase'])
    files = sum(len(r['files']) for r in corpus)

    print(f"\n  wrote {name}")
    print(f"  corpus size          : {len(corpus)}")
    print(f"  excluded             : {excluded}")
    print(f"  files queued to scan : {files}")
    print(f"  .env committed       : {env_n} ({100*env_n/max(1,len(corpus)):.0f}%)  <- pre-scan signal")
    print(f"  uses supabase        : {sup_n} ({100*sup_n/max(1,len(corpus)):.0f}%)")
    print(f"  GitHub calls used    : {search_calls + repo_calls}")


if __name__ == '__main__':
    main()
