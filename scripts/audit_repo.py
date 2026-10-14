#!/usr/bin/env python3
"""Read-only GitHub repository authenticity triage. Python 3.9+, no dependencies.

NOT a fake-star classifier or malware scanner. Exposes evidence and blind spots.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

UTC = dt.timezone.utc
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$")
CODE_SUFFIXES = ('.py', '.js', '.jsx', '.ts', '.tsx', '.go', '.rs', '.java', '.c', '.h', '.cpp', '.cs', '.rb', '.php', '.sh', '.swift', '.kt', '.vue', '.svelte')
INSTALL_HOOKS = ('preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly')
SENSITIVE_PATTERNS = (
    ('SHELL_PIPELINE', re.compile(r'(?:curl|wget)\b[^\n]{0,300}\|\s*(?:sh|bash|zsh)\b', re.I)),
    ('ENCODED_EXECUTION', re.compile(r'(?:base64\s+(?:-d|--decode)|\b(?:eval|exec)\s*\(|node\s+-e\b|python\d?\s+-c\b)', re.I)),
    ('CREDENTIAL_PATH', re.compile(r'(?:\.ssh/|\.npmrc\b|\.aws/|GITHUB_TOKEN\b|\.env\b)', re.I)),
    ('REMOTE_FETCH', re.compile(r'(?:\bcurl\b|\bwget\b|Invoke-WebRequest|https?://)', re.I)),
)
CAPABILITY_PATTERNS = (
    ('NODE_CHILD_PROCESS', re.compile(r'(?:node:)?child_process|\b(?:execSync|spawnSync|execFile)\s*\(', re.I)),
    ('CREDENTIALS_ACCESS', re.compile(r'\bctx\.credentials\b|\binject\s*=\s*\[[^]]*[\'\"]credentials[\'\"]', re.I)),
    ('TOOL_INTERCEPTOR', re.compile(r'tools/pre-execute', re.I)),
    ('DYNAMIC_EVAL', re.compile(r'\beval\s*\(', re.I)),
)


def now_utc() -> dt.datetime:
    return dt.datetime.now(UTC)


def when(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.astimezone(UTC) if parsed.tzinfo else None
    except (ValueError, OverflowError):
        return None


def parse_repo(value: str) -> str:
    text = value.strip()
    if text.startswith('git@github.com:'):
        text = text.removeprefix('git@github.com:')
    elif text.startswith('github:'):
        text = text.removeprefix('github:')
    elif '://' in text:
        u = urllib.parse.urlparse(text)
        if u.scheme != 'https' or u.hostname != 'github.com' or u.username or u.password or u.port or u.query or u.fragment:
            raise ValueError('Only https://github.com/OWNER/REPO is accepted')
        text = u.path.lstrip('/')
    if text.endswith('.git'):
        text = text[:-4]
    text = text.strip('/')
    if not REPO_RE.fullmatch(text) or '..' in text:
        raise ValueError('Expected OWNER/REPO (no subpaths, fragments, or unsafe characters)')
    return text


class GitHubError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class StrictRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        old_host = urllib.parse.urlsplit(req.full_url).hostname
        if u.scheme != 'https' or u.hostname != old_host:
            raise GitHubError('Cross-host redirect refused to prevent credential leakage')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class GitHubClient:
    def __init__(self, token: str = '', timeout: int = 12, max_api: int = 20):
        self.token, self.timeout, self.max_api = token, timeout, max_api
        self.api_calls = 0
        self.remaining: int | None = None
        self.opener = urllib.request.build_opener(StrictRedirect())

    def _read(self, url: str, raw: bool = False, accept: str | None = None) -> Any:
        parsed = urllib.parse.urlsplit(url)
        host = 'raw.githubusercontent.com' if raw else 'api.github.com'
        if parsed.scheme != 'https' or parsed.hostname != host:
            raise GitHubError('Refusing non-GitHub host')
        if not raw:
            if self.api_calls >= self.max_api:
                raise GitHubError(f'API budget exhausted (max {self.max_api}); results incomplete')
            self.api_calls += 1
        headers = {'User-Agent': 'github-repo-authenticity-skill/1.0', 'Accept': accept or 'application/vnd.github+json'}
        if self.token and not raw:
            headers['Authorization'] = f'Bearer {self.token}'
        request = urllib.request.Request(url, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                if not raw:
                    rem = response.headers.get('x-ratelimit-remaining')
                    if rem and rem.isdigit():
                        self.remaining = int(rem)
                data = response.read(512 * 1024 + 1)
                if len(data) > 512 * 1024:
                    raise GitHubError('Response exceeds 512 KiB inspection limit')
                return data.decode('utf-8', errors='replace') if raw else json.loads(data)
        except urllib.error.HTTPError as exc:
            description = {403: 'Forbidden / permission or API rate limit', 404: 'Not found / unavailable', 401: 'Unauthorized token', 422: 'Endpoint rejected request'}.get(exc.code, f'HTTP {exc.code}')
            raise GitHubError(description, exc.code) from exc
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            raise GitHubError(f'Network/response error ({type(exc).__name__})') from exc

    def api(self, path: str, query: dict[str, str | int] | None = None, accept: str | None = None) -> Any:
        suffix = '?' + urllib.parse.urlencode(query) if query else ''
        return self._read('https://api.github.com/' + path.lstrip('/') + suffix, accept=accept)

    def raw(self, full_repo: str, sha: str, path: str) -> str:
        if not re.fullmatch('[a-fA-F0-9]{40}', sha):
            raise GitHubError('Missing valid 40-character commit SHA for immutable source inspection')
        if path.startswith('/') or '..' in path.split('/'):
            raise GitHubError('Unsafe file path')
        owner, repo = full_repo.split('/')
        pieces = [owner, repo, sha, *path.split('/')]
        url = 'https://raw.githubusercontent.com/' + '/'.join(urllib.parse.quote(p, safe='') for p in pieces)
        return self._read(url, raw=True)


def signal(code: str, severity: str, observed: str, interpretation: str, url: str) -> dict[str, str]:
    return {'code': code, 'severity': severity, 'observed': observed, 'interpretation': interpretation, 'url': url}


def basic_signals(repo: dict[str, Any], at: dt.datetime) -> list[dict[str, str]]:
    s: list[dict[str, str]] = []
    stars = max(0, int(repo.get('stargazers_count') or 0))
    forks = max(0, int(repo.get('forks_count') or 0))
    subs = max(0, int(repo.get('subscribers_count') or 0))
    size = max(0, int(repo.get('size') or 0))
    created, pushed = when(repo.get('created_at')), when(repo.get('pushed_at'))
    url = repo.get('html_url') or f"https://github.com/{repo.get('full_name','')}"
    age = max(0.1, (at-created).total_seconds()/86400) if created else None
    span = max(0, (pushed-created).total_seconds()/86400) if created and pushed else None
    if stars >= 30:
        ratio = forks / stars
        if ratio < 0.02:
            s.append(signal('LOW_FORK_STAR_RATIO', 'review', f'{forks}/{stars}={ratio:.2%}', 'Low engagement proxy; docs, demos and non-code projects naturally have low forks. No fake-star verdict.', url))
        elif ratio < 0.05:
            s.append(signal('MODEST_FORK_STAR_RATIO', 'context', f'{forks}/{stars}={ratio:.2%}', 'Potential engagement mismatch; cohort baseline needed.', url))
        watcher_ratio = subs / stars
        threshold = .0005 if stars >= 50000 else .001
        if watcher_ratio < threshold:
            s.append(signal('LOW_SUBSCRIBER_STAR_RATIO', 'context', f'{subs}/{stars}={watcher_ratio:.3%}', 'subscribers_count is NOT GitHub watchers_count; notification subscriptions are not representative of stars.', url))
    if stars >= 100 and size < 30:
        s.append(signal('SMALL_REPO_HIGH_STARS', 'review', f'{stars} stars; GitHub size {size} KiB', 'May be a legitimate docs/prompts/config-only repo. Examine actual tree and claimed features.', url))
    if stars >= 200 and span is not None and span < 2:
        s.append(signal('SHORT_PUSH_SPAN', 'review', f'{span:.1f} days from creation to last push; {stars} stars', 'pushed_at is NOT a star history; imported/mirrored repositories can look similar.', url))
    if stars >= 100 and age and age < 7:
        s.append(signal('YOUNG_POPULAR_REPO', 'context', f'{stars} stars in {age:.1f} days since creation', 'Rapid popularity can come from launch publicity; seek actual star history and independent coverage.', url))
    if repo.get('archived'):
        s.append(signal('ARCHIVED_REPOSITORY', 'context', 'Repository archived', 'Not inherently fraudulent; compare against claims of active maintenance.', url))
    if repo.get('fork'):
        s.append(signal('FORK_OF_OTHER_REPO', 'context', 'GitHub fork=true', 'Trace upstream provenance before attributing originality.', url))
    return s


def source_findings(path: str, text: str, base_url: str) -> list[dict[str, str]]:
    findings = []
    for n, line in enumerate(text.splitlines(), 1):
        for code, pattern in CAPABILITY_PATTERNS:
            if pattern.search(line):
                findings.append({'code': code, 'severity': 'review', 'file': path, 'line': n, 'evidence': line.strip()[:180], 'url': f'{base_url}/{path}#L{n}'})
        if len(findings) >= 24:
            break
    return findings


def manifest_findings(path: str, text: str, base_url: str) -> tuple[list[dict[str, str]], list[str]]:
    findings: list[dict[str, str]] = []
    errors: list[str] = []
    try:
        obj = json.loads(text)
        if not isinstance(obj, dict):
            raise ValueError('package.json is not an object')
    except (ValueError, json.JSONDecodeError) as exc:
        return [], [f'{path}: JSON parse failed ({type(exc).__name__})']
    scripts = obj.get('scripts', {})
    if not isinstance(scripts, dict):
        scripts = {}
    for hook in INSTALL_HOOKS:
        command = scripts.get(hook)
        if not isinstance(command, str) or not command.strip():
            continue
        matched = [code for code, rx in SENSITIVE_PATTERNS if rx.search(command)]
        severity = 'high-review' if ('SHELL_PIPELINE' in matched or ('ENCODED_EXECUTION' in matched and 'REMOTE_FETCH' in matched)) else 'review'
        line = next((i for i, ln in enumerate(text.splitlines(), 1) if f'"{hook}"' in ln), 1)
        findings.append({'code': 'INSTALL_HOOK' + (':' + ','.join(matched) if matched else ''), 'severity': severity, 'file': path, 'line': line, 'evidence': f'{hook}: {command[:160]}', 'url': f'{base_url}/{path}#L{line}'})
    for kind in ('dependencies', 'devDependencies', 'optionalDependencies'):
        deps = obj.get(kind)
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            if isinstance(version, str) and re.match(r'^(?:github:|git\+|git://|https?://)', version, re.I):
                findings.append({'code': 'GIT_OR_URL_DEPENDENCY', 'severity': 'review', 'file': path, 'line': 1, 'evidence': f'{kind}: {name} => {version[:120]}', 'url': f'{base_url}/{path}'})
    return findings, errors


def sample_stargazers(client: GitHubClient, repo: str, stars: int, count: int) -> dict[str, Any]:
    """Optional convenience sample, NOT statistical evidence; 2026 GitHub access may be restricted."""
    if count <= 0 or stars <= 0:
        return {'status': 'not_requested'}
    page = max(1, math.ceil(stars / 100))
    try:
        rows = client.api(f'repos/{repo}/stargazers', {'per_page': 100, 'page': page})
        if not isinstance(rows, list):
            raise GitHubError('Unexpected stargazer payload')
        targets = [r.get('login') for r in rows[-count:] if isinstance(r, dict) and isinstance(r.get('login'), str)]
        if not targets:
            return {'status': 'unavailable', 'reason': 'Latest page empty or inaccessible; no conclusions'}
        sparse = 0
        inspected = 0
        for login in targets:
            try:
                person = client.api('users/' + urllib.parse.quote(login, safe=''))
                if not isinstance(person, dict):
                    continue
                inspected += 1
                if (person.get('public_repos') == 0 and person.get('followers') == 0
                        and not person.get('bio') and not person.get('company')):
                    sparse += 1
            except GitHubError:
                continue
        if inspected < 3:
            return {'status': 'insufficient', 'inspected': inspected, 'reason': 'Fewer than 3 accessible profiles'}
        return {'status': 'sampled', 'inspected': inspected, 'sparse_profiles': sparse,
                'ratio': round(sparse / inspected, 3), 'method': 'Latest accessible page; convenience sample; no bot or campaign inference'}
    except GitHubError as exc:
        return {'status': 'unavailable', 'reason': str(exc) + '; GitHub may restrict stargazer endpoints'}


def inspect_deep(client: GitHubClient, repo: str, meta: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {'status': 'partial', 'commit_sha': None, 'tree_truncated': None,
                           'files_observed': 0, 'code_files': 0, 'test_files': 0, 'documentation_files': 0,
                           'readme_headings': [], 'checked_files': [], 'findings': [], 'errors': []}
    branch = meta.get('default_branch') or 'main'
    try:
        info = client.api(f'repos/{repo}/commits/{urllib.parse.quote(branch, safe="")}')
        sha = str(info.get('sha') or '')
        tree_sha = str(info.get('commit', {}).get('tree', {}).get('sha') or '')
        if not re.fullmatch(r'[0-9a-fA-F]{40}', sha) or not re.fullmatch(r'[0-9a-fA-F]{40}', tree_sha):
            raise GitHubError('Unable to pin commit and tree SHA')
        out['commit_sha'] = sha
        out['source_url'] = f'https://github.com/{repo}/tree/{sha}'
    except (GitHubError, AttributeError, TypeError) as exc:
        out['errors'].append('Commit pin failed: ' + str(exc))
        return out
    try:
        tree = client.api(f'repos/{repo}/git/trees/{tree_sha}', {'recursive': 1})
        files = [f for f in tree.get('tree', []) if isinstance(f, dict) and f.get('type') == 'blob' and isinstance(f.get('path'), str)]
        out['tree_truncated'] = bool(tree.get('truncated'))
        out['files_observed'] = len(files)
        out['code_files'] = sum(f['path'].lower().endswith(CODE_SUFFIXES) for f in files)
        out['test_files'] = sum(bool(re.search(r'(^|/)(test|tests|__tests__|spec)(/|\.)', f['path'], re.I)) for f in files)
        out['documentation_files'] = sum(f['path'].lower().endswith(('.md', '.mdx', '.rst')) for f in files)
        known = {f['path']: f for f in files if f.get('size', 0) <= 128*1024}
    except (GitHubError, AttributeError, TypeError) as exc:
        out['errors'].append('Tree inspection failed: ' + str(exc))
        return out
    candidates = [p for p in ('README.md', 'readme.md', 'package.json', 'cordis.patch.yml', 'pyproject.toml', 'Cargo.toml', 'go.mod', 'src/index.ts', 'src/index.js', 'index.js', 'index.ts', 'lib/index.js') if p in known]
    # Include up to 3 nested package manifests for monorepos.
    candidates += [p for p in sorted(known) if p.endswith('/package.json')][:3]
    candidates = list(dict.fromkeys(candidates))[:12]
    sha = out['commit_sha']
    base_url = f'https://github.com/{repo}/blob/{sha}'
    for path in candidates:
        try:
            contents = client.raw(repo, sha, path)
            out['checked_files'].append(path)
            if path.lower().endswith('readme.md'):
                out['readme_headings'] = [re.sub(r'[\r\n|]', ' ', line)[:140] for line in contents.splitlines() if re.match(r'^#{1,3}\s', line)][:20]
            if path.endswith('package.json'):
                f, errs = manifest_findings(path, contents, base_url)
                out['findings'].extend(f)
                out['errors'].extend(errs)
            elif path.endswith(('.ts', '.js')):
                out['findings'].extend(source_findings(path, contents, base_url))
        except GitHubError as exc:
            out['errors'].append(f'{path}: {exc}')
    out['status'] = 'complete-with-limits' if not out['errors'] and not out['tree_truncated'] else 'partial'
    return out


def audit_one(client: GitHubClient, identifier: str, deep: bool, sample: int, at: dt.datetime) -> dict[str, Any]:
    result: dict[str, Any] = {'input': identifier, 'status': 'unverified', 'signals': [], 'coverage': {'metadata': 'not_checked', 'source': 'not_checked', 'stargazers': 'not_checked'}, 'errors': []}
    try:
        repo = parse_repo(identifier)
        result['repo'] = repo
    except ValueError as exc:
        result['errors'].append(str(exc))
        return result
    try:
        meta = client.api('repos/' + repo)
        if not isinstance(meta, dict) or 'stargazers_count' not in meta:
            raise GitHubError('Unexpected repository metadata')
    except GitHubError as exc:
        result['errors'].append('Metadata unavailable: ' + str(exc))
        return result
    result['status'] = 'triaged'
    result['coverage']['metadata'] = 'checked'
    result['repo'] = meta.get('full_name', repo)
    result['metadata'] = {key: meta.get(key) for key in ('html_url', 'description', 'stargazers_count', 'forks_count', 'subscribers_count', 'size', 'created_at', 'pushed_at', 'archived', 'fork', 'has_issues', 'open_issues_count', 'default_branch')}
    result['signals'] = basic_signals(meta, at)
    if deep:
        detail = inspect_deep(client, result['repo'], meta)
        result['source'] = detail
        result['coverage']['source'] = detail['status']
        if detail.get('code_files', 0) == 0 and detail.get('files_observed', 0) > 0 and not detail['tree_truncated']:
            result['signals'].append(signal('NO_RECOGNIZED_CODE', 'context', 'No files matched common code extensions', 'May be a perfectly legitimate documentation, dataset or configuration repository; contrast with functional claims.', detail.get('source_url', f'https://github.com/{repo}')))
        if detail.get('errors'):
            result['errors'].extend(detail['errors'])
    else:
        result['coverage']['source'] = 'skipped; use --deep'
    if sample:
        check = sample_stargazers(client, result['repo'], int(meta.get('stargazers_count') or 0), sample)
        result['stargazer_sample'] = check
        result['coverage']['stargazers'] = check['status']
        if check.get('status') == 'sampled' and check.get('ratio', 0) >= .25:
            result['signals'].append(signal('SPARSE_STARGAZER_SAMPLE', 'review', f"{check['sparse_profiles']}/{check['inspected']} sparse profiles in convenience sample", 'Not evidence that accounts are bots. Look for longitudinal coordinated behavior; sample is not representative.', f'https://github.com/{repo}/stargazers'))
    else:
        result['coverage']['stargazers'] = 'skipped; opt in via --sample-stargazers'
    result['review_priority'] = 'elevated' if any(s['severity'] == 'review' for s in result['signals']) or any(f.get('severity') == 'high-review' for f in result.get('source', {}).get('findings', [])) else 'routine'
    result['conclusion'] = 'Preliminary leads only; fake stars, implementation fidelity, and supply-chain safety are NOT established.'
    return result


def clean(text: Any) -> str:
    return re.sub(r'[\r\n|]+', ' ', str(text or '')).strip()[:360]


def markdown_report(payload: dict[str, Any]) -> str:
    lines = ['# GitHub 项目真实性初筛（非造假定论）', '', f"调查时间：{payload['checked_at']}；REST 请求：{payload['api_calls']}；剩余额度：{payload['rate_limit_remaining'] if payload['rate_limit_remaining'] is not None else '未知'}。", '', '| 仓库 | 状态 | 人气/活动线索 | 源码覆盖 | 建议 |', '| --- | --- | --- | --- | --- |']
    for row in payload['results']:
        marks = ', '.join(s['code'] for s in row['signals']) or '无显著自动线索'
        lines.append(f"| {clean(row.get('repo', row['input']))} | {row['status']} | {clean(marks)} | {clean(row['coverage']['source'])} | {clean(row.get('review_priority','证据不足'))} |")
    for row in payload['results']:
        lines += ['', f"## {clean(row.get('repo', row['input']))}", '', f"- 状态：{row['status']}。覆盖：{json.dumps(row['coverage'], ensure_ascii=False)}"]
        meta = row.get('metadata', {})
        if meta:
            lines.append(f"- GitHub 元数据：Stars={meta.get('stargazers_count')}, Forks={meta.get('forks_count')}, Subscribers={meta.get('subscribers_count')}, size={meta.get('size')} KiB, Created={meta.get('created_at')}, Last push={meta.get('pushed_at')}。")
        for s in row['signals']:
            lines.append(f"- **{s['severity']} / {s['code']}**：{clean(s['observed'])}；{clean(s['interpretation'])}。证据：{s['url']}")
        source = row.get('source')
        if source:
            lines.append(f"- 固定源码版本：`{source.get('commit_sha') or '未知'}`；树枚举文件：{source.get('files_observed',0)}，识别代码文件：{source.get('code_files',0)}，测试文件：{source.get('test_files',0)}；扫描文件：{', '.join(source.get('checked_files', [])) or '无'}。")
            if source.get('tree_truncated'):
                lines.append('- **覆盖警告**：GitHub 返回的树已截断，文件统计不完整。')
            for f in source.get('findings', []):
                lines.append(f"- **源码审阅线索（{f['severity']} / {f['code']}）**：`{clean(f['file'])}:{f['line']}` — `{clean(f['evidence'])}`；{f['url']}。匹配不等于恶意。")
            if source.get('readme_headings'):
                lines.append('- README 标题（仅用于 Agent 后续抽取待验证声明）：' + ' / '.join(clean(x) for x in source['readme_headings'][:8]))
        if row.get('stargazer_sample'):
            lines.append('- 点赞者便利抽样：' + clean(json.dumps(row['stargazer_sample'], ensure_ascii=False)) + '；不可将空白资料判作机器人。')
        for error in row['errors']:
            lines.append(f'- **未完成项**：{clean(error)}')
        lines.append('- **仍须 Agent 验证**：README 中具体功能是否有源码和可复现测试；版本与 Release 是否对应；维护者/项目来源；星标增长时序与传播事件；依赖和分发物是否匹配。')
    lines += ['', '本脚本只读访问 GitHub，不安装、不构建、不执行目标代码；自动线索均不能单独证明刷星、恶意或虚假宣传。']
    return '\n'.join(lines) + '\n'


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Evidence-oriented GitHub repository authenticity triage (read only)')
    parser.add_argument('repos', nargs='+', help='OWNER/REPO or https://github.com/OWNER/REPO')
    parser.add_argument('--deep', action='store_true', help='Inspect pinned tree and up to 12 small, selected files (no execution)')
    parser.add_argument('--sample-stargazers', type=int, default=0, metavar='N', help='Optional 3-10 account convenience sample; can be inaccessible and costly')
    parser.add_argument('--max-api', type=int, default=20, help='Maximum REST API calls in this run, default 20')
    parser.add_argument('--timeout', type=int, default=12, help='Per-request timeout (seconds)')
    parser.add_argument('--format', choices=('markdown', 'json'), default='markdown')
    parser.add_argument('--output', help='Save output to a local file instead of stdout')
    args = parser.parse_args(argv)
    if args.sample_stargazers != 0 and not 3 <= args.sample_stargazers <= 10:
        parser.error('--sample-stargazers must be 0 or between 3 and 10')
    if not 1 <= args.max_api <= 500 or not 1 <= args.timeout <= 120:
        parser.error('Invalid resource budget')
    client = GitHubClient(token=os.environ.get('GITHUB_TOKEN', ''), timeout=args.timeout, max_api=args.max_api)
    at = now_utc()
    results = [audit_one(client, r, args.deep, args.sample_stargazers, at) for r in args.repos]
    payload = {'schema_version': '1.0', 'checked_at': at.isoformat(), 'api_calls': client.api_calls, 'rate_limit_remaining': client.remaining, 'results': results}
    output = json.dumps(payload, ensure_ascii=False, indent=2) + '\n' if args.format == 'json' else markdown_report(payload)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as file:
            file.write(output)
    else:
        print(output, end='')
    return 0 if all(r['status'] == 'triaged' for r in results) else 2


if __name__ == '__main__':
    sys.exit(main())
