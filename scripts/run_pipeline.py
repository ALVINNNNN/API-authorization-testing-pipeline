"""Start isolated lab instances, run HTTP checks, and prove regressions are detected."""
import argparse
import html
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = [
    ('bola', "if actor['role'] == 'customer' and actor['id'] != account['owner']:",
     'if False:  # seeded ownership regression', 'test_customer_cannot_access_other_customer', '/accounts/acct-bob'),
    ('tenant-isolation', "if actor['tenant'] != resource['tenant']:",
     'if False:  # seeded tenant regression', 'test_admin_cannot_cross_tenant', '/accounts/acct-carol'),
    ('admin-role', "if actor['role'] != 'admin':",
     'if False:  # seeded function authorization regression', 'test_customer_cannot_call_admin', '/admin/users'),
    ('mass-assignment', "if set(body) != {'display_name'}:",
     'if not body:  # seeded writable-fields regression', 'test_profile_mass_assignment', '/users/alice/profile'),
    ('logout-revocation', 'self.sessions.pop(token, None)  # revoke the presented session',
     'pass  # seeded revocation regression', 'test_logout_revokes_only_presented_session', '/me'),
    ('session-expiry', "if not session or session['expires'] <= time.monotonic():",
     'if not session:  # seeded expiry regression', 'test_expired_session', '/me'),
]


@contextmanager
def service(source, environment, folder):
    log_path = folder / 'server.log'
    with log_path.open('w') as log:
        proc = subprocess.Popen([sys.executable, '-m', 'app.server'], cwd=source,
                                env={**environment, 'PORT': '0', 'HOST': '127.0.0.1'},
                                stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError('API exited before readiness; inspect server.log')
                lines = log_path.read_text().splitlines()
                if lines:
                    ready = json.loads(lines[0])
                    base = 'http://127.0.0.1:' + str(ready['port'])
                    with urlopen(base + '/health', timeout=2) as response:
                        if json.load(response) != {'status': 'ok'}:
                            raise RuntimeError('Unexpected health response')
                    yield base
                    return
                time.sleep(0.05)
            raise RuntimeError('API readiness timed out')
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def run_tests(base, environment, folder, test=None):
    command = [sys.executable, '-m', 'tests.run', '--output', str(folder)]
    if test:
        command += ['--test', test]
    with (folder / 'tests.log').open('w') as log:
        result = subprocess.run(command, cwd=ROOT, env={**environment, 'API_BASE_URL': base},
                                stdout=log, stderr=subprocess.STDOUT, timeout=120)
    path = folder / 'results.json'
    if not path.exists():
        raise RuntimeError('Test runner produced no report; inspect tests.log')
    return result.returncode, json.loads(path.read_text())


def reports(out, outcomes):
    passed = all(row['passed'] for row in outcomes)
    report = {'passed': passed, 'source_commit': os.environ.get('GITHUB_SHA', 'local'),
              'checks': outcomes}
    (out / 'summary.json').write_text(json.dumps(report, indent=2))
    lines = ['# API authorization security gate', '', 'Result: ' + ('PASS' if passed else 'FAIL'), '',
             '| Check | Result | Detail |', '|---|---|---|']
    for row in outcomes:
        lines.append('| ' + row['name'] + ' | ' + ('PASS' if row['passed'] else 'FAIL') +
                     ' | ' + row['detail'].replace('|', '/') + ' |')
    lines += ['', 'Mutation failures are expected only when the named test observes unauthorized HTTP 200.',
              'Crashes, missing reports and test errors fail the gate.', '',
              'Each check folder contains redacted HTTP JSON, JUnit XML and CLI output.',
              'All accounts, balances and transactions are synthetic.']
    (out / 'summary.md').write_text('\n'.join(lines) + '\n')
    rows = ''.join('<tr><td>' + html.escape(r['name']) + '</td><td>' +
                   ('PASS' if r['passed'] else 'FAIL') + '</td><td>' +
                   html.escape(r['detail']) + '</td></tr>' for r in outcomes)
    (out / 'report.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width"><title>Authorization evidence</title>'
        '<style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:20px;background:#f6f8fb;'
        'color:#18283d}table{border-collapse:collapse;width:100%;background:white}td,th{padding:14px;'
        'border:1px solid #cbd5e1;text-align:left}h1{color:#15385c}</style>'
        '<h1>API authorization security gate: ' + ('PASS' if passed else 'FAIL') + '</h1>'
        '<p>Live HTTP checks against an isolated synthetic banking API.</p>'
        '<table><tr><th>Check</th><th>Result</th><th>Evidence</th></tr>' + rows + '</table>'
        '<p>Open each check folder for redacted requests, responses and JUnit results. '
        'Seeded mutation failures demonstrate test sensitivity, not vulnerabilities in the hardened app.</p></html>')
    return passed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='evidence')
    parser.add_argument('--base-url', help='Test an already running loopback API; no mutation tests')
    args = parser.parse_args()
    out = Path(args.output).resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit('Use a new or empty output directory to avoid mixing runs.')
    out.mkdir(parents=True, exist_ok=True)
    password = os.environ.get('DEMO_PASSWORD') or secrets.token_urlsafe(32)
    environment = {**os.environ, 'DEMO_PASSWORD': password, 'SESSION_TTL_SECONDS': '3',
                   'TEST_SESSION_TTL': '3', 'PYTHONDONTWRITEBYTECODE': '1'}
    outcomes = []
    try:
        baseline = out / 'hardened'
        baseline.mkdir()
        if args.base_url:
            if not os.environ.get('DEMO_PASSWORD'):
                raise RuntimeError('External target requires the same DEMO_PASSWORD; set its session TTL to 3.')
            code, report = run_tests(args.base_url, environment, baseline)
        else:
            with service(ROOT, environment, baseline) as base:
                code, report = run_tests(base, environment, baseline)
        ok = code == 0 and report['successful'] and report['tests'] >= 79
        outcomes.append({'name': 'hardened API', 'passed': ok,
                         'detail': f"{report['tests']} tests, {report['failures']} failures, {report['errors']} errors"})
        print('Hardened API: ' + outcomes[-1]['detail'], flush=True)
        if ok and not args.base_url:
            original = (ROOT / 'app/server.py').read_text()
            for name, old, new, test, endpoint in MUTATIONS:
                folder = out / name
                folder.mkdir()
                if original.count(old) != 1:
                    raise RuntimeError('Mutation anchor changed: ' + name)
                with tempfile.TemporaryDirectory(prefix='authorization-mutant-') as tmp:
                    source = Path(tmp)
                    shutil.copytree(ROOT / 'app', source / 'app')
                    (source / 'app/server.py').write_text(original.replace(old, new))
                    with service(source, environment, folder) as base:
                        code, report = run_tests(base, environment, folder, test)
                observed = any(e.get('request', {}).get('path') == endpoint
                               and e.get('response', {}).get('status') == 200
                               for row in report['cases'] for e in row.get('failure_http', []))
                killed = (code == 1 and report['tests'] == 1 and report['failures'] >= 1
                          and report['errors'] == 0 and observed
                          and report['cases'][0]['test'].endswith('.' + test)
                          and report['cases'][0]['status'] == 'failed')
                outcomes.append({'name': name, 'passed': killed,
                    'detail': ('Detected by ' if killed else 'NOT correctly detected by ') + test})
                print(name + ': ' + outcomes[-1]['detail'], flush=True)
    except Exception as exc:
        outcomes.append({'name': 'pipeline infrastructure', 'passed': False, 'detail': str(exc)})
        print(str(exc), file=sys.stderr)
    passed = reports(out, outcomes)
    # A second check prevents accidental credential disclosure in any generated artifact.
    for path in out.rglob('*'):
        if path.is_file() and password.encode() in path.read_bytes():
            path.write_text('[Artifact withheld: credential detected]\n')
            print('Credential found in artifact; gate failed', file=sys.stderr)
            passed = False
    print('SECURITY GATE: ' + ('PASS' if passed else 'FAIL'), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
