"""Black-box tests: expectations do not import the API's authorization code."""
import json
import os
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

EVIDENCE = []
SENSITIVE = {'authorization', 'password', 'access_token', 'cookie', 'set-cookie'}


def redact(value):
    if isinstance(value, dict):
        return {k: '[REDACTED]' if k.lower() in SENSITIVE else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.base = os.environ['API_BASE_URL']
        url = urlsplit(self.base)
        if url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost'):
            raise RuntimeError('This lab only tests a loopback HTTP target.')
        self.password = os.environ['DEMO_PASSWORD']
        self.client = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, method, path, token=None, body=None, headers=None):
        sent_headers = {'Content-Type': 'application/json', **(headers or {})}
        if token is not None:
            sent_headers['Authorization'] = 'Bearer ' + token
        req = Request(self.base + path, method=method, headers=sent_headers,
                      data=json.dumps(body).encode() if body is not None else None)
        try:
            response = self.client.open(req, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            status = response.status
            payload = json.loads(response.read())
            response_headers = dict(response.headers)
        EVIDENCE.append({'test': self.id().split('.')[-1],
                         'request': {'method': method, 'path': path,
                                     'headers': redact(sent_headers), 'body': redact(body)},
                         'response': {'status': status, 'headers': redact(response_headers),
                                      'body': redact(payload)}})
        return status, payload

    def login(self, username='alice'):
        status, body = self.request('POST', '/auth/login', body={
            'username': username, 'password': self.password})
        self.assertEqual(status, 200, 'Login must succeed before authorization testing')
        self.assertEqual(body['token_type'], 'Bearer')
        return body['access_token']

    def test_anonymous_endpoints(self):
        for method, path in [('GET', '/me'), ('GET', '/accounts'),
                             ('GET', '/accounts/acct-alice'),
                             ('GET', '/accounts/acct-alice/transactions'),
                             ('GET', '/transactions/tx-alice'),
                             ('PATCH', '/users/alice/profile'), ('GET', '/admin/users'),
                             ('PATCH', '/admin/users/bob/role'), ('POST', '/auth/logout')]:
            with self.subTest(path=path):
                self.assertEqual(self.request(method, path)[0], 401)

    def test_invalid_login(self):
        for user, password in [('alice', 'incorrect'), ('nonexistent', self.password)]:
            self.assertEqual(self.request('POST', '/auth/login', body={
                'username': user, 'password': password})[0], 401)

    def test_invalid_and_tampered_tokens(self):
        token = self.login()
        for invalid in ('not-a-token', token + 'tampered'):
            self.assertEqual(self.request('GET', '/me', invalid)[0], 401)
        self.assertEqual(self.request('GET', '/me', headers={'Authorization': 'Basic invalid'})[0], 401)

    def test_expired_session(self):
        token = self.login()
        self.assertEqual(self.request('GET', '/me', token)[0], 200)
        time.sleep(int(os.environ.get('TEST_SESSION_TTL', '3')) + 0.2)
        self.assertEqual(self.request('GET', '/me', token)[0], 401)

    def test_logout_revokes_only_presented_session(self):
        first, second = self.login(), self.login()
        self.assertEqual(self.request('POST', '/auth/logout', first)[0], 200)
        self.assertEqual(self.request('GET', '/me', first)[0], 401)
        self.assertEqual(self.request('GET', '/me', second)[0], 200)

    def test_customer_cannot_access_other_customer(self):
        status, body = self.request('GET', '/accounts/acct-bob', self.login())
        self.assertEqual(status, 404)
        self.assertEqual(body, {'error': 'not_found'})

    def test_admin_cannot_cross_tenant(self):
        status, body = self.request('GET', '/accounts/acct-carol', self.login('admin'))
        self.assertEqual(status, 404)
        self.assertEqual(body, {'error': 'not_found'})

    def test_customer_cannot_call_admin(self):
        self.assertEqual(self.request('GET', '/admin/users', self.login())[0], 403)

    def test_profile_mass_assignment(self):
        token = self.login()
        status, before = self.request('GET', '/me', token)
        self.assertEqual(status, 200)
        for field, value in [('role', 'admin'), ('tenant', 'beta'), ('id', 'admin'),
                             ('password', 'replaced'), ('balance', 999999)]:
            with self.subTest(field=field):
                status, _ = self.request('PATCH', '/users/alice/profile', token,
                                         {'display_name': 'Injected', field: value})
                self.assertEqual(status, 400)
                self.assertEqual(self.request('GET', '/me', token)[1], before)
        self.assertEqual(self.request('GET', '/admin/users', token)[0], 403)

    def test_profile_valid_update(self):
        token = self.login()
        status, body = self.request('PATCH', '/users/alice/profile', token,
                                     {'display_name': 'Alice Updated'})
        self.assertEqual(status, 200)
        self.assertEqual(body['display_name'], 'Alice Updated')
        self.assertEqual(body['role'], 'customer')

    def test_profile_ownership(self):
        for actor, target, expected in [('alice', 'bob', 403), ('alice', 'carol', 404),
                                         ('admin', 'alice', 403), ('support', 'bob', 403)]:
            with self.subTest(actor=actor, target=target):
                self.assertEqual(self.request('PATCH', '/users/' + target + '/profile',
                    self.login(actor), {'display_name': 'Unauthorized'})[0], expected)

    def test_role_changes(self):
        admin, bob = self.login('admin'), self.login('bob')
        try:
            status, _ = self.request('PATCH', '/admin/users/bob/role', admin, {'role': 'support'})
            self.assertEqual(status, 200)
            # Existing sessions immediately use authoritative server-side roles.
            self.assertEqual(self.request('GET', '/me', bob)[1]['role'], 'support')
            self.assertEqual(self.request('GET', '/transactions/tx-bob', bob)[0], 403)
        finally:
            self.request('PATCH', '/admin/users/bob/role', admin, {'role': 'customer'})
        self.assertEqual(self.request('GET', '/transactions/tx-bob', bob)[0], 200)

    def test_role_change_denials(self):
        for actor, target, role, expected in [
            ('alice', 'bob', 'support', 403), ('support', 'bob', 'customer', 403),
            ('admin', 'carol', 'support', 404), ('admin', 'bob', 'admin', 400),
            ('admin', 'admin', 'customer', 403), ('admin', 'bob', 'unknown', 400),
        ]:
            with self.subTest(actor=actor, target=target, role=role):
                self.assertEqual(self.request('PATCH', '/admin/users/' + target + '/role',
                    self.login(actor), {'role': role})[0], expected)

    def test_spoofed_identity_headers(self):
        headers = {'X-User-ID': 'admin', 'X-Role': 'admin', 'X-Tenant-ID': 'beta'}
        self.assertEqual(self.request('GET', '/admin/users', self.login(), headers=headers)[0], 403)
        self.assertEqual(self.request('GET', '/accounts/acct-carol', self.login('admin'), headers=headers)[0], 404)

    def test_account_lists(self):
        expected = {'alice': ['acct-alice'], 'bob': ['acct-bob'], 'carol': ['acct-carol'],
                    'support': ['acct-alice', 'acct-bob'], 'admin': ['acct-alice', 'acct-bob'],
                    'beta-support': ['acct-carol'], 'beta-admin': ['acct-carol']}
        for actor, ids in expected.items():
            with self.subTest(actor=actor):
                status, body = self.request('GET', '/accounts?tenant=beta&owner=carol', self.login(actor))
                self.assertEqual(status, 200)
                self.assertEqual(sorted(a['id'] for a in body['accounts']), ids)
                if 'support' in actor:
                    self.assertTrue(all('balance' not in a for a in body['accounts']))

    def test_admin_user_lists(self):
        for actor, tenant in [('admin', 'acme'), ('beta-admin', 'beta')]:
            status, body = self.request('GET', '/admin/users', self.login(actor))
            self.assertEqual(status, 200)
            self.assertTrue(body['users'])
            self.assertTrue(all(u['tenant'] == tenant for u in body['users']))
            self.assertTrue(all(set(u) == {'id', 'tenant', 'role', 'display_name'} for u in body['users']))
        for actor in ('support', 'beta-support', 'bob', 'carol'):
            self.assertEqual(self.request('GET', '/admin/users', self.login(actor))[0], 403)


def matrix_case(actor, owner, kind, expected):
    def test(self):
        path = {'account': '/accounts/acct-' + owner,
                'transactions': '/accounts/acct-' + owner + '/transactions',
                'direct': '/transactions/tx-' + owner}[kind]
        status, body = self.request('GET', path, self.login(actor))
        self.assertEqual(status, expected, f'{actor} accessing {path}')
        if expected != 200:
            self.assertEqual(body, {'error': 'not_found' if expected == 404 else 'forbidden'})
        elif kind == 'account':
            self.assertEqual(body['owner'], owner)
            self.assertEqual('balance' in body, 'support' not in actor)
        elif kind == 'direct':
            self.assertEqual(body['account_id'], 'acct-' + owner)
        else:
            self.assertEqual([t['account_id'] for t in body['transactions']], ['acct-' + owner])
    return test


MATRIX = json.loads(Path(__file__).with_name('read_matrix.json').read_text())
for actor, kinds in MATRIX['actors'].items():
    for kind in ('account', 'transactions', 'direct'):
        statuses = kinds['transactions' if kind == 'direct' else kind]
        for owner, expected in zip(MATRIX['owners'], statuses):
            setattr(AuthorizationTests, 'test_matrix_' + actor.replace('-', '_') + '_' + owner + '_' + kind,
                    matrix_case(actor, owner, kind, expected))
