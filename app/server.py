"""Synthetic authorization lab. Standard-library HTTP server, not a production stack."""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class APIError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


class Bank:
    def __init__(self, password, ttl=900):
        self.lock = threading.RLock()
        self.ttl = ttl
        self.salt = secrets.token_bytes(16)
        self.password_hash = self.hash_password(password)
        self.sessions = {}
        self.users = {}
        for name, tenant, role in [
            ('alice', 'acme', 'customer'), ('bob', 'acme', 'customer'),
            ('carol', 'beta', 'customer'), ('support', 'acme', 'support'),
            ('admin', 'acme', 'admin'), ('beta-support', 'beta', 'support'),
            ('beta-admin', 'beta', 'admin'),
        ]:
            self.users[name] = dict(id=name, tenant=tenant, role=role, display_name=name.title())
        self.accounts = {
            'acct-' + user: dict(id='acct-' + user, owner=user, tenant=tenant,
                                balance=balance, currency='SGD')
            for user, tenant, balance in [('alice', 'acme', 1200), ('bob', 'acme', 2400),
                                          ('carol', 'beta', 3600)]
        }
        self.transactions = {
            'tx-' + user: dict(id='tx-' + user, account_id='acct-' + user,
                              amount=10, description='Synthetic purchase')
            for user in ('alice', 'bob', 'carol')
        }

    def hash_password(self, password):
        return hashlib.scrypt(password.encode(), salt=self.salt, n=16384, r=8, p=1)

    def authenticate(self, header):
        if not header or not header.startswith('Bearer '):
            raise APIError(401, 'unauthenticated')
        token = header[7:]
        session = self.sessions.get(token)
        if not session or session['expires'] <= time.monotonic():
            self.sessions.pop(token, None)
            raise APIError(401, 'unauthenticated')
        return self.users[session['user']], token

    def tenant_check(self, actor, resource):
        if actor['tenant'] != resource['tenant']:
            raise APIError(404, 'not_found')

    def account_access(self, actor, account, transactions=False):
        self.tenant_check(actor, account)
        if actor['role'] == 'customer' and actor['id'] != account['owner']:
            raise APIError(404, 'not_found')
        if transactions and actor['role'] == 'support':
            raise APIError(403, 'forbidden')

    def dispatch(self, method, path, body, authorization):
        # Serialization keeps this in-memory lab's session and update operations atomic.
        with self.lock:
            if path == '/health' and method == 'GET':
                return 200, {'status': 'ok'}
            if path == '/auth/login' and method == 'POST':
                username, password = body.get('username'), body.get('password')
                if not isinstance(username, str) or not isinstance(password, str):
                    raise APIError(400, 'invalid_credentials_format')
                valid = hmac.compare_digest(self.hash_password(password), self.password_hash)
                if not valid or username not in self.users:
                    raise APIError(401, 'invalid_credentials')
                token = secrets.token_urlsafe(32)
                self.sessions[token] = {'user': username, 'expires': time.monotonic() + self.ttl}
                return 200, {'access_token': token, 'token_type': 'Bearer', 'expires_in': self.ttl}

            actor, token = self.authenticate(authorization)
            if path == '/auth/logout' and method == 'POST':
                self.sessions.pop(token, None)  # revoke the presented session
                return 200, {'status': 'logged_out'}
            if path == '/me' and method == 'GET':
                return 200, dict(actor)
            if path == '/accounts' and method == 'GET':
                visible = []
                for account in self.accounts.values():
                    try:
                        self.account_access(actor, account)
                    except APIError:
                        continue
                    visible.append(self.account_view(actor, account))
                return 200, {'accounts': visible}
            match = re.fullmatch(r'/accounts/([a-z-]+)(/transactions)?', path)
            if match and method == 'GET':
                account = self.accounts.get(match[1])
                if not account:
                    raise APIError(404, 'not_found')
                self.account_access(actor, account, transactions=bool(match[2]))
                if match[2]:
                    return 200, {'transactions': [dict(t) for t in self.transactions.values()
                                                 if t['account_id'] == account['id']]}
                return 200, self.account_view(actor, account)
            match = re.fullmatch(r'/transactions/([a-z-]+)', path)
            if match and method == 'GET':
                transaction = self.transactions.get(match[1])
                if not transaction:
                    raise APIError(404, 'not_found')
                self.account_access(actor, self.accounts[transaction['account_id']], transactions=True)
                return 200, dict(transaction)
            match = re.fullmatch(r'/users/([a-z-]+)/profile', path)
            if match and method == 'PATCH':
                target = self.users.get(match[1])
                if not target:
                    raise APIError(404, 'not_found')
                self.tenant_check(actor, target)
                if actor['id'] != target['id']:
                    raise APIError(403, 'forbidden')
                if set(body) != {'display_name'}:
                    raise APIError(400, 'invalid_fields')
                if not isinstance(body.get('display_name'), str) or not 1 <= len(body['display_name']) <= 80:
                    raise APIError(400, 'invalid_display_name')
                target.update(body)
                return 200, dict(target)
            if path.startswith('/admin/'):
                if actor['role'] != 'admin':
                    raise APIError(403, 'forbidden')
                if path == '/admin/users' and method == 'GET':
                    return 200, {'users': [dict(u) for u in self.users.values()
                                          if u['tenant'] == actor['tenant']]}
                match = re.fullmatch(r'/admin/users/([a-z-]+)/role', path)
                if match and method == 'PATCH':
                    target = self.users.get(match[1])
                    if not target:
                        raise APIError(404, 'not_found')
                    self.tenant_check(actor, target)
                    if target['role'] == 'admin' or target['id'] == actor['id']:
                        raise APIError(403, 'forbidden')
                    if set(body) != {'role'} or body['role'] not in ('customer', 'support'):
                        raise APIError(400, 'invalid_role')
                    target['role'] = body['role']
                    return 200, dict(target)
            raise APIError(404, 'not_found')

    @staticmethod
    def account_view(actor, account):
        result = dict(account)
        if actor['role'] == 'support':
            result.pop('balance')
        return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # No credentials, tokens, or user-controlled paths in server logs.

    def handle_request(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 <= length <= 16384:
                raise APIError(413, 'body_too_large')
            body = json.loads(self.rfile.read(length)) if length else {}
            if not isinstance(body, dict):
                raise APIError(400, 'invalid_json_object')
            status, response = self.server.bank.dispatch(
                self.command, urlsplit(self.path).path, body, self.headers.get('Authorization'))
        except (ValueError, UnicodeError):
            status, response = 400, {'error': 'invalid_json'}
        except APIError as exc:
            status, response = exc.status, {'error': exc.code}
        payload = json.dumps(response).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PATCH = do_DELETE = do_PUT = handle_request


if __name__ == '__main__':
    password = os.environ.get('DEMO_PASSWORD', '')
    if len(password) < 16:
        raise SystemExit('Set DEMO_PASSWORD to at least 16 characters (synthetic lab users only).')
    ttl = int(os.environ.get('SESSION_TTL_SECONDS', '900'))
    if not 1 <= ttl <= 3600:
        raise SystemExit('SESSION_TTL_SECONDS must be between 1 and 3600.')
    server = ThreadingHTTPServer((os.environ.get('HOST', '127.0.0.1'),
                                  int(os.environ.get('PORT', '8080'))), Handler)
    server.bank = Bank(password, ttl)
    print(json.dumps({'ready': True, 'port': server.server_port}), flush=True)
    server.serve_forever()
