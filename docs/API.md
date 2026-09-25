# API contract and synthetic identities

All endpoints return JSON. Protected endpoints require `Authorization: Bearer TOKEN`.
Session tokens are opaque, random and server-side; they are not JWTs.

| Username | Tenant | Role | Account |
|---|---|---|---|
| alice | acme | customer | acct-alice |
| bob | acme | customer | acct-bob |
| carol | beta | customer | acct-carol |
| support | acme | support | None |
| admin | acme | admin | None |
| beta-support | beta | support | None |
| beta-admin | beta | admin | None |

All seven users use the runtime `DEMO_PASSWORD` for this lab. No real credentials
or customer information are included. Transaction IDs are `tx-alice`, `tx-bob`
and `tx-carol`.

| Method | Path | Input | Successful response |
|---|---|---|---|
| GET | /health | None, public | `{"status":"ok"}` |
| POST | /auth/login | `{"username":"alice","password":"YOUR_RUNTIME_PASSWORD"}` | `access_token`, `token_type`, `expires_in` |
| POST | /auth/logout | Bearer token | `{"status":"logged_out"}` |
| GET | /me | Bearer token | Own id, tenant, role, display_name |
| GET | /accounts | Bearer token | Filtered `accounts` array |
| GET | /accounts/{id} | Bearer token | Authorized account, with support balance filtering |
| GET | /accounts/{id}/transactions | Bearer token | Authorized `transactions` array |
| GET | /transactions/{id} | Bearer token | Transaction after parent-account authorization |
| PATCH | /users/{id}/profile | `{"display_name":"New name"}` | Updated self profile |
| GET | /admin/users | Admin bearer token | Same-tenant `users` array |
| PATCH | /admin/users/{id}/role | `{"role":"support"}` or `{"role":"customer"}` | Updated same-tenant non-admin profile |

No query parameter or identity header changes access scope. Clients cannot grant
admin through the API. Profile fields other than `display_name` are rejected;
the display name must be a string of 1–80 characters.

Error responses contain only `{"error":"CODE"}`. The suite checks 401 for invalid
authentication, 403 for forbidden functions, 404 for inaccessible objects and
400 for invalid fields. Request bodies are capped at 16 KiB.

For a safe interactive request example, with the running server's password in
your current shell, run this from a second terminal:

```bash
python - <<'PY'
import json, os
from urllib.request import Request, urlopen
base = 'http://127.0.0.1:8080'
login = Request(base + '/auth/login', method='POST',
    headers={'Content-Type': 'application/json'},
    data=json.dumps({'username': 'alice', 'password': os.environ['DEMO_PASSWORD']}).encode())
with urlopen(login) as response:
    token = json.load(response)['access_token']
request = Request(base + '/accounts/acct-alice', headers={'Authorization': 'Bearer ' + token})
with urlopen(request) as response:
    print(json.dumps(json.load(response), indent=2))
PY
```

The example prints account data, not the password or session token. To reproduce
an ownership denial, change the account path to `/accounts/acct-bob`; Alice's
request receives HTTP 404.
