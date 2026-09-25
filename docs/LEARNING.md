# Reproduce, fix, and explain authorization bugs

## Start with the evidence

Run `python scripts/run_pipeline.py`. Compare:

- `evidence/hardened/results.json`: allowed and denied requests for the hardened API.
- `evidence/bola/results.json`: the same ownership regression test receives an unauthorized 200.
- `evidence/bola/tests.log`: the actual failed assertion that caught the seeded bug.
- `evidence/summary.md`: why the intentionally failing test makes the mutation check pass.

The temporary mutated application is deleted after each scenario. The tracked
application stays hardened. The six exact mutations and detector names are in
`scripts/run_pipeline.py`.

## Exercise: enforce a real PR gate

1. Create a practice branch and remove the account ownership check in `app/server.py`.
2. Open a PR. The hardened suite should fail before mutation checks begin.
3. Inspect the redacted request from Alice to Bob's account and its unexpected 200.
4. Restore the ownership check and push again. The suite should pass.
5. Require the **Security gate** status in repository branch rules before merging.

Do not merge intentionally vulnerable practice changes. Keep the lab on loopback.

## Exercise: add an endpoint

Add a beneficiary endpoint using synthetic records. Write the expected permission
matrix first: own-user read/write, same-tenant support read, no cross-tenant access.
Then implement it, add allowed and denied HTTP cases, and introduce a temporary
ownership mutation to prove the tests detect it. Test direct IDs and list filtering.

## Next improvements

- Add an OpenAPI contract and check every protected operation has positive and negative cases.
- Add authenticated ZAP scanning against this same disposable target, keeping explicit
  object- and function-authorization assertions; login success alone is not coverage.
- Replace demo login with a local OIDC provider and test audience, issuer, expiry,
  revocation and role-change behaviour without trusting client-supplied claims.
- Add PostgreSQL with tenant-scoped queries and test cross-tenant joins and transactions.
- Introduce controlled concurrent role-change tests and session-revocation races.
- Map cases to OWASP API Security categories, documenting coverage gaps rather than
  claiming full compliance from a passing suite.
