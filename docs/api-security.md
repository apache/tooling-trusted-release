# ATR API security model

All ATR routes, on both the website and the API, require HTTPS using TLS 1.2 or newer for their transport.

There are two access levels to the ATR API: public and committer. Public API endpoints are accessible to everybody. Committer endpoints have the following accessibility criteria instead.

## PATs

Committers must obtain a [Personal Access Token](https://en.wikipedia.org/wiki/Personal_access_token) (PAT) from the ATR website at the route `/tokens`. Only committers, signed in through [ASF OAuth](https://oauth.apache.org/api.html) to ATR, can obtain PATs. Each PAT expires in 180 days, and can be revoked at any time by the user at the same route. ATR does not store PATs, only the hashes of PATs.

## JWTs

To make a request to a committer protected endpoint on the API, committers must first obtain a [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token). They can do this in one of two ways:

1. For debugging, obtaining a JWT from the `/tokens` page.
2. For script use, obtaining a JWT by POSTing their PAT in a JSON payload to the API endpoint `/api/jwt`. This is a public route, and requires a payload such as `{"asfuid": "${ASF_UID}", "pat": "${PAT_TOKEN}"}`. The response will be `{"asfuid": "${ASF_UID}", "jwt": "${JWT_TOKEN}"}`.

Every JWT issued by the ATR expires in 90 minutes, uses the HS256 (HMAC-SHA256) algorithm, and makes `sub` (ASF UID), `iat` (issue time), `exp` (expires at), and `jti` (token payload) claims. JWTs are stateless, so there is no analogue stored by the ATR, except for the secret symmetric key of the server which is initialised on startup. If the ATR server is restarted, all JWTs are expired immediately.


The JWT can be used to access protected endpoints by using it in the `Authorization` header as a bearer token, i.e. `Authorization: Bearer ${JWT_TOKEN}`. PATs and JWTs must never appear in URLs. They must be protected by the user at all times. Accidental sharing of a PAT or a JWT must be reported to ASF security.

Note that PATs cannot be used to access protected endpoints. They can only be used to issue a JWT, which is then used to access protected endpoints.

Endpoints which mutate state, require significant computation, or have large or sensitive payloads use POST. All other endpoints use GET.

## Limitations

We do not currently support scopes in either PATs or JWTs, but are considering this.

Admins are able to revoke any PAT, and users are able to revoke any of their own PATs, but neither admins nor users are able to revoke JWTs on an individual basis. Restarting the server resets the server secret symmetric key, which has the side effect of expiring all JWTs, and can be used in an emergency.

We do not have refresh tokens, and do not plan to implement refresh tokens. PATs must be used to issue a new JWT through the API.

We do not presently have logging or auditing of the logging for the API. Once we implement logging, we must ensure that tokens and other sensitive data are not stored.

We do not use all available JWT fields, such as `iss` (issuer).

We do not rate limit PAT or JWT issuance.
