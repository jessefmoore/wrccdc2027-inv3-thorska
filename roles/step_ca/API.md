# Flokie Step CA API

The API listens on TCP 8080. 

```text
GET  /health
GET  /trust/root.pem
GET  /trust/ssh-user-ca.pub
GET  /trust/ssh-host-ca.pub
GET  /v1/ca
POST /v1/ca/action
POST /v1/certificates/x509
POST /v1/certificates/ssh
```

Authenticated endpoints require both the shared key from
`/etc/step-ca-api/token` and valid `ice.land` domain credentials. The API uses
an intentionally unencrypted LDAP simple bind to `vattar.ice.land:389` to check
the credentials. A username without a domain is expanded to `@ice.land`.

```bash
curl --user 'alice@ice.land:DomainPassword' \
  -H 'X-API-Key: SMBlyRequired!' \
  http://ca.ice.land:8080/v1/ca
```

Issue an X.509 certificate and encrypted private key:

```bash
curl -X POST --user 'alice@ice.land:DomainPassword' \
  -H 'X-API-Key: SMBlyRequired!' \
  -H 'Content-Type: application/json' \
  -d '{"subject":"wordpress.ice.land","sans":["wordpress.ice.land"],"duration":"2h"}' \
  http://ca.ice.land:8080/v1/certificates/x509
```

Sign an existing SSH public key for arbitrary principals:

```bash
curl -X POST --user 'alice@ice.land:DomainPassword' \
  -H 'X-API-Key: SMBlyRequired!' \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"operator","public_key":"ssh-ed25519 AAAA...","principals":["root"],"duration":"2h"}' \
  http://ca.ice.land:8080/v1/certificates/ssh
```

Add `"host":true` to the same request to sign an SSH host public key rather
than a user key.

Control the CA service:

```bash
curl -X POST --user 'alice@ice.land:DomainPassword' \
  -H 'X-API-Key: SMBlyRequired!' \
  -H 'Content-Type: application/json' \
  -d '{"action":"stop"}' \
  http://ca.ice.land:8080/v1/ca/action
```

## Troubleshooting

Use `--fail-with-body` instead of `-f` so an unsuccessful request still prints
the API's JSON error message:

```bash
curl --fail-with-body -sS [request options] \
  http://ca.ice.land:8080/v1/certificates/ssh

journalctl -u step-ca-api.service -n 50 --no-pager
```

The service log records status codes, response sizes, request sources,
authenticated domain usernames, issuance identities and principals, and
underlying `step` errors. It does not record API keys, domain passwords,
submitted public keys, generated private keys, or issued certificates.
