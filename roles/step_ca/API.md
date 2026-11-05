# Flokie Step CA API

The API listens on TCP 8080. 

```text
GET  /health
GET  /trust/root.pem
GET  /trust/ssh-user-ca.pub
GET  /v1/ca
POST /v1/ca/action
POST /v1/certificates/x509
POST /v1/certificates/ssh
```

Use the token from `/etc/step-ca-api/token`:

```bash
curl -H 'Authorization: Bearer SMBlyRequired!' \
  http://ca.ice.land:8080/v1/ca
```

Issue an X.509 certificate and encrypted private key:

```bash
curl -X POST -H 'Authorization: Bearer SMBlyRequired!' \
  -H 'Content-Type: application/json' \
  -d '{"subject":"wordpress.ice.land","sans":["wordpress.ice.land"],"duration":"2h"}' \
  http://ca.ice.land:8080/v1/certificates/x509
```

Sign an existing SSH public key for arbitrary principals:

```bash
curl -X POST -H 'Authorization: Bearer SMBlyRequired!' \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"operator","public_key":"ssh-ed25519 AAAA...","principals":["root"],"duration":"2h"}' \
  http://ca.ice.land:8080/v1/certificates/ssh
```

Control the CA service:

```bash
curl -X POST -H 'Authorization: Bearer SMBlyRequired!' \
  -H 'Content-Type: application/json' \
  -d '{"action":"stop"}' \
  http://ca.ice.land:8080/v1/ca/action
```
