# Connecting a Linux service host to Flokie CA

These instructions are for Linux hosts using systemd. Replace hostnames, paths,
and service names for each box. The host must resolve `ca.ice.land` and reach
TCP 9000 and 8080 on Thorska.

## 1. Install trust and tooling

Install `step-cli`, `curl`, and `jq`. Then install the public trust material:

```bash
install -d -m 0755 /etc/step
curl -fsS http://ca.ice.land:8080/trust/root.pem -o /etc/step/root_ca.crt
curl -fsS http://ca.ice.land:8080/trust/ssh-user-ca.pub -o /etc/ssh/ssh_user_ca_key.pub
curl -fsS http://ca.ice.land:8080/trust/ssh-host-ca.pub -o /etc/step/ssh_host_ca_key.pub
chmod 0644 /etc/step/root_ca.crt /etc/ssh/ssh_user_ca_key.pub /etc/step/ssh_host_ca_key.pub
```

On Fedora/RHEL, also install the X.509 root into system trust:

```bash
install -m 0644 /etc/step/root_ca.crt \
  /etc/pki/ca-trust/source/anchors/flokie-root-ca.crt
update-ca-trust
```

On Debian/Ubuntu, copy it to `/usr/local/share/ca-certificates/flokie-root-ca.crt`
and run `update-ca-certificates`.

## 2. HTTPS certificate and renewal

Request the initial certificate from the API. Supply the shared API key plus the
credentials of any valid `ice.land` domain account. The API checks the account
using intentionally unencrypted LDAP. The response contains an encrypted
private key and its password:

```bash
install -d -m 0700 /etc/nginx/tls

jq -n '{
  subject: "wordpress.ice.land",
  sans: ["wordpress.ice.land"],
  duration: "2h"
}' | curl --fail-with-body -sS \
  --user 'alice@ice.land:DomainPassword' \
  -H 'X-API-Key: SMBlyRequired!' \
  -H 'Content-Type: application/json' --data-binary @- \
  http://ca.ice.land:8080/v1/certificates/x509 \
  > /tmp/wordpress-certificate.json

jq -erj '.certificate' /tmp/wordpress-certificate.json > /etc/nginx/tls/wordpress.crt
jq -erj '.private_key' /tmp/wordpress-certificate.json > /etc/nginx/tls/wordpress.key
jq -erj '.private_key_password' /tmp/wordpress-certificate.json > /etc/nginx/tls/key-password
chmod 0600 /etc/nginx/tls/wordpress.key /etc/nginx/tls/key-password
```

Configure Nginx with:

```nginx
ssl_certificate /etc/nginx/tls/wordpress.crt;
ssl_certificate_key /etc/nginx/tls/wordpress.key;
ssl_password_file /etc/nginx/tls/key-password;
```

Install `examples/step-cert-renew@.service`, its matching timer, and an environment
file based on `examples/wordpress.env`. Enable it with:

```bash
systemctl daemon-reload
systemctl enable --now step-cert-renew@wordpress.timer
```

The timer checks every 10–12 minutes, renews inside the final 45 minutes, and
reloads the configured web service after successful renewal. Smallstep recommends
systemd timers for automated renewal.

## 3. Accept Step-issued SSH user certificates

Add `/etc/ssh/sshd_config.d/00-step-ca-ssh.conf`:

```text
PubkeyAuthentication yes
TrustedUserCAKeys /etc/ssh/ssh_user_ca_key.pub
AuthorizedPrincipalsFile none
PermitRootLogin yes
```

Validate and reload:

```bash
sshd -t && systemctl reload sshd
```

With `AuthorizedPrincipalsFile none`, a certificate is accepted when one of its
principals matches the target local or SSSD-resolved account name.

## 4. Give the SSH server a host certificate

Store the shared JWK provisioner password locally:

```bash
printf '%s\n' 'SMBlyRequired!' > /etc/step/provisioner-password
chmod 0600 /etc/step/provisioner-password
```

Sign the existing OpenSSH host public key. Replace both host principals:

```bash
step ssh certificate --host --sign --force \
  --principal=server.ice.land --principal=server \
  --not-after=2h \
  --ca-url=https://ca.ice.land:9000 \
  --root=/etc/step/root_ca.crt \
  --provisioner=admin \
  --provisioner-password-file=/etc/step/provisioner-password \
  server.ice.land /etc/ssh/ssh_host_ed25519_key.pub
```

Add the resulting certificate to sshd configuration:

```text
HostKey /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

Install `examples/step-ssh-host-renew@.service`, its timer, and an environment
file based on `examples/sshd.env`. Then enable it:

```bash
systemctl daemon-reload
systemctl enable --now step-ssh-host-renew@sshd.timer
sshd -t && systemctl reload sshd
```

SSH clients or the scoring engine can trust all signed host certificates with a
`known_hosts` entry containing:

```text
@cert-authority *.ice.land <contents of ssh_host_ca_key.pub>
```

## Scoring guidance

For HTTPS, perform a normal TLS connection using `root_ca.crt`, verify the SAN,
chain and current validity, and then perform the existing application checks.

For SSH, generate an ephemeral keypair, request a short-lived user certificate,
and log in to a known scoring account. Select randomly from a configured list of
accounts; a truly random username will fail unless that account exists and is
resolvable through local NSS or SSSD.

The API requires both the shared API key and valid AD credentials, but it
intentionally does not constrain requested principals to the authenticated
account. A valid domain user can therefore request a certificate for every local
or AD account accepted by the target, including root. The scoring engine needs
its own ordinary domain account and may request a dedicated `scorecheck`
principal; the same authorization flaw remains available as the red-team path.
