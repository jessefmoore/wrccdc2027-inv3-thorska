# Connecting service hosts to Flokie CA

Replace hostnames, paths, and service names for each box. Every host must resolve
`ca.ice.land` and reach TCP 9000 and 8080 on Thorska.

## Linux onboarding

These instructions are for Linux hosts using systemd.

### 1. Install trust and tooling

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

### 2. HTTPS certificate and renewal

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

### 3. Accept Step-issued SSH user certificates

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

### 4. Give the SSH server a host certificate

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

## Windows OpenSSH onboarding

Windows Server 2019 and newer can trust the same Step SSH user and host CAs as
the Linux systems. The examples below must be run from an elevated PowerShell
prompt unless stated otherwise.

### 1. Install OpenSSH Server

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic
Start-Service sshd
```

If Windows Firewall is enabled, allow inbound TCP 22:

```powershell
New-NetFirewallRule `
  -Name OpenSSH-Server-In-TCP `
  -DisplayName "OpenSSH Server (sshd)" `
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### 2. Trust Step-issued SSH user certificates

Download the public user CA key:

```powershell
Invoke-WebRequest `
  -Uri "http://ca.ice.land:8080/trust/ssh-user-ca.pub" `
  -OutFile "$env:ProgramData\ssh\ssh_user_ca_key.pub"

icacls.exe "$env:ProgramData\ssh\ssh_user_ca_key.pub" `
  /inheritance:r /grant "*S-1-5-18:F" /grant "*S-1-5-32-544:F"
```

Add the following to `C:\ProgramData\ssh\sshd_config`:

```text
PubkeyAuthentication yes
TrustedUserCAKeys C:/ProgramData/ssh/ssh_user_ca_key.pub
AuthorizedPrincipalsFile none
```

Validate the configuration and restart OpenSSH:

```powershell
& "$env:WINDIR\System32\OpenSSH\sshd.exe" -t
if ($LASTEXITCODE -ne 0) { throw "Invalid sshd configuration" }
Restart-Service sshd
```

The SSH certificate principal must exactly match the login name recognized by
Windows OpenSSH. Use the same form for the certificate and connection. For
example, try the domain UPN form first:

```text
alice@ice.land
```

If that Windows installation expects the NetBIOS form, use `ice\alice` for both
instead. Local accounts use their local username, such as `Administrator`.

### 3. Test a Windows user certificate

Run these commands from a Linux or macOS administration system. Generate an
ephemeral keypair and request a certificate for an existing Windows account:

```bash
ssh-keygen -t ed25519 -f ./windows-user -N ''

jq -n \
  --arg key "$(cat ./windows-user.pub)" \
  '{
    key_id: "windows-test",
    public_key: $key,
    principals: ["alice@ice.land"],
    duration: "2h"
  }' | curl --fail-with-body -sS \
    --user 'scoring@ice.land:DomainPassword' \
    -H 'X-API-Key: SMBlyRequired!' \
    -H 'Content-Type: application/json' \
    --data-binary @- \
    http://ca.ice.land:8080/v1/certificates/ssh | \
  jq -er '.certificate' > ./windows-user-cert.pub

ssh -i ./windows-user \
  -o CertificateFile=./windows-user-cert.pub \
  -o IdentitiesOnly=yes \
  -l 'alice@ice.land' windows-host.ice.land
```

There is no Windows `root` account. Certificates for `Administrator` or a
privileged AD account provide that account's local Windows privileges. A session
created with SSH certificate authentication does not contain reusable domain
credentials and normally cannot authenticate onward to another domain service
as that user.

### 4. Give the Windows SSH server a host certificate

The default Ed25519 host public key is:

```text
C:\ProgramData\ssh\ssh_host_ed25519_key.pub
```

Submit its contents to `POST /v1/certificates/ssh` with a request such as:

```json
{
  "key_id": "windows-host.ice.land",
  "public_key": "ssh-ed25519 AAAA...",
  "principals": ["windows-host.ice.land", "windows-host"],
  "duration": "2h",
  "host": true
}
```

Save the returned `certificate` as:

```text
C:\ProgramData\ssh\ssh_host_ed25519_key-cert.pub
```

Restrict its permissions:

```powershell
icacls.exe "$env:ProgramData\ssh\ssh_host_ed25519_key-cert.pub" `
  /inheritance:r /grant "*S-1-5-18:F" /grant "*S-1-5-32-544:F"
```

Add the host key and certificate to `C:\ProgramData\ssh\sshd_config`:

```text
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key
HostCertificate __PROGRAMDATA__/ssh/ssh_host_ed25519_key-cert.pub
```

Validate and restart sshd:

```powershell
& "$env:WINDIR\System32\OpenSSH\sshd.exe" -t
if ($LASTEXITCODE -ne 0) { throw "Invalid sshd configuration" }
Restart-Service sshd
```

Clients and the scoring engine use the same `known_hosts` CA entry as Linux:

```text
@cert-authority *.ice.land <contents of ssh_host_ca_key.pub>
```

### 5. Renew the Windows host certificate

Create a PowerShell renewal script and run it through Task Scheduler every 10
minutes. It should inspect the existing host certificate, request a replacement
inside its final 45 minutes, write the replacement atomically, validate
`sshd_config`, and restart `sshd` only after successful renewal. The API key and
an ordinary domain account may be stored locally for this competition
environment.

## Scoring guidance

For HTTPS, perform a normal TLS connection using `root_ca.crt`, verify the SAN,
chain and current validity, and then perform the existing application checks.

For SSH, generate an ephemeral keypair, request a short-lived user certificate,
and log in to a known scoring account. Select randomly from a configured list of
accounts; a truly random username will fail unless that account exists and is
resolvable through local NSS, SSSD, or Windows account lookup. On Windows, use
the exact account-name form accepted by OpenSSH and verify the session with a
harmless command such as `whoami`.

The API requires both the shared API key and valid AD credentials, but it
intentionally does not constrain requested principals to the authenticated
account. A valid domain user can therefore request a certificate for every local
or AD account accepted by the target, including root. The scoring engine needs
its own ordinary domain account and may request a dedicated `scorecheck`
principal; the same authorization flaw remains available as the red-team path.
