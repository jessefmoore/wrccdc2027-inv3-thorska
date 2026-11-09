# Certificate renewal timer example

Install the template units and create one environment file per dependent
service:

```bash
install -m 0644 step-cert-renew@.service /etc/systemd/system/
install -m 0644 step-cert-renew@.timer /etc/systemd/system/
install -d -m 0700 /etc/step/renew
install -m 0600 wordpress.env /etc/step/renew/wordpress.env
systemctl daemon-reload
systemctl enable --now step-cert-renew@wordpress.timer
```

The timer runs approximately every 10–12 minutes. The corresponding oneshot
service exits cleanly while the certificate has more than 45 minutes remaining.
When renewal is necessary, it renews through Step CA and reloads or restarts the
dependent systemd unit.

Test it with:

```bash
systemctl start step-cert-renew@wordpress.service
systemctl status step-cert-renew@wordpress.service
systemctl list-timers 'step-cert-renew@*'
```

For an Apache deployment, change the certificate paths and set
`RELOAD_UNIT=httpd.service`. Each custom application can use its own environment
file and reload target.
