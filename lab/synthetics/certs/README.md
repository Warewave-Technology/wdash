# Lab certificates

Generated, not committed. `../../lab.sh up synthetics` makes them if they are
missing; `make-certs.sh` is what it runs.

They are private keys. Self-signed, worthless, and for a lab that listens on
localhost — but a repository with `-----BEGIN PRIVATE KEY-----` in it teaches
whoever reads it that this is normal, and every secret scanner ever written
will flag the clone. Neither is worth the two seconds `openssl` takes.

Two certificates, because a TLS monitor is mostly an expiry clock:

  * `healthy`   — a year out, so the page has an untroubled row
  * `expiring`  — twelve days out, so the warning band is exercised without
                  waiting a year for it
