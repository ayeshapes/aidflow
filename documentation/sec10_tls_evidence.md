# SEC-10 evidence: trusted TLS connection (ticket A-05)

Goal: show that a client reaches AidFlow over TLS 1.2+, that the server proves its
identity with a certificate chaining to our CA, and that the connection is refused
when it should be.

> The sample output below was captured against a **TEMPORARY self-signed
> certificate** (`scripts/dev_self_signed_cert.sh`). It shows what to look for but is
> **not** SEC-10 evidence. Re-run the commands with the CA-issued certificate and
> attach that output.

## 0. Prepare
`ca.pem` is the **public** certificate of the CA that issued the server certificate
(Warisha's root CA certificate, never its key). With the temporary cert, the cert is
its own CA: `cp secrets/server.crt ca.pem`.

```bash
./scripts/dev.sh up        # stack running; nginx on https://localhost
```

## 1. curl
```bash
curl -v --cacert ca.pem https://localhost/api/health
```
Look for these lines (sample, trimmed):
```
* CAfile: ca.pem
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519 / id-ecPublicKey
* Server certificate:
*  subject: ... CN=localhost
*  subjectAltName: host "localhost" matched cert's "localhost"
*  issuer: <your CA's name>          (temporary cert: same as subject)
*  SSL certificate verify ok.
< HTTP/1.1 200 OK
< Strict-Transport-Security: max-age=31536000
< X-Content-Type-Options: nosniff
< X-Frame-Options: DENY
< Referrer-Policy: strict-origin-when-cross-origin
< Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
{"status":"ok","db":true}
```

## 2. openssl s_client
The command as requested:
```bash
openssl s_client -connect localhost:443 -showcerts
```
This does not tell openssl which CA to trust, so unless your system already trusts the
CA it ends with `Verify return code: 20 (unable to get local issuer certificate)`
(self-signed: `18`). That is expected, not a TLS fault. For the evidence run, add the CA
and make verification mandatory:
```bash
openssl s_client -connect localhost:443 -servername localhost -showcerts \
  -CAfile ca.pem -verify_hostname localhost -verify_return_error </dev/null
```
Sample (trimmed):
```
Certificate chain
 0 s:O = ..., CN = localhost
   i:<issuer>
   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: ecdsa-with-SHA256
   v:NotBefore: ...; NotAfter: ...
Verified peername: localhost
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Verification: OK
Verify return code: 0 (ok)
```

## 3. What proves a trusted TLS connection
All of these, together:

| Evidence | Shows |
|---|---|
| `SSL certificate verify ok` (curl) / `Verify return code: 0 (ok)` and `Verification: OK` (openssl) | The certificate chain validates up to the CA in `ca.pem`: signature, validity dates and key usage all checked. This is what "trusted" means. |
| `subjectAltName: host "localhost" matched` / `Verified peername: localhost` | The certificate is for the host we asked for, so a valid certificate for some other site cannot be swapped in. |
| `issuer:` / `i:` is **our CA**, not equal to `subject` | It was issued by the project CA. Issuer == subject means self-signed (the temporary cert). |
| `SSL connection using TLSv1.3` (or `TLSv1.2` + an `ECDHE-...-GCM`/`CHACHA20` suite) | Modern protocol with forward secrecy and authenticated encryption. |
| `NotBefore`/`NotAfter` covers today | The certificate is currently valid. |
| Response carries `Strict-Transport-Security` etc. | The response came through nginx with the security headers applied. |

Verification only means something if it can fail. These negative checks (all observed
against the sample setup) complete the evidence:
```bash
curl https://localhost/api/health                  # no --cacert: curl: (60) SSL certificate problem
openssl s_client -connect localhost:443 -CAfile ca.pem -verify_hostname evil.example -verify_return_error
                                                   # verify error: hostname mismatch
openssl s_client -connect localhost:443 -tls1_1 -cipher 'ALL:@SECLEVEL=0'
                                                   # tlsv1 alert protocol version (alert 70)
openssl s_client -connect localhost:443 -tls1_2 -cipher 'AES128-SHA:DES-CBC3-SHA'
                                                   # handshake failure (alert 40): no weak suite
curl -si http://localhost/api/health | head -1     # HTTP/1.1 301 Moved Permanently
curl -sS http://localhost:8000/api/health          # connection refused: backend has no host port
```
(The `-SECLEVEL=0` option only lowers the *client's* own limits so it actually attempts
the old protocol; without it OpenSSL 3 refuses locally and proves nothing about the server.)

## 4. Header spoofing (SEC-10)
`X-SSL-Client-Verify` and `X-SSL-Client-S-DN` are set to `""` on every proxied request,
so nginx never forwards a client-supplied value. Checked against a header-echo upstream
with the temporary setup: a request sending both headers (and a forged `X-Forwarded-For`)
reached the upstream with neither `X-SSL-*` header present and `X-Forwarded-For` replaced
by the real peer address. Same result on `/`, `/api/` and `/api/docs`.
