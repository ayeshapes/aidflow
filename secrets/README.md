# secrets/

This folder is git-ignored. Only this README is tracked.

It will hold local, sensitive material that must NEVER be committed:
- Root CA private key and certificate (Warisha, PKI)
- Server certificate and key for nginx
- Client certificates (.p12) issued to users
- Field-encryption key and signing keys
- Backup encryption passphrases

Share these with teammates only through a secure channel, never through Git.
Real configuration values belong in `.env` (also git-ignored).
