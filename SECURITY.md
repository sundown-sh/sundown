# Security policy

## Reporting a vulnerability

Please email **security@sundown.sh** with:

- A description of the vulnerability
- A proof-of-concept or reproduction steps
- The affected version (`git rev-parse HEAD` or release tag)
- Your disclosure timeline preference

We aim to respond within **72 hours** and to ship a fix within **14 days**
for high/critical issues. We will credit you in the release notes unless
you ask us not to.

## Threat model

Sundown is a **read-only** auditing tool. It is designed to minimize
blast radius:

| Concern                          | Mitigation                                       |
| -------------------------------- | ------------------------------------------------ |
| Compromised Sundown instance     | Connectors hold read-only scopes; no writes.     |
| Stolen connector secret          | Encrypted at rest with a key-derived AEAD.       |
| Tampered audit log               | Append-only; HMAC-chained for tamper detection.  |
| Malicious connector              | Connector registry uses an explicit allow-list.  |
| Outbound webhook spoofing        | Body signed with HMAC-SHA256 of the payload.     |
| Replay attack on outbound hooks  | Signed timestamp; reject if older than 5 min.    |

## Scopes Sundown will request

| Provider          | Scopes                                                 |
| ----------------- | ------------------------------------------------------ |
| BambooHR          | `directory:read`                                       |
| Rippling          | `employees:read`                                       |
| Okta              | `okta.users.read`                                      |
| Google Workspace  | `admin.directory.user.readonly`                        |
| GitHub            | App: `Members:Read`, `Organization administration:Read`|
| Slack             | `users:read`, `users:read.email`, `team:read`          |

Sundown will **refuse** to operate with write scopes on any grant.
