# Loon security posture

This repository must stay safe to publish. Do not commit full `.lcf` files,
proxy nodes, remote proxy subscription URLs, certificates, passphrases, API
tokens, or MITM hostnames.

## Account-risk posture

- Prefer stable routing over fastest-node switching for finance, crypto,
  payment, social, and streaming accounts.
- Keep mainland实名 services on `DIRECT` unless there is a specific reason to
  proxy them.
- Keep PayPal separate from the broader finance/crypto group so it can use a
  dedicated stable exit.
- Avoid MITM/rewrite plugins for authenticated app business traffic. DNS and
  HTTPDNS hygiene are lower risk than request-body/header rewriting.
- Treat ad blocking and app enhancement plugins as optional. Disable them first
  when login, playback, payment, captcha, or account-risk signals appear.

## Public artifacts

Safe to publish:

- Domain rule lists under `rules/loon/`.
- Routing-order documentation.
- Validation and secret-audit tooling.

Unsafe to publish:

- `[Proxy]`, `[Remote Proxy]`, and complete `[Mitm]` material.
- Node names if they reveal subscription/provider identity.
- Subscription URLs or URLs with token-like query parameters.
- Certificates, passphrases, private keys, cookies, or account identifiers.

## Local Loon policy

Use the generated rules in `rules/loon/generated/` as the subscription source.
The generator pulls reviewed upstream sources, applies local supplements, and
drops exact duplicates plus later rules already covered by earlier
`DOMAIN-SUFFIX` rules.

High-level generated order:

1. Reject and LAN rules.
2. `AccountSafety-DIRECT` and mainland direct foundations.
3. Device/service rules such as `Seetong-Local`.
4. Stable payment, finance, and crypto rules.
5. Company/service rules.
6. Category aggregation rules.
7. ASN/direct catchalls.

The config should not mix these generated subscriptions with the original
upstream subscriptions, because that reintroduces duplicate and shadowed rules.
