# Security and deployment boundary

[Home](../README.md) · [Architecture](architecture.md) · [Adapters and runtimes](adapters-and-runtimes.md)

RCN coordinates processes and result transfers across contributed machines. A group operator is responsible for deployment identity, authorization, network exposure, approved runtime distribution, host policy, and storage. This public preview has not been independently security-audited.

## Local demo

Use an independent `RCN_HOME` and database and bind the synthetic demo to `127.0.0.1`. The demo uses a trusted local identity for inspection. Do not expose that listener to a LAN or the internet. Moving beyond loopback requires the supported authentication/TLS or authenticated gateway configuration; a local demo command is not a deployment recipe.

## Permission and execution model

- Personal tokens, project grants, machine participation, and administrator privileges have separate scopes. Permission to submit work does not imply permission to contribute or control a machine.
- Jobs select registered profiles with structured data. Arbitrary commands and general-purpose remote shells are outside the supported job contract.
- Scientific runtimes must be supplied, fingerprinted, approved, and admitted by the deploying group. Their code is trusted execution code, not an adversarial sandbox.
- Owner consent, resource policies, preview/confirm operations, and audit records are part of the control model. Review exceptional host-wide operations separately from routine RCN process control.
- Memory requests are scheduling declarations, not hard OS isolation. Review the chosen backend's actual enforcement before sharing a workstation.

## Credentials and data

Keep personal tokens, invitations, host keys, private keys, certificates, database backups, and production state outside the repository. Use personal credentials and the supported local credential storage. Do not paste tokens into URLs, command-line arguments, public issues, or Agent transcripts.

The metadata database stores policy, manifests, and audit records. Input/output bytes may pass through staging directories; configure their access, retention, capacity, and custody policies. Hash verification checks integrity; project-side verification and scientific acceptance remain separate responsibilities.

Only install member packages and approved runtimes from a trusted operator through a verified distribution route. MIT licensing of RCN does not vouch for an arbitrary archive or grant a solver license.

## Report a vulnerability

Use the repository's **Security → Report a vulnerability** private reporting option if it is available. If that option is unavailable, open an issue requesting a private contact without including exploit details, credentials, host addresses, or private data. A dedicated monitored security mailbox and response-time commitment are not established for this preview.

Include the affected version and component, impact, and a synthetic reproduction through the private channel. Revoke exposed credentials through your operator immediately; deleting a public post alone does not revoke them.
