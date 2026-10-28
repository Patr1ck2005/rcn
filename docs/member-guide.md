# Member guide

[Home](../README.md) · [Quickstart](quickstart.md) · [Security](security.md)

This guide applies to a group whose operator has configured a center, submission grants, transport and approved execution profiles. The public demo does not enroll compute machines or provide scientific runtimes. See the detailed [installation, connection and Agent guide](member-onboarding-guide.md). The installed client includes offline public help for the same workflow.

## Install, connect and configure an Agent

Follow the single [onboarding guide](member-onboarding-guide.md#三步开始): **GitHub Releases → Setup → HTTPS join → one private administrator approval → automatic Agent configuration and diagnostics**. Operators provide their own center URL; this research group's `https://rcn.my1ab.fyi` endpoint is live following alpha.6 HTTPS acceptance. See the [release status and boundaries](releases/0.15.0a6.md).

The software installer contains no personal credential. The client generates and protects the personal secret locally before sending its digest for approval. Pairing codes help the administrator check a person and device; they are not login credentials. Private bundles and SSH remain advanced recovery paths. Keep credentials and machine invitations out of Git, screenshots, issues and Agent conversations. Personal policies and project/runtime gates still apply after connection.

A lost response must resume the same pairing UUID and Agent instance. Pending approval polls every five seconds during a bounded wait. Use `join --status --wait 120` to continue; the [canonical CLI instructions](member-onboarding-guide.md#agent-申请与原编号续接) maintain the complete installed command. Removing an Agent's local encrypted login and revoking its center credential remain separate actions.

## Submit and collect work

1. Obtain a sealed task package from the project's origin adapter.
2. Import it in the member client and inspect the project, profile, resources and output contract.
3. Review the partition plan, then confirm submission.
4. Track the original operation and job; recover that operation after a disconnect.
5. Collect the result and verify the integrity receipt. Formal project import and scientific analysis remain with the origin adapter.

See the [task-package guide](member-task-package-guide.zh.md) for the data-only preparation contract. A model file alone does not specify a complete scientific task.

## Personal Agent access

Read the exported `AGENT_ACCESS.md` and `rcn-agent-access.json`. Use that JSON's complete `command_prefix`, including the Agent's own state root. Add these arguments to the prefix:

```text
help list --format json
help read member-getting-started --format markdown
context
doctor
capabilities
plan --package task.zip
```

Public help is available offline. Protected help still requires the current center identity and role. `doctor` produces a sanitized staged report; reuse that report when asking for help. The installed stable entry follows the verified active version after upgrades.

Keep the operation ID returned by `plan` and use it for `submit`, `watch`, `diagnostics` and `collect`. A watch timeout ends observation, not the job. Do not create another submission to recover an unknown reply.

The legacy `configure` CLI remains an advanced recovery option with a hidden prompt or named environment variable. Normal Agent setup uses HTTPS `join` and the automatic credential flow. No token belongs in a command-line argument. Agent access permits registered structured workloads, not an arbitrary remote shell.

## Contribute a machine

Compute participation is optional and separate from permission to submit jobs. Your operator must provide a compatible machine invitation and approved runtime setup. In the current Windows scientific route, COMSOL 6.4 and a suitable license must already be available.

Review the machine identity, managed account, work directory, resource budget, time zone, and availability before consenting. Some setup steps require Windows administrator confirmation. Pause stops admission of new work; draining lets existing work finish. OS resource behavior and the runtime's enforcement limits are described in [architecture](architecture.md#resource-semantics).

The public repository does not provide a ready-to-use scientific invitation or runtime download. Do not install an untrusted archive or approve an unfamiliar elevation prompt just because it is labeled RCN.

## If work appears stuck

Keep the original operation ID and job ID. Inspect diagnostics for approval, runtime, permission, memory, capacity, or transport gates. An uncertain attempt needs reconciliation; do not assume a disconnect means the computation failed. Share sanitized reason codes and relevant IDs with your operator. A downloaded result is scientifically accepted only after the origin project's own checks.
