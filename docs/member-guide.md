# Member guide

[Home](../README.md) · [Quickstart](quickstart.md) · [Security](security.md)

This guide applies to a group whose operator has already configured a center, grants, transport, and approved scientific runtime. The public demo is useful for exploring the console, but it does not enroll compute machines. Ask the group operator for the center address and your personal access route.

## Submit and collect work

The Windows member client provides a local interface to a configured center. To inspect its supported lifecycle commands:

```shell
python -m research_compute_network.member_client_lifecycle --help
```

On a supported Windows installation, launch it with a dedicated local state root:

```powershell
python -m research_compute_network.member_client_lifecycle launch --state-root (Join-Path $env:LOCALAPPDATA 'RCN-PublicMember')
```

Launching the client does not install a scientific runtime or issue a group identity. It opens the local interface; connect to your operator's HTTPS center and use your own token. The Windows personal-access route stores local credentials using DPAPI.

For an authorized task:

1. Obtain a sealed task package from the project's origin adapter.
2. Import it in the member client and inspect the project, profile, resources, and output contract.
3. Create and review the partition plan, then confirm submission.
4. Track the original operation and job. If the center becomes unavailable, recover that operation rather than creating another submission.
5. Collect the result and check the client's integrity status. Formal project import and scientific analysis still belong to the origin adapter.

Keep tokens and machine invitations private. Do not put them in a task package, issue, screenshot, or command-line argument.

## Personal Agent access

The Agent CLI uses the same personal scope and structured operations. Its configure command accepts a token through a hidden prompt or an explicitly named environment variable, not a `--token` value.

```shell
rcn-agent --help
rcn-agent configure --center-url https://compute.example.org
rcn-agent status
rcn-agent capabilities
rcn-agent plan --package task.zip
```

Replace the example center with your group's address. `plan` returns an operation ID. Review the plan and retain that ID before continuing:

```shell
rcn-agent submit --operation-id YOUR_OPERATION_ID
rcn-agent watch --operation-id YOUR_OPERATION_ID --timeout-s 60
rcn-agent diagnostics --operation-id YOUR_OPERATION_ID
rcn-agent collect --operation-id YOUR_OPERATION_ID
```

Use `rcn-agent instructions --output agent-instructions` to create a new local instruction directory for a supported Agent workflow. Agent access is a permissioned client; it does not grant general remote shell access or authorize arbitrary workloads.

## Contribute a machine

Compute participation is optional and separate from permission to submit jobs. Your operator must provide a compatible machine invitation and approved runtime setup. In the current Windows scientific route, COMSOL 6.4 and a suitable license must already be available.

Review the machine identity, managed account, work directory, resource budget, time zone, and availability before consenting. Some setup steps require Windows administrator confirmation. Pause stops admission of new work; draining lets existing work finish. OS resource behavior and the runtime's enforcement limits are described in [architecture](architecture.md#resource-semantics).

The public repository does not provide a ready-to-use scientific invitation or runtime download. Do not install an untrusted archive or approve an unfamiliar elevation prompt just because it is labeled RCN.

## If work appears stuck

Keep the original operation ID and job ID. Inspect diagnostics for approval, runtime, permission, memory, capacity, or transport gates. An uncertain attempt needs reconciliation; do not assume a disconnect means the computation failed. Share sanitized reason codes and relevant IDs with your operator. A downloaded result is scientifically accepted only after the origin project's own checks.
