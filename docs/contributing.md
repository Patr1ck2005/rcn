# Contributing

[Home](../README.md) · [Architecture](architecture.md) · [Security](security.md)

This public preview welcomes reproducible bug reports, small fixes, documentation improvements, and discussion of adapter contracts. For a new scheduler policy, profile, platform, or execution backend, describe the user need and contract first so changes preserve existing job identities and permissions.

## Local development

Use Python 3.11+ and a supported Node.js version, then:

```shell
python -m venv .venv
# Activate .venv for your shell.
python -m pip install -e ".[dev]"
npm --prefix web ci
npm --prefix web test
npm --prefix web run build
python -m pytest
```

The console build outputs to `src/research_compute_network/web_dist/`. Keep that generated directory local; release packaging can include the built assets without putting them in source history. Run the [isolated demo](quickstart.md) to inspect the UI. Browser tests use Playwright and may require browser binaries already installed in your environment; `web/playwright.config.js` documents their local URL and viewport matrix.

## Changes and tests

- Cover behavior changes with focused tests, including failure and recovery cases where they affect identity or state.
- Use synthetic users, machine names, jobs, and packages in fixtures. Never copy production snapshots or research inputs into a test.
- Keep profile contracts versioned and preserve existing plan, job, unit, attempt, and request-hash semantics.
- Preserve permissions, owner consent, runtime approval, and audit requirements across UI, CLI, and API paths.
- Treat result transfer, integrity checks, project import, and scientific acceptance as separate states.

Run checks relevant to the change and report what actually ran. A unit test, mocked browser test, local demo, and real worker acceptance prove different things; label them accordingly.

## Source and generated outputs

Commit maintainable source, hand-written configuration, build entrypoints, documentation, and necessary lightweight audit receipts. Keep runtime state, tokens, private keys, scientific input/output, `node_modules`, built frontend assets, distribution packages, runtime ZIPs, rendered screenshots, and generated galleries out of Git. A hand-maintained source diagram is welcome; generated binary previews belong in artifact storage.

## Reports and pull requests

Include the version, supported platform, reproduction steps, expected and observed behavior, and a small synthetic example. Sanitize logs before sharing. Explain the change and relevant checks in a pull request, and identify any integration environment still needed for acceptance.

Contributions are provided under this repository's [MIT license](../LICENSE). Keep third-party notices and source attribution when using existing code. Report vulnerabilities through the private route in the [security notice](security.md), rather than a public issue containing sensitive details.
