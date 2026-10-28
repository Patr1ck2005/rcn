# Run the synthetic demo

[Home](../README.md) · [Architecture](architecture.md) · [Member guide](member-guide.md)

This path runs the real control-plane API and console with a synthetic fleet. It does not start remote workers or a scientific solver. Use a dedicated state directory and database even if RCN is already installed on the computer.

## Install from source

Joining an existing group does not require this development setup. Use the
[member onboarding guide](member-onboarding-guide.md) to install the Windows
Setup and request HTTPS membership. Operators configure their own center;
the research-group endpoint and alpha.6 acceptance status are recorded in the
[release notes](releases/0.15.0a6.md).

Use Python 3.11+ and Node.js 20.19+ or 22.12+. The frontend uses the dependency versions recorded in `web/package-lock.json`.

```shell
git clone https://github.com/Patr1ck2005/rcn.git
cd rcn
python -m venv .venv
```

Activate the environment on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or on macOS/Linux:

```sh
. .venv/bin/activate
```

Then build the console and install the package:

```shell
npm --prefix web ci
npm --prefix web run build
python -m pip install .
```

Build before installing: Vite writes the console into `src/research_compute_network/web_dist/`, which the Python package serves. For development, `python -m pip install -e ".[dev]"` keeps the installed package tied to the checkout.

## Start an isolated demo

Windows PowerShell:

```powershell
$env:RCN_HOME = Join-Path ([IO.Path]::GetTempPath()) 'rcn-public-demo'
$env:RCN_DATABASE_URL = 'sqlite:///' + (Join-Path $env:RCN_HOME 'demo.db').Replace('\', '/')
python -m research_compute_network.cli serve --demo --host 127.0.0.1 --port 18882
```

macOS/Linux:

```sh
export RCN_HOME="${TMPDIR:-/tmp}/rcn-public-demo"
export RCN_DATABASE_URL="sqlite:///$RCN_HOME/demo.db"
python -m research_compute_network.cli serve --demo --host 127.0.0.1 --port 18882
```

Open http://127.0.0.1:18882/app/overview. The console currently uses Chinese labels.

- **Fleet:** watch synthetic machine telemetry, capacity, and resource budgets.
- **Runs:** inspect jobs, work units, attempts, and progress.
- **Topology / insights:** follow the execution flow and view operational summaries.

All machines, users, jobs, and telemetry in this demo are synthetic. Compute onboarding is unavailable in demo mode. The local listener uses a trusted loopback identity; keep this demo bound to `127.0.0.1`.

## Verify and stop

In another terminal, open http://127.0.0.1:18882/health. A successful response confirms the API is serving; inspect `dataset_mode` for `demo`. API contracts are exposed at http://127.0.0.1:18882/docs.

Press `Ctrl+C` in the server terminal to stop. The dedicated state directory remains available for the next run. To begin with a fresh synthetic dataset, choose a new `RCN_HOME` and database filename; never point the demo at an existing group's database.

## If something fails

| Symptom | Check |
|---|---|
| `npm ci` rejects the Node version | Use a Node version meeting the requirement above. |
| Console route is missing or blank | Build `web`, reinstall a non-editable Python package, and restart the demo. |
| Port is already in use | Stop the prior demo or explicitly choose another local demo port. |
| Data looks unfamiliar or mode is not `demo` | Recheck both state environment variables and the server command. |
| A scientific job cannot run | The demo does not provide scientific execution. Read [adapters and runtimes](adapters-and-runtimes.md). |

For a group deployment, read the [security boundary](security.md) before changing the listener, authentication, or transport. A successful demo is a local product check, not acceptance of remote execution.

## Exercise the fixed worker locally

After installing RCN, run `python scripts/smoke_worker.py --output-root .scratch/fixed-worker-smoke` with a new output directory. It executes the shipped fixed-function worker in a real child process, verifies the synthetic result, and retains its receipt. It performs no SSH, enrollment, scientific computation or custom user-code execution. This complements the simulated fleet, without claiming a remote-machine acceptance.
