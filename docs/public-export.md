# Internal and public release parity

`manifests/public-export.json` is the reviewed common-file allowlist. It records
exact shared collection, volume-budget, result-preparation, member, help code and UI
including incremental inventory, registered restore sources, event-driven transfer
queue, bounded physical inventory and release-version verification
files, plus intentional version, deployment and scientific-approval differences.
Unlisted files are outside this tool's copy scope. In particular, a service/API
change needs a separate public review; this tool never copies whole directories.
Private scientific archives, their release-input manifest and runtime lock stay
outside the public distribution. Public HTTPS onboarding and internal managed
SSH policy remain distribution-specific.

`required_files` contains the task-package guide and packaged help. Both editions
must provide them. Public navigation and adapter links differ, so these files
are checked against their own source and never copied by this tool.

Run from either repository with Python 3.11+. All commands are check-only unless
`--copy-common` is present. Use the intended internal and independent public Git
roots; no production state or credentials are needed.

```powershell
python scripts/release_parity.py --internal-root C:/path/to/internal --public-root D:/path/to/public
```

Source checks compare allowlisted text after LF/CRLF normalization. Missing or
different common files fail. Public exclusion checks use `git ls-files`, avoiding
recursive inspection of local state or `.scratch`. The existing public
`scripts/check_public_tree.py` remains the broader source/credential boundary
check and must also pass.

To deliberately copy the reviewed common files from internal to public, first
inspect the source check and manifest, then run:

```powershell
python scripts/release_parity.py --internal-root C:/path/to/internal --public-root D:/path/to/public --copy-common
```

Copy preflights all allowlisted paths before writing. It reports changed files,
refuses links/reparse points and excluded paths, and does not stage or commit.
Intentional differences and all other files retain their public implementation.

After building **both** distributions and their member installers, check the
actual delivered payloads. An artifact check requires all six artifact inputs:

```powershell
python scripts/release_parity.py --internal-root C:/path/to/internal --public-root D:/path/to/public `
  --internal-wheel C:/build/internal.whl --public-wheel D:/build/public.whl `
  --internal-runtime C:/build/RCN-Member-Setup.runtime.zip --public-runtime D:/build/RCN-Member-Setup.runtime.zip `
  --internal-setup-manifest C:/build/RCN-Member-Setup.manifest.json --public-setup-manifest D:/build/RCN-Member-Setup.manifest.json `
  --internal-web-root C:/build/internal-source/src/research_compute_network/web_dist `
  --public-web-root D:/build/public-source/src/research_compute_network/web_dist
```

Web roots default to each source root's `src/research_compute_network/web_dist`.
Override them when building from clean exported sources. The index, JavaScript
and CSS are required; every built asset must match its own wheel byte for byte.
Bundles are intentionally checked within each distribution because the outer
console and release metadata differ.

The check hashes the real wheel and runtime ZIP, validates both the external
Setup manifest and embedded `member-software-release.json`, and checks every
declared runtime file against the ZIP bytes. It then compares the entire RCN
package between that side's wheel and the installed
`runtime/python/Lib/site-packages/research_compute_network/` payload. Shared
Python/help files must also match source; common package files must have identical
**raw SHA-256** in both wheels. Required help is verified against its own edition.
Public ZIP/MPH payloads fail; the embedded Python `python311.zip` is the only
allowed runtime archive. Optional
`--internal-setup` and `--public-setup` also verify the delivered EXE hashes.

Exit status is zero only for the requested scope. JSON identifies `source-only`
versus `source-and-artifacts` and reports common payload hashes and failures.
Source success alone does not establish release parity. These checks establish
content integrity, not publisher signatures, deployment, member-machine
installation or scientific acceptance.
