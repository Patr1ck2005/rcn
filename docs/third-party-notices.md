# Third-party components

[Home](../README.md) · [RCN license](../LICENSE)

The MIT license in this repository applies to RCN's own source. Third-party packages retain their upstream copyright, license, and notice requirements. Including a dependency in an RCN wheel, browser bundle, offline installer, or wheelhouse does not relicense it as RCN MIT.

## Dependency sources

| Component group | Dependency records |
|---|---|
| Python API and runtime | `pyproject.toml`; installed package metadata and upstream license files |
| Browser console | `web/package.json` and exact versions/licenses in `web/package-lock.json` |
| Build and test tooling | Development dependencies in those same manifests |
| Optional Windows UI | The `owner-ui` extra and its upstream distributions |
| Operator-supplied scientific environment | Its own archive manifest, package licenses, solver terms, and notices |

The browser console uses React, React DOM, React Router, Recharts, and Lucide. Preserve their applicable notices and those of transitive dependencies when distributing built assets. The icon package has its own upstream licensing and attribution; do not assume every dependency uses MIT.

For a binary or offline release, inventory the exact files being shipped and carry the required upstream license texts and notices with that artifact. This source-level notice is not a complete license inventory for an operator's custom installer or runtime.

COMSOL and other external commercial software are not included and remain subject to their respective licenses. Solver/profile compatibility code does not grant rights to use or redistribute those products. Scientific templates and datasets are also outside RCN's source license unless their owner separately licenses them.
