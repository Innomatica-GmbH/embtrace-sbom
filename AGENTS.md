# AGENTS.md — embtrace-sbom (the public twin of the embtrace suite)

Rules for any agent or person working in this repository. They come from the
owner's decisions (Innomatica GmbH, Ivan Maradzhiyski) and are not up for
reinterpretation here.

## What this repository is

`embtrace-sbom` (formerly `embtrace-check`) is the open-source collector of
the embtrace CRA suite: it reads a build and writes a CycloneDX SBOM locally,
and — only on the user's explicit decision — sends dependency metadata for a
free CRA readiness report. It is published so that anyone can verify what
leaves their machine.

## Scope policy (owner's decision, 11.09.2026)

- **The public twin stays deliberately simpler than the suite.** Depth —
  full CMake condition resolution, the complete dependency graph across all
  ecosystems, knowledge-base enrichment, triage, audit reports — stays on
  the suite side. Do not port suite depth into this repository "because it
  is easy".
- **A shared scanner base between suite and twin is on hold** pending the
  owner's license strategy: it would publish the full scanner. Any move in
  that direction needs the owner's explicit decision first.
- **License: GPL-3.0-or-later** from 0.9.0 on (see LICENSE). Contributions
  are accepted under the same license. Releases up to embtrace-check 0.8.6
  stay MIT.

## Working rules

- Code and comments in English; user-facing texts plain, no marketing
  adjectives, every claim measurable (see the suite's rule "Präsens nur mit
  Testbeleg": present tense only for behaviour with a code path and a test).
- Nothing is transmitted by default; `--send` shows the exact list first and
  asks. Keep it that way — it is the product.
- Lint with the same ruff rule set as the suite (`ruff check src tests`),
  run `pytest -q` before pushing; the `tests` workflow runs both on 3.11 and
  3.12 and fails fast.
- Releases: tag `vX.Y.Z` → the `publish` workflow builds and publishes
  `embtrace-sbom` (PyPI, Trusted Publishing), the forwarding shell
  `embtrace-check` (`shim/`), and the Linux binary. A release needs
  `.github/release-notes/vX.Y.Z.md`.
- **No AI co-author trailers in commits of this public repository.**
- Metadata only: fixtures and tests reference package names and versions;
  nothing here installs or executes third-party packages by design.
