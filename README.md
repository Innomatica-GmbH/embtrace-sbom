# embtrace-check

**Reads your build, writes your bill of materials — locally.** One command in
your project folder produces a CycloneDX SBOM, including from **configured
builds** (`CMakeCache.txt`) and **Yocto/Buildroot build output** that generic
scanners cannot read. **The default run transmits nothing.**

If you want the free CRA readiness report on top — traffic-light status against
the [EU Cyber Resilience Act](https://embtrace.dev/en/cra-nis2-guide.html),
your component inventory, known vulnerabilities with severity — send the bill
explicitly. You are shown exactly what would leave the house, and asked first.

This collector is **open source for one reason: so you can verify exactly
what leaves your machine.**

## What a send contains — and what it never does

The default run sends nothing at all. **If** you send (`--send`, or by
answering the question), this travels (JSON, ~a few kB):

- names, versions and package ecosystems of your dependencies
  (from lockfiles and build files: Conan, vcpkg, CMake, Cargo, npm/yarn/pnpm,
  Python incl. uv, Go, Maven/Gradle, Meson, Alire, and more),
- **Zephyr workspaces**: the `west.yml` module manifest — every module
  with its pinned revision,
- **Yocto and Buildroot BUILD OUTPUT**: run the check in your build
  directory — it reads `deploy/images/**/*.manifest` (what is actually
  in your image) resp. `legal-info/manifest.csv`. The recipe source
  tree only says what *could* be built, so the build output is what
  counts,
- names and versions of FPGA IP cores
  (AMD/Xilinx Vivado `.hwh`/`.xci`, Microchip Libero Tcl/`.cxf`,
  Intel/Altera Quartus `*_hw.tcl`),
- the project folder name (hash it with `--anonymize`),
- scan statistics (number of build files, tool version),
- **only if you wrote them yourself** in `embtrace-deps.yaml`: the
  supplier, license, purl and CPE entries of your declaration — a
  declaration is written for SBOM purposes, so it travels by default and
  makes your report complete (58 instead of 17 attributed licenses on a
  typical Zephyr project). Withhold it with `--no-declared-metadata`.
  Discovered components never carry these fields.

**Never transmitted:** source code, file paths, file contents, configuration,
credentials. The supplier of a *detected* FPGA IP core is known locally but
deliberately **not** transmitted — a supplier you declare yourself in
`embtrace-deps.yaml` is your statement and does travel.
See for yourself before sending anything:

```bash
embtrace-check . --dry-run     # prints the exact payload, uploads nothing
```

Build outputs (`dist/`, `build/`, `node_modules/`, …) and hidden
directories are never scanned. Project-specific excludes go into a
committed `.embtraceignore` at the project root — one glob pattern per
line, `#` comments.

**Quality rules** (v0.6.0): component identity is (name, version,
ecosystem) — nested second versions of one package are kept as own rows
(the older nested version is often the vulnerable one); build tools and
system libraries (`Doxygen`, `-lanl`, `find_package(Git)`, …) are
dropped via a curated 950-name skip list — your own `embtrace-deps.yaml`
declarations are never skipped; `*` and guessed versions are never
reported — a missing version is shown as honestly missing. If no
supported build system is found, nothing is uploaded and the tool tells
you exactly what it looks for and where.

## Usage

```bash
pipx install embtrace-check         # or: pip install embtrace-check,
                                    #     or download the standalone binary
embtrace-check .                    # reads your build, writes sbom.cdx.json
                                    # — and transmits NOTHING
```

You now have your own CycloneDX SBOM. An existing `sbom.cdx.json` is never
silently overwritten.

**Free CRA readiness report** (optional): send the bill explicitly —

```bash
embtrace-check . --send --email you@example.com
```

You are shown exactly what would leave the house (names and versions, no
paths, no code) and asked to confirm; `--yes` skips the question in scripts.
No code is required. The report arrives within 24 hours. You can also simply
e-mail your `sbom.cdx.json` to support@innomatica.de.

More options: `embtrace-check --help` — including `--sbom PATH` (write the
SBOM elsewhere), `--output payload.json` for air-gapped environments (send the
file by mail) and `--with-tools` to additionally use native package-manager
CLIs for higher-fidelity results.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | success |
| 1    | error (network, missing --email with --send, …) |
| 2    | no components found — declare dependencies manually in `embtrace-deps.yaml` |

## Privacy

Data is processed exclusively on Innomatica's own servers in Germany and is
never shared or sold. Full notes: <https://embtrace.dev/check-privacy>.

## About

`embtrace-check` is the free entry point to
[embtrace](https://embtrace.dev) — the CRA/NIS2 compliance toolchain for
embedded software teams by [Innomatica GmbH](https://embtrace.dev/impressum.html).
The server side (enrichment, vulnerability monitoring, reports) is a
commercial product; this repository contains the complete client.

Maintained by Innomatica; the roadmap follows the product. Issues and PRs are
welcome — please report security topics per [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Innomatica GmbH
