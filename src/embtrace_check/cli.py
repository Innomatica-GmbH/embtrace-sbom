"""CLI entry point for embtrace-check (standalone CRA Readiness Check collector).

Usage:
    embtrace-check . --code CHK-ACME-7F3A     # one-time code from embtrace.dev/check
    embtrace-check . --dry-run                # show exactly what would be sent
    embtrace-check . --output payload.json    # offline / firewall fallback
    embtrace-check . --voucher STOIL-2026 --email cto@example.com   # partner voucher

Exit codes: 0 = success, 1 = error, 2 = no components found.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from embtrace_check import __version__
from embtrace_check.collector import collect_components
from embtrace_check.core.exceptions import EmbtraceError
from embtrace_check.payload import build_payload
from embtrace_check.upload import DEFAULT_SUBMIT_URL, serialize_payload, upload_payload

_PRIVACY_URL = "https://embtrace.dev/check-privacy"

console = Console(stderr=True)
_stdout = Console(soft_wrap=True)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="embtrace-check")
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option(
    "--code",
    default="",
    help="Personal one-time code from https://embtrace.dev/check (report goes "
    "to the address you registered there).",
)
@click.option("--voucher", default="", help="Partner voucher / campaign code.")
@click.option(
    "--lang", type=click.Choice(["de", "en"]), default=None,
    help="Report language. Default: the language of the landing page "
         "your code was issued on (German if undeterminable).",
)
@click.option(
    "--email",
    "contact_email",
    default="",
    help="E-mail address the report is sent to (required with --voucher).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Print the exact payload that would be uploaded, upload nothing.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the payload to a file instead of uploading (offline fallback).",
)
@click.option(
    "--anonymize",
    is_flag=True,
    help="Replace the project name with a stable hash in the payload.",
)
@click.option(
    "--with-tools",
    is_flag=True,
    help="Additionally use native package-manager CLIs (cargo, go, npm, ...) if installed.",
)
@click.option(
    "--no-declared-metadata",
    "no_declared_metadata",
    is_flag=True,
    help="Do not transmit supplier/license/purl/cpe you declared in "
    "embtrace-deps.yaml (they are included by default because you wrote "
    "them for SBOM purposes; --dry-run shows the payload either way).",
)
@click.option(
    "--url",
    default=DEFAULT_SUBMIT_URL,
    show_default=False,
    help="Override the submit endpoint (testing).",
)
def main(  # noqa: PLR0913 — CLI surface, mirrors documented flags
    path: Path,
    code: str,
    voucher: str,
    lang: str | None,
    contact_email: str,
    dry_run: bool,
    output: Path | None,
    anonymize: bool,
    with_tools: bool,
    no_declared_metadata: bool,
    url: str,
) -> None:
    """Collect dependency metadata for the embtrace CRA Readiness Check.

    Scans PATH (default: current directory) for lockfiles and build files,
    then uploads component names/versions of discovered components — plus
    the supplier/license/purl/cpe you declared yourself in
    embtrace-deps.yaml (disable with --no-declared-metadata). Never code,
    never file paths. Privacy notice: https://embtrace.dev/check-privacy
    """
    try:
        _run(
            path=path,
            code=code,
            voucher=voucher,
            lang=lang,
            contact_email=contact_email,
            dry_run=dry_run,
            output=output,
            anonymize=anonymize,
            with_tools=with_tools,
            no_declared_metadata=no_declared_metadata,
            url=url,
        )
    except EmbtraceError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)


def _run(  # noqa: PLR0913 — mirrors the CLI surface
    *,
    path: Path,
    code: str,
    voucher: str,
    lang: str | None = None,
    contact_email: str,
    dry_run: bool,
    output: Path | None,
    anonymize: bool,
    with_tools: bool,
    no_declared_metadata: bool = False,
    url: str,
) -> None:
    """Execute collect → assemble → (print | write | upload)."""
    uploading = not dry_run and output is None
    if uploading:
        if code and voucher:
            console.print("[red]Error:[/red] use either --code or --voucher, not both.")
            sys.exit(1)
        if code:
            # Personal one-time token: the server knows the registered address.
            voucher = code
        elif not voucher:
            console.print(
                "[red]Error:[/red] a code is required for upload. Get your free "
                "one-time code at https://embtrace.dev/check"
            )
            sys.exit(1)
        elif "@" not in contact_email:
            console.print("[red]Error:[/red] --email must be a valid address (report delivery).")
            sys.exit(1)
        if code and contact_email and "@" not in contact_email:
            console.print("[red]Error:[/red] --email must be a valid address (report delivery).")
            sys.exit(1)

    console.print(f"[bold]embtrace-check[/bold] {__version__} — scanning {path.resolve().name}/")
    components, stats = collect_components(
        path,
        with_tools=with_tools,
        include_declared_metadata=not no_declared_metadata,
    )
    # Conditional alternatives travel MARKED, not as components (Befund 44).
    real = [c for c in components if not c.condition]
    conditional = [c for c in components if c.condition]

    if not real:
        # An empty report is the worst possible answer — but WHY it is empty
        # differs, and telling a CMake customer "no build system found" when
        # their CMakeLists.txt was read is the Befund-42 mistake (describing
        # the tool, not their project). Three cases, three texts.
        if stats.build_files_scanned == 0:
            console.print(
                "[yellow]No supported build system found in this directory."
                "[/yellow]\n"
                "Recognised: Conan, vcpkg, CMake, Cargo, npm/yarn/pnpm, Python "
                "(pip/poetry/uv/pipenv), Go, Maven/Gradle, Alire, Zephyr "
                "(west.yml), FPGA projects (Vivado/Libero/Quartus) — and "
                "Yocto/Buildroot BUILD OUTPUT.\n"
                "For Yocto/Buildroot: run the check in your BUILD directory "
                "(it reads deploy/images/*.manifest resp. "
                "legal-info/manifest.csv), not in the recipe source tree.\n"
                "For proprietary components without a package manager: declare "
                "them once in embtrace-deps.yaml and re-run.\n"
                "Adjust exclusions via a committed .embtraceignore."
            )
        elif conditional:
            # Build files WERE read; the default build has no components, but
            # optional backends are available behind a build option.
            names = ", ".join(sorted(c.name for c in conditional)[:4])
            console.print(
                "[yellow]No components in the DEFAULT build.[/yellow]\n"
                f"{len(conditional)} optional backend(s) are available behind "
                f"a build option ({names}): no default build contains them, "
                "and mutually exclusive ones (OpenSSL or LibreSSL) never both "
                "ship.\n"
                "Configure the build once (e.g. `cmake -S . -B build "
                "-DWITH_SSL=ON`) so embtrace-check reads which you actually "
                "use, or declare it in embtrace-deps.yaml."
            )
        else:
            # Build files read, genuinely nothing — self-contained.
            console.print(
                "[yellow]No external components found.[/yellow]\n"
                f"Read {stats.build_files_scanned} build file(s) "
                f"({', '.join(stats.ecosystems) or 'no package manager'}); "
                "no third-party packages are declared. For a self-contained "
                "library that is plausible.\n"
                "If you link system libraries via `-l` or vendor foreign code "
                "(third_party/, vendor/), declare it in embtrace-deps.yaml — "
                "or configure the build once (e.g. `cmake -S . -B build`) so "
                "embtrace-check can read build/CMakeCache.txt.\n"
                "Adjust exclusions via a committed .embtraceignore."
            )
        # A read build system that yields nothing (self-contained) or only
        # conditional backends is a VALID result, not a failure — a clean
        # library run in CI must not fail (Befund 44 follow-up). Only "no
        # build system found at all" stays exit 2.
        sys.exit(2 if stats.build_files_scanned == 0 else 0)

    console.print(
        f"Found [bold]{len(real)}[/bold] components "
        f"({', '.join(stats.ecosystems) or 'no ecosystem info'}) "
        f"in {stats.build_files_scanned} build files."
    )
    if conditional:
        names = ", ".join(sorted(c.name for c in conditional)[:4])
        console.print(
            f"[dim]{len(conditional)} conditional alternative(s) behind build "
            f"options ({names}) — marked, not counted, not gating. Configure "
            f"the build to resolve which is used.[/dim]"
        )
    for src in stats.build_output_sources:
        console.print(f"[dim]Build output: {src}[/dim]")
    mehrfach = len(real) - len({c.name.lower() for c in real})
    if mehrfach:
        console.print(
            f"[dim]{mehrfach} additional version(s) of already-listed "
            f"packages included — nested second versions are often the "
            f"vulnerable ones.[/dim]"
        )

    ausgeschlossen = sum(1 for c in components if c.scope == "excluded")
    if ausgeschlossen:
        console.print(
            f"[dim]{ausgeschlossen} component(s) from test/example "
            f"directories or dev tooling marked scope=excluded — listed, "
            f"never gating. Adjust via .embtraceignore.[/dim]"
        )
    declared = sum(1 for c in components if c.source_type == "declared")
    if declared and not no_declared_metadata:
        console.print(
            f"[dim]{declared} component(s) from embtrace-deps.yaml include the "
            f"supplier/license/purl/cpe you declared there "
            f"(--no-declared-metadata to withhold, --dry-run to inspect).[/dim]"
        )

    payload = build_payload(
        lang=lang or "",
        voucher=voucher or code or "DRY-RUN",
        # With a personal --code the address stays empty — the server fills it
        # from the registration; the placeholder is for dry-run/offline only.
        contact_email=contact_email or ("" if code else "dry-run@localhost"),
        tool_version=__version__,
        project_label=path.resolve().name,
        components=components,
        stats=stats,
        anonymize=anonymize,
    )

    if dry_run:
        console.print("[dim]-- payload that would be uploaded (nothing was sent): --[/dim]")
        _stdout.print_json(payload.model_dump_json())
        console.print(f"[dim]Privacy notice: {_PRIVACY_URL}[/dim]")
        return

    if output is not None:
        output.write_bytes(serialize_payload(payload))
        console.print(
            f"[green]Payload written to {output}.[/green] "
            "Send it to support@innomatica.de to receive your report."
        )
        return

    reference = upload_payload(payload, url=url)
    destination = contact_email or "your registered address"
    console.print(
        f"[green]Uploaded.[/green] Reference: [bold]{reference}[/bold] — "
        f"your CRA readiness report will be sent to {destination} within 24 hours."
    )


if __name__ == "__main__":
    main()
