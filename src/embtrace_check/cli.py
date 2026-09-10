"""CLI entry point for embtrace-check (standalone CRA Readiness Check collector).

Usage:
    embtrace-check .                          # read the build, write your SBOM — sends NOTHING
    embtrace-check . --send --email you@example.com   # free CRA report (asks first)
    embtrace-check . --sbom bill.json         # write the SBOM somewhere else
    embtrace-check . --dry-run                # show exactly what a send would contain
    embtrace-check . --output payload.json    # offline / firewall fallback

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
from embtrace_check.payload import CheckPayload, build_payload
from embtrace_check.sbom_out import write_cyclonedx
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
    "--send",
    is_flag=True,
    help="Send the bill of materials to embtrace for a free CRA readiness "
    "report (needs --email; asks for confirmation first, shows exactly what "
    "leaves the house). Without this flag NOTHING is transmitted. "
    "Privacy: https://embtrace.dev/check-privacy",
)
@click.option(
    "--no-send",
    "never_send",
    is_flag=True,
    help="Never ask and never transmit: just read the build and write the "
    "SBOM. For anyone who has decided they will not send.",
)
@click.option(
    "--yes",
    "assume_yes",
    is_flag=True,
    help="Skip the confirmation question (for scripts/CI). Only meaningful "
    "together with --send.",
)
@click.option(
    "--sbom",
    "sbom_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Where to write the CycloneDX SBOM (default: ./sbom.cdx.json). An "
    "existing file is never silently overwritten.",
)
@click.option(
    "--code",
    default="",
    help="Personal one-time code from https://embtrace.dev/check (optional; "
    "the report goes to the address you registered there).",
)
@click.option("--voucher", default="",
              help="Optional partner / campaign code (tracking only).")
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
    send: bool,
    never_send: bool,
    assume_yes: bool,
    sbom_path: Path | None,
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
    """Read your build and write your bill of materials — locally.

    Scans PATH (default: current directory) for lockfiles and build files —
    including CONFIGURED builds (CMakeCache.txt) and Yocto/Buildroot build
    output — and writes a CycloneDX SBOM next to you. The default run
    TRANSMITS NOTHING.

    To get a free CRA readiness report, send the bill explicitly with --send
    (you are shown exactly what would leave the house and asked first).
    Never code, never file paths. Privacy: https://embtrace.dev/check-privacy
    """
    try:
        _run(
            path=path,
            send=send,
            never_send=never_send,
            assume_yes=assume_yes,
            sbom_path=sbom_path,
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


def _asks_interactively(assume_yes: bool) -> bool:
    """Only ask when a human is actually there (order: in CI never ask)."""
    if assume_yes:
        return False
    return sys.stdin.isatty() and sys.stdout.isatty()


def _print_send_invitation(written: Path) -> None:
    """What the customer has, and how to get the report — no pressure."""
    console.print(
        f"\n[bold]Nothing was transmitted.[/bold] Your bill of materials is "
        f"yours: {written}\n"
        f"Free CRA readiness report: send it with "
        f"[bold]embtrace-check --send --email you@example.com[/bold] "
        f"(or e-mail {written.name} to check@innomatica.de) — "
        f"report within 24 hours.\n"
        f"[dim]Privacy: {_PRIVACY_URL}[/dim]"
    )


def _print_leaving_summary(payload: CheckPayload) -> None:
    """Exactly what would leave the house: names + versions, no paths."""
    comps = payload.components
    console.print(
        f"\n[bold]This would be sent[/bold] ({len(comps)} entries — names and "
        f"versions only, no code, no file paths):"
    )
    for c in comps[:15]:
        console.print(f"  {c.name} {c.version or '(no version)'}")
    if len(comps) > 15:
        console.print(f"  … and {len(comps) - 15} more")
    console.print(
        f"  [dim]plus: project label '{payload.project_label}', tool version, "
        f"contact address '{payload.contact_email or '(from your code)'}'[/dim]"
    )


def _run(  # noqa: PLR0913 — mirrors the CLI surface
    *,
    path: Path,
    send: bool = False,
    never_send: bool = False,
    assume_yes: bool = False,
    sbom_path: Path | None = None,
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
    """Execute collect → write the SBOM → show → (offer to send).

    Order collector-transparent-machen (Ivan, 09.09.2026): the DEFAULT run
    generates, shows and SAVES — it transmits nothing. Sending is an explicit
    decision: --send, or answering the question after the summary. A code is
    no longer required (Ivan, 09.09.): only an e-mail address, so the report
    can reach the customer; --voucher stays optional for partner tracking.
    """
    # Uploading now happens ONLY on an explicit request. --dry-run and
    # --output keep their meaning (inspect / offline hand-off).
    if never_send and send:
        console.print(
            "[red]Error:[/red] --no-send and --send contradict each other."
        )
        sys.exit(1)
    uploading = send and not dry_run and output is None
    if uploading and code and voucher:
        console.print("[red]Error:[/red] use either --code or --voucher, not both.")
        sys.exit(1)
    if uploading and code:
        # Personal one-time token: the server knows the registered address.
        voucher = code
    if uploading and contact_email and "@" not in contact_email:
        console.print("[red]Error:[/red] --email must be a valid address (report delivery).")
        sys.exit(1)
    # --send is a promise to transmit: check its precondition BEFORE scanning,
    # so the customer is not told "error" only after the work is done. With a
    # personal --code the server knows the address, so that path needs none.
    if uploading and not code and "@" not in (contact_email or ""):
        console.print(
            "[red]Error:[/red] --send needs --email (the address your report "
            "is sent to). Example: embtrace-check . --send --email "
            "you@example.com"
        )
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
        # No placeholder (Befund 93a): the field was filled with the literal
        # "DRY-RUN" on EVERY payload — the old comment claimed it was "for
        # dry-run/offline only", but a real --send carried it too. On the
        # server that beat the honest classification, so a paying prospect
        # was filed as CHK-…-DRY-RUN.json and reported as attribution
        # "DRY-RUN" in the support mail that a human forwards by hand.
        # An empty field is the truth: no code was given. The server files
        # it as "no-code".
        voucher=voucher or code or "",
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
            "Send it to check@innomatica.de to receive your report."
        )
        return

    # --- The default: the customer's own result, written locally ----------
    # Generate → show → save. Nothing is transmitted here (order
    # collector-transparent-machen). An existing SBOM is never silently
    # overwritten — an earlier bill is evidence.
    # The bill belongs to the project that was scanned, not to whatever
    # directory the tool was invoked from (`embtrace-check /path/to/proj`
    # must leave the SBOM in /path/to/proj). --sbom overrides explicitly.
    written = write_cyclonedx(
        sbom_path or (path / "sbom.cdx.json"),
        components,
        stats,
        project_name=path.resolve().name,
    )
    console.print(f"[green]Your SBOM is in {written}[/green] (CycloneDX 1.6).")
    if sbom_path is None and written.name != "sbom.cdx.json":
        console.print(
            "[dim]An existing sbom.cdx.json was kept — the new bill went to "
            "the name above.[/dim]"
        )

    if not send and (never_send or not _asks_interactively(assume_yes)):
        # Non-interactive (CI, pipe) and no --send: just the invitation.
        _print_send_invitation(written)
        return

    if not send:
        # Interactive default run: one direct question, default NO.
        console.print(
            "\nSend it to embtrace now for the free CRA readiness report? "
            f"[dim](privacy: {_PRIVACY_URL})[/dim]"
        )
        if not click.confirm("Send now?", default=False):
            _print_send_invitation(written)
            return
        if not contact_email:
            contact_email = click.prompt(
                "E-mail address for the report", default="", show_default=False,
            ).strip()
        if "@" not in contact_email:
            console.print(
                "[yellow]No valid address — nothing was sent.[/yellow]"
            )
            _print_send_invitation(written)
            return
        payload = payload.model_copy(update={"contact_email": contact_email})

    # --- The send path: show what leaves the house, then ask -------------
    if not assume_yes:
        _print_leaving_summary(payload)
        if not click.confirm("Send this to embtrace?", default=True):
            console.print("[yellow]Nothing was sent.[/yellow]")
            _print_send_invitation(written)
            return
    reference = upload_payload(payload, url=url)
    destination = contact_email or "your registered address"
    console.print(
        f"[green]Sent.[/green] Reference: [bold]{reference}[/bold] — "
        f"your CRA readiness report will be sent to {destination} within 24 hours."
    )


if __name__ == "__main__":
    main()
