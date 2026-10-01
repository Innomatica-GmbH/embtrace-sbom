# embtrace-check is now jochwacht-sbom

Same tool, new name. Install the new package:

```
pipx install jochwacht-sbom
jochwacht-sbom .        # writes sbom.cdx.json, sends nothing
```

This package only exists so that printed instructions keep working: it
installs `jochwacht-sbom` and provides the `embtrace-check` command, which
prints a one-line notice and runs the same tool. It receives no further
releases. Source and issues:
https://github.com/Innomatica-GmbH/jochwacht-sbom

Why the name changed: `embtrace` collided with a registered trademark. The
tool, its licence (GPL-3.0-or-later) and its behaviour are unchanged.
