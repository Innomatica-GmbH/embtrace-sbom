# embtrace-check has moved to embtrace-sbom

Same tool, new name. Install the new package:

```
pipx install embtrace-sbom
embtrace-sbom .        # writes sbom.cdx.json, sends nothing
```

This package only exists so that printed instructions keep working: it
installs `embtrace-sbom` and provides the `embtrace-check` command, which
prints a one-line notice and runs the same tool. It receives no further
releases. Source and issues: https://github.com/Innomatica-GmbH/embtrace-sbom
