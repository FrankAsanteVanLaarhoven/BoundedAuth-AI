# Third-party notices

This file records the third-party code BoundedAuth depends on and the licences
under which it is used. The authoritative licence text for each dependency lives
in that dependency's own repository; the summaries below are for orientation, not
a substitute for it.

## Core module — zero third-party dependencies

`github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI` (the root package) imports
**only the Go standard library**. Embedding the verifier pulls in no third-party
code. This is a deliberate property, checked by `go.mod` having no `require`
block, and it is why the PostgreSQL store is a separate module.

## `postgres/` and `bench/` modules

These modules use a database driver and therefore carry dependencies:

| Dependency | Version | Licence |
| --- | --- | --- |
| `github.com/jackc/pgx/v5` | v5.7.2 | MIT |
| `github.com/jackc/pgpassfile` | v1.0.0 | MIT |
| `github.com/jackc/pgservicefile` | (pinned) | MIT |
| `github.com/jackc/puddle/v2` | v2.2.2 | MIT |
| `golang.org/x/crypto` | v0.31.0 | BSD-3-Clause |
| `golang.org/x/sync` | v0.10.0 | BSD-3-Clause |
| `golang.org/x/text` | v0.21.0 | BSD-3-Clause |

All of the above are permissive licences (MIT, BSD-3-Clause) compatible with
this project's Apache-2.0 distribution.

## Verifying this list

The tables above are maintained by hand and can drift. Before a release, the
authoritative, machine-generated inventory should be produced with a tool and
committed alongside the tag, for example:

```bash
go install github.com/google/go-licenses@latest
go-licenses report ./... > sbom-core.txt
cd postgres && go-licenses report ./... > ../sbom-postgres.txt
```

Treat a discrepancy between this file and the tool output as the file being
wrong, not the tool.
