---
name: exasol-virtual-schemas
description: Query an external database (PostgreSQL, MySQL, SQL Server, Oracle, another Exasol) from the local Exasol database without loading it, through a virtual schema the starter kit sets up with `exakit connect` — covering the unattended connect (env vars, password file, consent for the one restart), the source lifecycle (`exakit source list|show|check|reauth|refresh|remove`), why names need double quotes, the TLS and host-name limits of Exasol Personal, and the fact that every virtual schema is visible to AI clients over MCP. Triggers — "connect my Postgres to Exasol", "connect MySQL", "connect SQL Server", "connect Oracle", "query an external database", "virtual schema", "exakit connect", "join PostgreSQL data with Exasol", "federated query", "remote database in Exasol", "source check failed", "reauth a connection", "remove a connected source".
---

# Virtual Schemas — query another database from Exasol

Virtual schemas are **part of the kit** - there is nothing to install. They
make the tables of an external database appear in the local Exasol as
`VS_<NAME>`: every query reads the source **live**, nothing is copied.
Supported: **PostgreSQL, MySQL, SQL Server, Oracle** and **Exasol** (another
Exasol, or a schema of this one). **Snowflake** is not available yet (see below).

| Source | `exakit connect <type>` | TLS on Exasol Personal |
|---|---|---|
| PostgreSQL | `postgresql` (`pg`) | encrypted, certificate not verified |
| MySQL | `mysql` | encrypted, not verified; driver is GPL, fetched onto this machine only |
| SQL Server | `sqlserver` (`mssql`) | encrypted, not verified (`trustServerCertificate=true`) |
| Oracle | `oracle` | Oracle Native Network Encryption (TCPS not possible yet) |
| Exasol | `exasol` | **verified** - the certificate is pinned by fingerprint |
| Snowflake | `snowflake` | not available: its driver must verify certificates, which the import side cannot yet |

`exakit connect` does the whole setup — adapter and JDBC driver downloaded and
checksum-verified, staged where the database reads them, the database's Java
runtime installed (one restart, consented), the CONNECTION, adapter script and
virtual schema created — and calls the source ready only after rows came back.

## Connect a source

Interactively, just run it: it asks for the source type, a pasted JDBC URL (or
host/port/database), the user and the password (hidden).

```bash
exakit connect
```

Unattended — **this is the form an agent uses**. Never put a password on a
command line; there is deliberately no `--password` option. Write it to a file
the user controls, or ask the user to run the command themselves:

```bash
exakit connect postgresql --name sales \
  --url jdbc:postgresql://db.example.com:5432/shop --user reader --schema public \
  --password-file ~/pg.pw --json
```

| Variable | Meaning |
|---|---|
| `EXAKIT_VS_SOURCE` / `EXAKIT_VS_NAME` | source type (`postgresql`, alias `pg`) / name → `VS_<NAME>` |
| `EXAKIT_VS_JDBC_URL` | the connection; a password inside it is **removed and not used** |
| `EXAKIT_VS_HOST`, `_PORT`, `_DATABASE`, `_USER`, `_SCHEMA` | the connection as fields |
| `EXAKIT_VS_PASSWORD_FILE` | the password file (UTF-8 or UTF-16) |
| `EXAKIT_VS_TLS` | `encrypt` (default) or `none` (local / private-network hosts only) |

**The first connect may need one database restart** (to activate the Java
runtime). Without `--yes` (or `EXAKIT_CONFIRM_RUNTIME_UPDATE=1`) and with no
terminal it exits **5** and changes nothing. That restart stops the database for
about 30 s (minutes the very first time, while it downloads) — **ask the user
before passing `--yes`**. Later connects need no restart.

Preview without changing anything: add `--dry-run`.

## Query it

```sql
SELECT * FROM VS_SALES."orders" LIMIT 10;
```

Names keep the **source's spelling**, so they go in **double quotes** — `VS_SALES.ORDERS`
is not found when the table is `orders`. Discover them from the system tables:

```sql
SELECT TABLE_NAME FROM SYS.EXA_ALL_TABLES WHERE TABLE_SCHEMA = 'VS_SALES';
```

In PowerShell, `exakit sql` loses inner double quotes: escape them as `\"` or
use `exakit sql --file <file.sql>`.

Type notes (PostgreSQL): `NUMERIC` arrives as `VARCHAR` (it can exceed Exasol's
DECIMAL range), `TIMESTAMPTZ` as `TIMESTAMP`, JSON/UUID/INTERVAL as `VARCHAR`;
array columns are left out, `BYTEA` reads as the text `bytea NOT SUPPORTED`.
`CAST` before aggregating.

## The lifecycle

```bash
exakit source list                 # every source, TLS level, last check
exakit source show sales
exakit source check sales          # repair what a restart can undo, then prove it reads
exakit source refresh sales        # re-read the source's tables and columns
exakit source reauth sales --password-file ~/pg.pw   # old credentials stay until new ones work
exakit source remove sales --dry-run                 # then --yes
```

All take `--json`: one object on stdout with `ok`, `status`, `kind`, and a
runnable `remedy` (or `null`) plus `remedy_hint`. Branch on `kind`:

| `kind` | Meaning | Do |
|---|---|---|
| `auth` | user or password refused | `remedy` (reauth, or connect again after a failed first connect) |
| `network` | the database cannot reach host:port | read `remedy_hint`: the connection starts **inside** the database container |
| `unresolvable` / `dns` | the name does not resolve / the Java runtime cannot resolve it | fix the name, or `exakit source check <name>` |
| `schema_missing` / `permission` | the source schema is missing / not readable | fix on the source side, then `exakit source check` |
| `tls` | encrypted connection failed | only if the source has no TLS: `--tls none` (private hosts) |
| `consent` | the restart was not confirmed (exit 5) | ask the user, then `remedy` |
| `password_needed` | a re-run changed host/port/TLS without a password | pass `--password-file` |
| `busy` | another connect/source command runs | wait, retry |

## What to tell the user

- **AI clients see it.** The MCP read-only user can read every schema, so a new
  `VS_*` is visible to every connected AI client at once. Say so.
- **TLS is encrypted but not verified** — Exasol Personal has no trust store for
  it yet. Fine on a trusted network; say so for a cloud database.
- **Host names** need a workaround the kit applies after every database start
  (Exasol Personal's Java runtime ships without name resolution). If a source
  given by name fails after a reboot, `exakit source check <name>` repairs it.
  `EXAKIT_VS_DNS_WORKAROUND=0` makes the kit use IP addresses instead.
- **`localhost` inside the database is the database itself.** A source on the
  user's own computer is reached through the container's host address — the kit
  works that out; the source must listen on a published port.
- **The password lives only in the database's CONNECTION.** The admin user
  (`exakit sql`, `exapump`) could read it back through a script — recommend a
  read-only account on the source.

## Never

- Never put the source password on a command line, in a log, or in your output.
- Never drop `VS_*`, `EXAKIT_SRC_*` or anything in `EXAKIT_VS` by hand —
  `exakit source remove` drops only what the kit made and keeps what others use.
- Never run `--yes` for the first connect without the user's agreement: it
  restarts their database.
