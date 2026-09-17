# Nadhi Audit — offline CVE database

The advisory database [Nadhi Audit](https://convaiinnovations.com) matches dependencies
against, published daily as a dated release.

<!--published-->Last published: **2026-09-17** &middot; [latest release](https://github.com/NandhaKishorM/nadhi-advisories/releases/latest)<!--/published-->

## Why this repository is public and separate

Nadhi Audit is an offline code auditor: it runs on the developer's machine and
the code never leaves it. Keeping that true while still shipping fresh CVE data
means the data has to travel to the machine, not the other way round.

**The application downloads this whole database and matches locally. It never
sends a package name, a version, or a lockfile anywhere.** A hosted scanner asks
`is lodash@4.17.20 vulnerable?` and in doing so learns your entire dependency
tree — your stack, your vendors, your internal package names. This does not.

The files are served unauthenticated, deliberately. Gating them behind a licence
key would put the customer's identity in every request and let us correlate who
fetched what and when. The contents are public OSV data with nothing proprietary
in them, so being unable to learn anything is worth more than the download.

## What is in a release

| file | contents |
|---|---|
| `latest.json` | manifest: date, and for each ecosystem its URL, SHA-256, size and package count |
| `npm.json` | npm advisories, compacted to package → affected ranges |
| `pypi.json` | PyPI, the same |
| `packagist.json` | Packagist, the same |

Compacted from the [OSV](https://osv.dev) per-ecosystem exports — the raw npm
export is 222MB of prose almost none of which a version comparison needs.

## Verifying

Every file is listed in `latest.json` with its SHA-256, and the application
installs an update only when **all** files match. The tampering that matters here
is removal: a bundle with advisories stripped out produces false negatives, and
a report built on it reads as clean. That is why a partial set is never applied.

```bash
curl -fsSL https://github.com/NandhaKishorM/nadhi-advisories/releases/latest/download/latest.json
```

## Air-gapped sites

Download a release on a connected machine, carry the four files across, and use
**Settings → CVE database → Import bundle**. The import checks the same hashes
as the network path.

## Rebuilding it yourself

```bash
node publish.js --dry-run     # rebuild from OSV and print the manifest
```

The publisher refuses to release an index that has shrunk below a floor, and
the workflow re-checks the live manifest afterwards from outside the script that
wrote it.
