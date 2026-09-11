#!/usr/bin/env node
'use strict';
/**
 * Publish the offline CVE database as a dated GitHub release.
 *
 * This repository exists so that Nadhi Audit can refresh its advisory database
 * without anyone telling us what they are auditing. The application downloads
 * the whole database and matches on the user's own machine; it never sends a
 * package name, a version or a lockfile anywhere. The rule the whole design
 * serves: the database comes to the code, the code never goes to the database.
 *
 * GitHub Releases rather than a cloud bucket, for three reasons. There is no
 * long-lived credential — GITHUB_TOKEN is issued per run and scoped to this
 * repository, so there is no key that could leak and be used to overwrite
 * something more dangerous. Egress is free, and the alternative charges per
 * gigabyte for exactly the traffic we want to grow. And a release is a public,
 * dated, immutable record of what was published and with which hashes, which
 * for a security product is worth more than it costs.
 *
 *   node publish.js              # rebuild from OSV, cut a release
 *   node publish.js --dry-run    # rebuild and hash, publish nothing
 *   node publish.js --skip-build # republish what is already built
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const SRC = path.join(__dirname, 'resources', 'advisories');
const ECOS = ['npm', 'pypi', 'packagist'];
const OSV_NAMES = { npm: 'npm', pypi: 'PyPI', packagist: 'Packagist' };

// An index that has shrunk means a truncated OSV export or a parse that
// failed. Publishing it would REMOVE advisories from everyone who downloads
// it, and their next report would come back clean — the worst failure this
// system can have, because it is silent and it looks like good news.
const FLOOR = { npm: 150000, pypi: 9000, packagist: 900 };

const argv = process.argv.slice(2);
const DRY = argv.includes('--dry-run');
const SKIP_BUILD = argv.includes('--skip-build');

const sh = (cmd, args, opts = {}) => execFileSync(cmd, args, { stdio: 'inherit', ...opts });
const cap = (cmd, args) => execFileSync(cmd, args).toString().trim();
const sha256 = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');

function repoSlug() {
  if (process.env.GITHUB_REPOSITORY) return process.env.GITHUB_REPOSITORY;
  try { return cap('gh', ['repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner']); }
  catch (_) { throw new Error('cannot determine the repository — set GITHUB_REPOSITORY'); }
}

function main() {
  fs.mkdirSync(SRC, { recursive: true });

  if (SKIP_BUILD) {
    console.log('[1/3] skipping the OSV rebuild');
  } else {
    console.log('[1/3] rebuilding indexes from OSV…');
    sh(process.execPath, [path.join(__dirname, 'build-advisory-index.js'), ...ECOS.map(e => OSV_NAMES[e])]);
  }

  const date = new Date().toISOString().slice(0, 10);
  const tag = `v${date}`;
  const slug = repoSlug();
  const base = `https://github.com/${slug}/releases/download/${tag}`;

  const files = {};
  for (const eco of ECOS) {
    const f = path.join(SRC, `${eco}.json`);
    if (!fs.existsSync(f)) throw new Error(`${eco}.json was not produced`);
    const doc = JSON.parse(fs.readFileSync(f, 'utf8'));
    const count = Object.keys(doc.index || {}).length;
    if (count < FLOOR[eco]) {
      console.error(`REFUSING TO PUBLISH: ${eco} has ${count} packages, below the floor of ${FLOOR[eco]}.`);
      console.error('A shrunken index removes advisories from everyone who downloads it.');
      process.exit(1);
    }
    // The URL is pinned to THIS tag, not to /latest/. A client reads the
    // manifest and then fetches the files it names; if those pointed at
    // "latest" a release cut in between would hand it bytes that do not match
    // the hashes it just read, and it would correctly refuse them.
    files[eco] = {
      url: `${base}/${eco}.json`,
      sha256: sha256(f),
      bytes: fs.statSync(f).size,
      packages: count,
      built: doc.built || date,
    };
    console.log(`      ${eco.padEnd(10)} ${String(count).padStart(7)} pkgs  ${(files[eco].bytes / 1048576).toFixed(1)} MB  ${files[eco].sha256.slice(0, 16)}…`);
  }

  const manifest = { date, files, generated: new Date().toISOString(), repo: slug };
  const manifestPath = path.join(SRC, 'latest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');

  if (DRY) {
    console.log('\n[dry-run] nothing published. Manifest that would go out:\n');
    console.log(JSON.stringify(manifest, null, 2));
    return;
  }

  console.log(`[2/3] cutting release ${tag}…`);
  const assets = [...ECOS.map(e => path.join(SRC, `${e}.json`)), manifestPath];
  const notes = [
    `Offline CVE database for Nadhi Audit — ${date}.`,
    '',
    '| ecosystem | packages | size |',
    '|---|---|---|',
    ...ECOS.map(e => `| ${e} | ${files[e].packages} | ${(files[e].bytes / 1048576).toFixed(1)} MB |`),
    '',
    'Compacted from the OSV per-ecosystem exports. Each file is listed in',
    '`latest.json` with its SHA-256; the application verifies every file against',
    'that manifest and installs an update only when all of them match.',
    '',
    'The application downloads these files and matches on the local machine. It',
    'does not send package names, versions or lockfiles anywhere.',
  ].join('\n');

  // A tag is immutable once anyone has downloaded it. Re-running on the same
  // day replaces the assets on that day's release rather than cutting a second
  // one, which keeps one release per date.
  let exists = true;
  try { cap('gh', ['release', 'view', tag]); } catch (_) { exists = false; }
  if (exists) {
    console.log(`      ${tag} exists — replacing its assets`);
    sh('gh', ['release', 'upload', tag, ...assets, '--clobber']);
    sh('gh', ['release', 'edit', tag, '--notes', notes]);
  } else {
    sh('gh', ['release', 'create', tag, ...assets, '--title', `Advisory database ${date}`, '--notes', notes, '--latest']);
  }

  console.log('[3/3] verifying what went live…');
  const live = JSON.parse(cap('curl', ['-fsSL',
    `https://github.com/${slug}/releases/latest/download/latest.json`]));
  if (live.date !== date) throw new Error(`the latest release reports ${live.date}, expected ${date}`);
  for (const eco of ECOS) {
    if (live.files[eco].sha256 !== files[eco].sha256) throw new Error(`hash mismatch for ${eco} in the live manifest`);
  }
  console.log(`\npublished ${tag}. Clients pick it up on their next daily check.`);
}

main();
