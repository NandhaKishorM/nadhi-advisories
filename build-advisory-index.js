#!/usr/bin/env node
'use strict';
/**
 * Build the offline advisory index the supply lane matches against.
 *
 * The report has always carried this disclaimer:
 *
 *   "Dependencies are analysed, but not matched against a vulnerability
 *    database … It does NOT tell you whether the versions you use have known
 *    CVEs — that needs an advisory database this run does not carry."
 *
 * For a product sold as a security audit that is the most conspicuous gap in
 * it, and it is also the one check in the whole system that cannot hallucinate:
 * a version either falls inside a published affected range or it does not.
 *
 * OSV publishes per-ecosystem exports. The raw npm zip is 222MB of one JSON
 * file per advisory; almost all of it is prose this never reads. Reduced to
 * package -> affected ranges + id + severity it is a few megabytes, which ships
 * with the app and works air-gapped.
 *
 *   node scripts/build-advisory-index.js npm PyPI
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');
const os = require('os');

const OUT = path.join(__dirname, '..', 'resources', 'advisories');

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const f = fs.createWriteStream(dest);
    https.get(url, (res) => {
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      res.pipe(f);
      f.on('finish', () => f.close(() => resolve(dest)));
    }).on('error', reject);
  });
}

/** Keep only what a version check needs. */
function compact(adv) {
  const out = [];
  for (const a of (adv.affected || [])) {
    const name = a.package && a.package.name;
    if (!name) continue;
    const ranges = [];
    for (const r of (a.ranges || [])) {
      if (r.type !== 'SEMVER' && r.type !== 'ECOSYSTEM') continue;
      let introduced = null;
      for (const ev of (r.events || [])) {
        if (ev.introduced != null) introduced = ev.introduced === '0' ? '0' : ev.introduced;
        else if (ev.fixed != null) { ranges.push([introduced || '0', ev.fixed]); introduced = null; }
        else if (ev.last_affected != null) { ranges.push([introduced || '0', ev.last_affected, 1]); introduced = null; }
      }
      if (introduced !== null) ranges.push([introduced, null]);
    }
    // Explicit version lists, used where a range cannot express it.
    const versions = Array.isArray(a.versions) && a.versions.length <= 60 ? a.versions : null;
    if (!ranges.length && !versions) continue;
    const sev = (adv.database_specific && adv.database_specific.severity)
      || (adv.severity && adv.severity[0] && adv.severity[0].type) || '';
    out.push({
      pkg: name.toLowerCase(),
      id: adv.aliases && adv.aliases.find(x => /^CVE-/.test(x)) || adv.id,
      sev: String(sev).toLowerCase().slice(0, 8),
      sum: String(adv.summary || '').slice(0, 140),
      ranges, versions,
    });
  }
  return out;
}

(async () => {
  const ecos = process.argv.slice(2);
  if (!ecos.length) { console.error('usage: build-advisory-index.js <ecosystem…>  e.g. npm PyPI'); process.exit(2); }
  fs.mkdirSync(OUT, { recursive: true });
  for (const eco of ecos) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'osv-'));
    const zip = path.join(tmp, 'all.zip');
    process.stdout.write(`  ${eco}: downloading… `);
    await download(`https://osv-vulnerabilities.storage.googleapis.com/${eco}/all.zip`, zip);
    process.stdout.write(`unzipping… `);
    execFileSync('unzip', ['-qq', '-o', zip, '-d', tmp]);
    const files = fs.readdirSync(tmp).filter(f => f.endsWith('.json'));
    const index = {};
    let kept = 0;
    for (const f of files) {
      let adv; try { adv = JSON.parse(fs.readFileSync(path.join(tmp, f), 'utf8')); } catch (_) { continue; }
      if (adv.withdrawn) continue;                       // retracted advisories are not findings
      for (const e of compact(adv)) {
        (index[e.pkg] = index[e.pkg] || []).push({ id: e.id, sev: e.sev, sum: e.sum, r: e.ranges, v: e.versions });
        kept++;
      }
    }
    const dest = path.join(OUT, `${eco.toLowerCase()}.json`);
    fs.writeFileSync(dest, JSON.stringify({ ecosystem: eco, built: new Date().toISOString().slice(0, 10), index }));
    const mb = (fs.statSync(dest).size / 1048576).toFixed(1);
    console.log(`${files.length} advisories → ${Object.keys(index).length} packages, ${kept} entries, ${mb}MB`);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
})().catch(e => { console.error('failed:', e.message); process.exit(1); });
