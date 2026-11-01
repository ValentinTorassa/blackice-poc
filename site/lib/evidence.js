import fs from 'node:fs';
import path from 'node:path';

// Status is read from the repository when the site builds. Nothing here is typed by hand.
const ROOT = path.join(process.cwd(), '..');

function evidenceFiles() {
  try {
    return fs.readdirSync(path.join(ROOT, 'evidence')).filter((f) => /^P\d-\d{2}-.+\.md$/.test(f));
  } catch {
    return [];
  }
}

// A checkpoint counts as recorded only when evidence/ has a file named after it,
// for example evidence/P0-02-real-deny-linux.md.
export function recordedCheckpoints() {
  return new Set(evidenceFiles().map((f) => f.slice(0, 5)));
}

// A checkpoint is recorded with findings when one of its entries says so in its own words, for example
// evidence/P0-06-faults-linux.md: "This is a run, not a pass." Read from the file, not typed here.
const FINDINGS_MARK = /This is a run, not a pass\./;

export function findingsCheckpoints() {
  const out = new Set();
  for (const f of evidenceFiles()) {
    try {
      if (FINDINGS_MARK.test(fs.readFileSync(path.join(ROOT, 'evidence', f), 'utf8'))) out.add(f.slice(0, 5));
    } catch {
      // An unreadable entry keeps its plain Recorded state.
    }
  }
  return out;
}

// The evidence entries of each checkpoint, for links: P0-07 -> its two files, P0-08 -> its one. A link's text
// comes from the file name: the platform when that alone tells a checkpoint's entries apart
// (P0-02-real-deny-macos.md -> "macOS"), otherwise the rest of the name (P0-07-fx-real-model-macos.md ->
// "fx real model, macOS"; P0-08-second-platform.md -> "second platform"). macOS first, then Linux, then the rest.
const PLATFORMS = [['macos', 'macOS'], ['linux', 'Linux']];

export function evidenceEntries() {
  const byId = new Map();
  for (const file of evidenceFiles()) {
    const slug = file.slice(6, -3);
    const at = PLATFORMS.findIndex(([key]) => slug === key || slug.endsWith(`-${key}`));
    const platform = at >= 0 ? PLATFORMS[at][1] : null;
    const rest = (at >= 0 ? slug.slice(0, -PLATFORMS[at][0].length) : slug).replace(/-+$/, '').replace(/-/g, ' ');
    const id = file.slice(0, 5);
    byId.set(id, [...(byId.get(id) || []), { file, platform, rest, rank: at >= 0 ? at : PLATFORMS.length }]);
  }
  for (const list of byId.values()) {
    list.sort((a, b) => a.rank - b.rank || a.file.localeCompare(b.file));
    for (const e of list) {
      const shared = list.filter((o) => o.platform === e.platform).length > 1;
      e.label = e.platform && !shared ? e.platform : [e.rest, e.platform].filter(Boolean).join(', ');
    }
  }
  return byId;
}

// Code counts as built when its path exists and, for a cell with builtWhen, when that file matches it.
function codeBuilt(cell) {
  if (!cell.code) return false;
  const file = path.join(ROOT, cell.code);
  if (!fs.existsSync(file)) return false;
  if (!cell.builtWhen) return true;
  try {
    return cell.builtWhen.test(fs.readFileSync(file, 'utf8'));
  } catch {
    return false;
  }
}

// A platform cell is verified by its evidence file, built when its code is in the repository,
// and otherwise keeps its design state.
export function cellState(cell) {
  if (cell.evidence && evidenceFiles().some((f) => cell.evidence.test(f))) return 'verified';
  if (codeBuilt(cell)) return cell.builtAs || 'built';
  return cell.base;
}
