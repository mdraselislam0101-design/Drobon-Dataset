#!/usr/bin/env node
/**
 * sca-engine.mjs — original, offline SCA matching logic for the synthetic
 * fixture population.
 *
 * Contract (mirrors the Main App provider seam):
 *
 *   provider.assess(coordinate) -> {
 *     providerId: string,
 *     datasetStatus: 'NO_DATA_LOADED' | 'NOT_ASSESSED' | 'ASSESSED',
 *     advisories: AdvisoryRef[],
 *   }
 *
 * Fail-closed rules, all enforced here rather than in callers:
 *   - a record that is not a Drobon synthetic fixture is refused outright
 *     (the production data lock: real feeds stay blocked);
 *   - an unknown ecosystem, malformed name/version, or range the local
 *     evaluator cannot prove makes the answer NOT_ASSESSED, never a guessed
 *     match and never an empty-but-confident "no advisories";
 *   - an empty record set reports NO_DATA_LOADED, never ASSESSED;
 *   - output is deterministic (severity rank, then advisory id) and the
 *     provider never mutates its inputs.
 *
 * This module performs no network, no filesystem reads of live feeds and no
 * model calls. Severity is the record's declared label — no CVSS arithmetic,
 * no exploitability claim, no EPSS/KEV enrichment.
 */
import { satisfiesRange, validateRange } from './range.mjs';

export const SCA_ECOSYSTEMS = Object.freeze(['npm', 'pypi']);
export const SCA_DATASET_STATUS = Object.freeze({
  NO_DATA_LOADED: 'NO_DATA_LOADED',
  NOT_ASSESSED: 'NOT_ASSESSED',
  ASSESSED: 'ASSESSED',
});
export const SCA_SEVERITIES = Object.freeze(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export const SYNTHETIC_SCHEMA = 'drobon.sca.synthetic-advisory/v1';

const SYNTHETIC_ID = /^DROBON-SAMPLE-\d{3}$/;
const PACKAGE_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const VERSION = /^[0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.-]+)?$/;
const SEVERITY_RANK = new Map(SCA_SEVERITIES.map((severity, index) => [severity, index]));

export class ScaContractError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'ScaContractError';
    this.code = code;
  }
}

/** Validate one coordinate. Returns a frozen copy; throws ScaContractError. */
export function normalizeCoordinate(input) {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new ScaContractError('INVALID_COORDINATE', 'coordinate must be an object');
  }
  const { ecosystem, name, version } = input;
  if (!SCA_ECOSYSTEMS.includes(ecosystem)) {
    throw new ScaContractError('INVALID_COORDINATE', `unknown ecosystem ${JSON.stringify(ecosystem)}`);
  }
  if (typeof name !== 'string' || !PACKAGE_NAME.test(name)) {
    throw new ScaContractError('INVALID_COORDINATE', `package name ${JSON.stringify(name)} is not a bounded lowercase name`);
  }
  if (typeof version !== 'string' || !VERSION.test(version)) {
    throw new ScaContractError('INVALID_COORDINATE', `version ${JSON.stringify(version)} is not a plain release version`);
  }
  return Object.freeze({ ecosystem, name, version });
}

/**
 * Validate one synthetic advisory record. Returns an array of reasons (empty
 * means valid). Total: never throws.
 */
export function validateSyntheticRecord(record) {
  const reasons = [];
  if (typeof record !== 'object' || record === null || Array.isArray(record)) {
    return ['record must be an object'];
  }
  if (record.schemaVersion !== SYNTHETIC_SCHEMA) {
    reasons.push(`schemaVersion must be ${SYNTHETIC_SCHEMA}`);
  }
  if (record.fixture !== true) {
    reasons.push('REAL_RECORD_REFUSED: fixture must be true (production data lock)');
  }
  if (typeof record.id !== 'string' || !SYNTHETIC_ID.test(record.id)) {
    reasons.push('id must match DROBON-SAMPLE-NNN (no third-party advisory ids in synthetic mode)');
  }
  if (!SCA_ECOSYSTEMS.includes(record.ecosystem)) {
    reasons.push(`ecosystem must be one of ${SCA_ECOSYSTEMS.join(', ')}`);
  }
  if (typeof record.package !== 'string' || !PACKAGE_NAME.test(record.package)) {
    reasons.push('package must be a bounded lowercase name');
  }
  if (!SCA_SEVERITIES.includes(record.severity)) {
    reasons.push(`severity must be one of ${SCA_SEVERITIES.join(', ')}`);
  }
  if (record.provenance?.source !== 'fixture') {
    reasons.push('provenance.source must be "fixture"');
  }
  if (!Array.isArray(record.affected) || record.affected.length === 0) {
    reasons.push('affected must be a non-empty array');
  } else {
    for (const [index, affected] of record.affected.entries()) {
      if (typeof affected !== 'object' || affected === null || Array.isArray(affected)) {
        reasons.push(`affected[${index}] must be an object`);
        continue;
      }
      const invalid = validateRange(record.ecosystem, affected.range);
      if (invalid !== null) {
        reasons.push(`affected[${index}].range: ${invalid}`);
      }
      if (affected.fixed !== undefined && (typeof affected.fixed !== 'string' || !VERSION.test(affected.fixed))) {
        reasons.push(`affected[${index}].fixed must be a plain release version`);
      }
    }
  }
  return reasons;
}

function freezeRecord(record) {
  return Object.freeze({
    id: record.id,
    ecosystem: record.ecosystem,
    package: record.package,
    severity: record.severity,
    affected: Object.freeze(record.affected.map((affected) => Object.freeze({
      range: affected.range,
      ...(affected.fixed === undefined ? {} : { fixed: affected.fixed }),
    }))),
  });
}

/**
 * Build a provider over synthetic records. Any non-synthetic record throws:
 * the provider cannot be constructed in a state that could serve real data.
 */
export function createSyntheticProvider(records) {
  if (!Array.isArray(records)) {
    throw new ScaContractError('INVALID_RECORD', 'records must be an array');
  }
  const failures = [];
  const frozen = [];
  for (const [index, record] of records.entries()) {
    const reasons = validateSyntheticRecord(record);
    if (reasons.length > 0) {
      failures.push(`record[${index}]: ${reasons.join('; ')}`);
      continue;
    }
    frozen.push(freezeRecord(record));
  }
  if (failures.length > 0) {
    throw new ScaContractError('INVALID_RECORD', failures.join(' | '));
  }
  const datasetStatus = frozen.length === 0
    ? SCA_DATASET_STATUS.NO_DATA_LOADED
    : SCA_DATASET_STATUS.ASSESSED;
  const provider = {
    providerId: 'drobon-sca-synthetic/v1',
    datasetStatus,
    recordCount: frozen.length,
    assess(coordinateInput) {
      return assessWithProvider(provider, frozen, coordinateInput);
    },
  };
  return Object.freeze(provider);
}

function assessWithProvider(provider, records, coordinateInput) {
  const coordinate = normalizeCoordinate(coordinateInput);
  const base = { providerId: provider.providerId };
  if (records.length === 0) {
    return Object.freeze({ ...base, datasetStatus: SCA_DATASET_STATUS.NO_DATA_LOADED, advisories: Object.freeze([]) });
  }
  const candidates = records.filter(
    (record) => record.ecosystem === coordinate.ecosystem && record.package === coordinate.name,
  );
  if (candidates.length === 0) {
    return Object.freeze({ ...base, datasetStatus: SCA_DATASET_STATUS.ASSESSED, advisories: Object.freeze([]) });
  }
  const matched = new Map();
  for (const record of candidates) {
    for (const affected of record.affected) {
      let hit;
      try {
        hit = satisfiesRange(record.ecosystem, coordinate.version, affected.range);
      } catch {
        // The local evaluator cannot prove this range against this version:
        // fail closed for the whole coordinate instead of answering partially.
        return Object.freeze({ ...base, datasetStatus: SCA_DATASET_STATUS.NOT_ASSESSED, advisories: Object.freeze([]) });
      }
      if (hit && !matched.has(record.id)) {
        matched.set(record.id, Object.freeze({
          id: record.id,
          ecosystem: record.ecosystem,
          package: record.package,
          severity: record.severity,
          range: affected.range,
          ...(affected.fixed === undefined ? {} : { fixed: affected.fixed }),
        }));
      }
    }
  }
  const advisories = [...matched.values()].sort((a, b) => {
    const rank = (SEVERITY_RANK.get(b.severity) ?? -1) - (SEVERITY_RANK.get(a.severity) ?? -1);
    if (rank !== 0) return rank;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
  return Object.freeze({
    ...base,
    datasetStatus: SCA_DATASET_STATUS.ASSESSED,
    advisories: Object.freeze(advisories),
  });
}

/** Deterministic severity order for display; no score is invented. */
export function severityRank(severity) {
  return SEVERITY_RANK.has(severity) ? SEVERITY_RANK.get(severity) : -1;
}

// ---------------------------------------------------------------------------
// SCA fixture-corpus contracts (2026-10-19, 1000x pump batch 3).
//
// These three functions back the offline fixture corpus under data/sca-fixtures.
// They are pure, deterministic and network-free, and they fail closed: an input
// the contract cannot prove is returned as an explicit reason, never coerced.
// ---------------------------------------------------------------------------

const CANONICAL_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const PYPI_SEPARATORS = /[-_.]+/g;

/**
 * Canonicalise a package name for one ecosystem.
 *
 * npm: names are already lowercase; scoped names (`@scope/pkg`) are REFUSED
 * with SCOPED_NAME_UNSUPPORTED rather than silently stripped, because the
 * record schema is bounded to unscoped names and a mangle would change identity.
 *
 * pypi: PEP 503 style normalisation — lowercase and collapse runs of -, _, .
 * into a single hyphen.
 */
export function canonicalPackageName(ecosystem, raw) {
  if (!SCA_ECOSYSTEMS.includes(ecosystem)) {
    return Object.freeze({ ok: false, code: 'UNKNOWN_ECOSYSTEM', reason: `unknown ecosystem ${JSON.stringify(ecosystem)}` });
  }
  if (typeof raw !== 'string' || raw.trim() === '') {
    return Object.freeze({ ok: false, code: 'EMPTY_NAME', reason: 'package name must be a non-empty string' });
  }
  const trimmed = raw.trim();
  if (trimmed.startsWith('@') || trimmed.includes('/')) {
    return Object.freeze({ ok: false, code: 'SCOPED_NAME_UNSUPPORTED', reason: `scoped name ${JSON.stringify(trimmed)} is outside the bounded record schema` });
  }
  const name = ecosystem === 'pypi'
    ? trimmed.toLowerCase().replace(PYPI_SEPARATORS, '-')
    : trimmed.toLowerCase();
  if (!CANONICAL_NAME.test(name)) {
    return Object.freeze({ ok: false, code: 'INVALID_NAME', reason: `name ${JSON.stringify(raw)} does not canonicalise to a bounded package name` });
  }
  return Object.freeze({ ok: true, ecosystem, name });
}

/**
 * Resolve an alias to its canonical name using a fixture alias table.
 * The table is synthetic contract data, not an authoritative rename map.
 * A malformed table entry is ignored (never guessed), and the resolution is
 * reported so callers can record which identity was used.
 */
export function resolveAlias(aliasTable, ecosystem, raw) {
  const canonical = canonicalPackageName(ecosystem, raw);
  if (canonical.ok !== true) {
    return Object.freeze({ ok: false, code: canonical.code, reason: canonical.reason });
  }
  if (!Array.isArray(aliasTable)) {
    return Object.freeze({ ok: false, code: 'INVALID_ALIAS_TABLE', reason: 'alias table must be an array' });
  }
  const targets = new Set();
  for (const entry of aliasTable) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
    if (entry.ecosystem !== ecosystem || typeof entry.canonical !== 'string' || !Array.isArray(entry.aliases)) continue;
    const aliases = entry.aliases.filter((alias) => typeof alias === 'string')
      .map((alias) => canonicalPackageName(ecosystem, alias))
      .filter((alias) => alias.ok === true)
      .map((alias) => alias.name);
    if (!aliases.includes(canonical.name)) continue;
    const target = canonicalPackageName(ecosystem, entry.canonical);
    if (target.ok !== true) continue;
    targets.add(target.name);
  }
  // Two table entries claiming the same alias for different canonicals is a
  // contract defect, not a decision the resolver may make by table order.
  if (targets.size > 1) {
    return Object.freeze({
      ok: false,
      code: 'AMBIGUOUS_ALIAS',
      reason: `alias ${JSON.stringify(canonical.name)} resolves to ${[...targets].sort().join(', ')}`,
    });
  }
  if (targets.size === 1) {
    const [name] = targets;
    return Object.freeze({ ok: true, ecosystem, name, resolvedFrom: canonical.name, via: 'alias' });
  }
  return Object.freeze({ ok: true, ecosystem, name: canonical.name, resolvedFrom: canonical.name, via: 'identity' });
}

/**
 * Resolve a dependency listing into a deterministic graph description.
 *
 * Every entry is validated; invalid entries are reported, never dropped
 * silently. Identical coordinates are de-duplicated, conflicting versions of
 * one package are reported as conflicts, and a resolved version that does not
 * satisfy its parent's declared range is reported as a range issue. The output
 * is sorted so two runs over the same input are byte-identical.
 */
export function resolveDependencyGraph(entries) {
  if (!Array.isArray(entries)) {
    throw new ScaContractError('INVALID_GRAPH', 'entries must be an array');
  }
  const nodes = new Map();
  const invalid = [];
  const duplicates = [];
  const conflicts = new Map();
  const rangeIssues = [];
  const seen = new Set();
  // A coordinate declared by several entries is direct when ANY entry says so.
  // The flag is collected before de-duplication so the resolved classification
  // cannot depend on the order in which the listing happens to arrive.
  const directDeclared = new Set();
  for (const [index, entry] of entries.entries()) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      invalid.push(`entry[${index}]: not an object`);
      continue;
    }
    const canonical = canonicalPackageName(entry.ecosystem, entry.name);
    if (canonical.ok !== true) {
      invalid.push(`entry[${index}]: ${canonical.reason}`);
      continue;
    }
    if (typeof entry.version !== 'string' || !VERSION.test(entry.version)) {
      invalid.push(`entry[${index}]: version ${JSON.stringify(entry.version)} is not a plain release version`);
      continue;
    }
    const key = `${canonical.ecosystem}:${canonical.name}@${entry.version}`;
    if (entry.direct === true) directDeclared.add(key);
    if (seen.has(key)) {
      duplicates.push(key);
      continue;
    }
    seen.add(key);
    const packageKey = `${canonical.ecosystem}:${canonical.name}`;
    if (!conflicts.has(packageKey)) conflicts.set(packageKey, new Set());
    conflicts.get(packageKey).add(entry.version);
    const requires = Array.isArray(entry.requires) ? entry.requires : [];
    const edges = [];
    const edgeKeys = new Set();
    for (const [reqIndex, req] of requires.entries()) {
      if (typeof req !== 'object' || req === null || Array.isArray(req)) {
        invalid.push(`entry[${index}].requires[${reqIndex}]: not an object`);
        continue;
      }
      const target = canonicalPackageName(req.ecosystem ?? canonical.ecosystem, req.name);
      if (target.ok !== true) {
        invalid.push(`entry[${index}].requires[${reqIndex}]: ${target.reason}`);
        continue;
      }
      const rangeError = validateRange(target.ecosystem, req.range);
      if (rangeError !== null) {
        invalid.push(`entry[${index}].requires[${reqIndex}]: ${rangeError}`);
        continue;
      }
      const edgeKey = `${target.ecosystem}:${target.name}::${req.range}`;
      if (edgeKeys.has(edgeKey)) continue; // duplicate graph edge: same target and range
      edgeKeys.add(edgeKey);
      edges.push(Object.freeze({ ecosystem: target.ecosystem, name: target.name, range: req.range }));
    }
    nodes.set(key, Object.freeze({
      id: key,
      ecosystem: canonical.ecosystem,
      name: canonical.name,
      version: entry.version,
      direct: directDeclared.has(key),
      requires: Object.freeze(edges.sort((a, b) => (`${a.ecosystem}:${a.name}` < `${b.ecosystem}:${b.name}` ? -1 : 1))),
    }));
  }
  // Apply the collected direct flags after the whole listing is read, so a
  // duplicate that arrives later cannot be outvoted by the first occurrence.
  for (const [key, node] of [...nodes.entries()]) {
    if (directDeclared.has(key) && node.direct !== true) {
      nodes.set(key, Object.freeze({ ...node, direct: true }));
    }
  }
  const resolved = [...nodes.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  // Reachability from the direct set, by package identity (ecosystem:name).
  const byPackage = new Map();
  for (const node of resolved) {
    const packageKey = `${node.ecosystem}:${node.name}`;
    if (!byPackage.has(packageKey)) byPackage.set(packageKey, []);
    byPackage.get(packageKey).push(node);
  }
  const reached = new Set();
  const queue = resolved.filter((node) => node.direct).map((node) => node.id);
  for (const id of queue) reached.add(id);
  while (queue.length > 0) {
    const id = queue.shift();
    const node = nodes.get(id);
    if (node === undefined) continue;
    for (const edge of node.requires) {
      const packageKey = `${edge.ecosystem}:${edge.name}`;
      const targets = byPackage.get(packageKey) ?? [];
      for (const target of targets) {
        if (reached.has(target.id)) continue;
        reached.add(target.id);
        queue.push(target.id);
      }
      if (targets.length === 0) {
        rangeIssues.push(Object.freeze({ from: id, missing: packageKey, range: edge.range, reason: 'UNRESOLVED_DEPENDENCY' }));
        continue;
      }
      for (const target of targets) {
        let ok;
        try {
          ok = satisfiesRange(target.ecosystem, target.version, edge.range);
        } catch {
          rangeIssues.push(Object.freeze({ from: id, missing: target.id, range: edge.range, reason: 'UNEVALUABLE_RANGE' }));
          continue;
        }
        if (!ok) {
          rangeIssues.push(Object.freeze({ from: id, missing: target.id, range: edge.range, reason: 'RANGE_MISMATCH' }));
        }
      }
    }
  }
  // Cycle detection over package identities (ecosystem:name), independent of the
  // concrete versions. Tarjan SCC is run over the package-level adjacency built
  // from every resolved node's edges; deterministic order comes from sorted keys.
  const adjacency = new Map();
  for (const node of resolved) {
    const from = `${node.ecosystem}:${node.name}`;
    if (!adjacency.has(from)) adjacency.set(from, new Set());
    for (const edge of node.requires) {
      const to = `${edge.ecosystem}:${edge.name}`;
      if (!adjacency.has(to)) adjacency.set(to, new Set());
      adjacency.get(from).add(to);
    }
  }
  const packageKeys = [...adjacency.keys()].sort();
  let tarjanIndex = 0;
  const indexOf = new Map();
  const lowLink = new Map();
  const onStack = new Set();
  const sccStack = [];
  const components = [];
  for (const root of packageKeys) {
    if (indexOf.has(root)) continue;
    indexOf.set(root, tarjanIndex);
    lowLink.set(root, tarjanIndex);
    tarjanIndex += 1;
    sccStack.push(root);
    onStack.add(root);
    const work = [{ node: root, next: 0, targets: [...adjacency.get(root)].sort() }];
    while (work.length > 0) {
      const frame = work[work.length - 1];
      if (frame.next < frame.targets.length) {
        const target = frame.targets[frame.next];
        frame.next += 1;
        if (!indexOf.has(target)) {
          indexOf.set(target, tarjanIndex);
          lowLink.set(target, tarjanIndex);
          tarjanIndex += 1;
          sccStack.push(target);
          onStack.add(target);
          work.push({ node: target, next: 0, targets: [...adjacency.get(target)].sort() });
        } else if (onStack.has(target) && indexOf.get(target) < lowLink.get(frame.node)) {
          lowLink.set(frame.node, indexOf.get(target));
        }
        continue;
      }
      work.pop();
      if (work.length > 0) {
        const parent = work[work.length - 1].node;
        if (lowLink.get(frame.node) < lowLink.get(parent)) lowLink.set(parent, lowLink.get(frame.node));
      }
      if (lowLink.get(frame.node) === indexOf.get(frame.node)) {
        const members = [];
        for (;;) {
          const member = sccStack.pop();
          onStack.delete(member);
          members.push(member);
          if (member === frame.node) break;
        }
        components.push(members.sort());
      }
    }
  }
  const cyclesOut = components
    .filter((members) => members.length > 1 || adjacency.get(members[0])?.has(members[0]) === true)
    .map((members) => Object.freeze({ members: Object.freeze(members), reason: 'DEPENDENCY_CYCLE' }))
    .sort((a, b) => (a.members.join('|') < b.members.join('|') ? -1 : 1));
  const conflictsOut = [...conflicts.entries()]
    .filter(([, versions]) => versions.size > 1)
    .map(([packageKey, versions]) => Object.freeze({ package: packageKey, versions: Object.freeze([...versions].sort()) }))
    .sort((a, b) => (a.package < b.package ? -1 : 1));
  return Object.freeze({
    nodes: Object.freeze(resolved),
    direct: Object.freeze(resolved.filter((node) => node.direct).map((node) => node.id)),
    transitive: Object.freeze(resolved.filter((node) => !node.direct && reached.has(node.id)).map((node) => node.id)),
    unreachable: Object.freeze(resolved.filter((node) => !node.direct && !reached.has(node.id)).map((node) => node.id)),
    duplicates: Object.freeze([...duplicates].sort()),
    conflicts: Object.freeze(conflictsOut),
    rangeIssues: Object.freeze(rangeIssues.sort((a, b) => (`${a.from}|${a.missing}` < `${b.from}|${b.missing}` ? -1 : 1))),
    invalid: Object.freeze([...invalid].sort()),
    cycles: Object.freeze(cyclesOut),
  });
}
