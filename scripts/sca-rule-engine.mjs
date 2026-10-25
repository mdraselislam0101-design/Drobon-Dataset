#!/usr/bin/env node
/**
 * sca-rule-engine.mjs — evaluator for `drobon.pack.sca/v1` rules.
 *
 * Scope, stated plainly: an SCA rule in this dataset classifies a *dependency
 * declaration* that a manifest, lockfile or registry-configuration file makes.
 * It never decides whether a concrete package version is affected by a
 * published advisory, and it never looks one up. The advisory tier stays a
 * separate concern (data/sca-fixtures, vuln-intel), so nothing here overlaps
 * `scripts/range.mjs`.
 *
 * The engine is deliberately small: one path resolver plus a closed vocabulary
 * of five predicates. Every rule file carries its own regex or string literal,
 * which is where the rule's knowledge lives; the evaluator only applies it.
 *
 * Input contract: `{ file, document }` where `document` is the already-parsed
 * artifact (JSON manifest, parsed TOML/YAML, parsed requirements list). The
 * dataset states the parse in the rule's `artifact`/`parser` fields; the
 * consumer owns the parser. Parse failures are the consumer's to report, never
 * silently treated as "no match" here.
 */

/** Closed vocabulary. A rule using anything else fails validation. */
export const SCA_CHECK_TYPES = Object.freeze([
  'sca-field-matches',
  'sca-field-not-matches',
  'sca-field-absent',
  'sca-key-matches',
  'sca-name-distance',
]);

/** Predicates that take a regular expression. */
export const SCA_PATTERN_TYPES = Object.freeze(['sca-field-matches', 'sca-field-not-matches', 'sca-key-matches']);

/** Ecosystems a rule may name. One ecosystem per rule, by design. */
export const SCA_ECOSYSTEMS = Object.freeze([
  'npm',
  'pypi',
  'go',
  'maven',
  'gradle',
  'nuget',
  'cargo',
  'composer',
  'rubygems',
  'hex',
  'cocoapods',
  'swift',
  'pub',
  'cran',
  'conda',
  'vcpkg',
  'conan',
]);

/** Parse kinds the rule may declare. The engine consumes parsed documents. */
export const SCA_PARSERS = Object.freeze([
  'json',
  'toml',
  'yaml',
  'requirements',
  'xml',
  'gradle',
  'properties',
  'ini',
  'lockfile-text',
]);

export class ScaRuleError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScaRuleError';
  }
}

/**
 * Resolve a dotted path against a parsed document.
 *
 * Grammar: `a.b` (object member), `a.*` (every object member), `a[]` (every
 * array element). Segments combine, e.g. `packages[].dependencies.*` or
 * `requirements[].hashes[]`. The empty path is the document itself.
 *
 * Returns `{ path, value, key }` nodes for every value the path reaches. A
 * missing member simply yields no node; callers that need "absent" semantics
 * use that empty result, never an exception.
 */
export function resolvePath(document, path) {
  if (typeof path !== 'string') throw new ScaRuleError('path: must be a string');
  const segments = path === '' ? [''] : path.split('.');
  let nodes = [{ path: '', value: document, key: null }];
  for (const segment of segments) {
    if (nodes.length === 0) return nodes;
    const arrayWildcard = segment.endsWith('[]');
    const name = arrayWildcard ? segment.slice(0, -2) : segment;
    const next = [];
    for (const node of nodes) {
      let value = node.value;
      let nodePath = node.path;
      let key = node.key;
      if (name === '*') {
        if (value === null || typeof value !== 'object' || Array.isArray(value)) continue;
        for (const [childKey, childValue] of Object.entries(value)) {
          next.push({
            path: nodePath === '' ? childKey : `${nodePath}.${childKey}`,
            value: childValue,
            key: childKey,
          });
        }
        continue;
      }
      if (name !== '') {
        if (value === null || typeof value !== 'object' || Array.isArray(value)) continue;
        if (!Object.prototype.hasOwnProperty.call(value, name)) continue;
        value = value[name];
        nodePath = nodePath === '' ? name : `${nodePath}.${name}`;
        key = name;
      }
      if (arrayWildcard) {
        if (!Array.isArray(value)) continue;
        value.forEach((item, index) => {
          next.push({ path: `${nodePath}[${index}]`, value: item, key: index });
        });
        continue;
      }
      next.push({ path: nodePath, value, key });
    }
    nodes = next;
  }
  return nodes;
}

/** Every own key of every object the path reaches. */
export function keysAtPath(document, path) {
  const keys = [];
  for (const node of resolvePath(document, path)) {
    if (node.value === null || typeof node.value !== 'object' || Array.isArray(node.value)) continue;
    for (const key of Object.keys(node.value)) keys.push({ path: node.path, key, value: node.value[key] });
  }
  return keys;
}

/**
 * Bounded Levenshtein distance. Returns `limit + 1` as soon as the answer is
 * known to exceed `limit`, so a long dependency name cannot cost more than the
 * declared budget. Used by the typosquat-watchlist rules.
 */
export function boundedDistance(left, right, limit) {
  if (left === right) return 0;
  if (Math.abs(left.length - right.length) > limit) return limit + 1;
  const previous = new Array(right.length + 1);
  const current = new Array(right.length + 1);
  for (let column = 0; column <= right.length; column += 1) previous[column] = column;
  for (let row = 1; row <= left.length; row += 1) {
    current[0] = row;
    let rowMinimum = current[0];
    for (let column = 1; column <= right.length; column += 1) {
      const cost = left[row - 1] === right[column - 1] ? 0 : 1;
      current[column] = Math.min(previous[column] + 1, current[column - 1] + 1, previous[column - 1] + cost);
      if (current[column] < rowMinimum) rowMinimum = current[column];
    }
    if (rowMinimum > limit) return limit + 1;
    for (let column = 0; column <= right.length; column += 1) previous[column] = current[column];
  }
  return previous[right.length];
}

function compilePattern(check) {
  if (typeof check.valuePattern === 'string') {
    try {
      return new RegExp(check.valuePattern);
    } catch (error) {
      throw new ScaRuleError(`check.valuePattern: invalid regex (${error.message})`);
    }
  }
  if (typeof check.keyPattern === 'string') {
    try {
      return new RegExp(check.keyPattern);
    } catch (error) {
      throw new ScaRuleError(`check.keyPattern: invalid regex (${error.message})`);
    }
  }
  throw new ScaRuleError('check: predicate needs valuePattern or keyPattern');
}

/**
 * Evaluate one rule against one parsed dependency input.
 *
 * @param {object} check   the rule's `check` object
 * @param {{file?: string, document: unknown}} input parsed artifact
 * @returns {boolean} whether the rule fires
 */
export function evaluateScaCheck(check, input) {
  if (typeof check !== 'object' || check === null || Array.isArray(check)) {
    throw new ScaRuleError('check: must be an object');
  }
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new ScaRuleError('input: must be an object');
  }
  if (!Object.prototype.hasOwnProperty.call(input, 'document')) {
    throw new ScaRuleError('input.document: required');
  }
  const document = input.document;
  switch (check.type) {
    case 'sca-field-matches': {
      const pattern = compilePattern(check);
      return resolvePath(document, check.path).some(
        (node) => typeof node.value === 'string' && pattern.test(node.value),
      );
    }
    case 'sca-field-not-matches': {
      const pattern = compilePattern(check);
      const nodes = resolvePath(document, check.path);
      if (nodes.length === 0) return false;
      return !nodes.some((node) => typeof node.value === 'string' && pattern.test(node.value));
    }
    case 'sca-field-absent':
      return resolvePath(document, check.path).length === 0;
    case 'sca-key-matches': {
      const pattern = compilePattern(check);
      return keysAtPath(document, check.path).some((entry) => pattern.test(entry.key));
    }
    case 'sca-name-distance': {
      if (typeof check.target !== 'string' || check.target.length === 0) {
        throw new ScaRuleError('check.target: must be a non-empty string');
      }
      const limit = check.maxDistance;
      if (!Number.isInteger(limit) || limit < 1 || limit > 2) {
        throw new ScaRuleError('check.maxDistance: must be 1 or 2');
      }
      return keysAtPath(document, check.path).some((entry) => {
        if (entry.key === check.target) return false;
        if (entry.key.length < 4) return false;
        return boundedDistance(entry.key, check.target, limit) <= limit;
      });
    }
    default:
      throw new ScaRuleError(`check.type: must be one of ${SCA_CHECK_TYPES.join(', ')}`);
  }
}

/** Stable dedupe signature: ecosystem + predicate + normalized parameters. */
export function scaSignature(rule) {
  const check = rule.check ?? {};
  const parts = [rule.ecosystems?.[0] ?? 'none', check.type ?? 'none', check.path ?? '', check.target ?? ''];
  const pattern = check.valuePattern ?? check.keyPattern ?? '';
  parts.push(pattern.replace(/\s+/g, ' ').trim());
  return parts.join('|');
}
