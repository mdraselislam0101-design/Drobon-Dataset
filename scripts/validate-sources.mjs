#!/usr/bin/env node
/**
 * Zero-dependency validator for `drobon.vuln-intel.sources/v1`.
 *
 * The source registry (`vuln-intel/sources.json`) is the canonical list
 * of allowed `provenance.source` values: terms pointers, review status,
 * and lifecycle per upstream. Pointers grant nothing — redistribution
 * stays UNVERIFIED until owner batch authorization (terms review:
 * docs/LICENSE_REVIEW.md; authorization: docs/LICENSE_DECISION_RECORD.md). The
 * consistency runner cross-checks every record source against this
 * registry, so an unregistered source fails the suite.
 *
 * Usage: node scripts/validate-sources.mjs [path...]  (default: vuln-intel/sources.json)
 */
import { statSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkBoundedText, readJsonFile } from './validate.mjs';

export const SOURCES_SCHEMA = 'drobon.vuln-intel.sources/v1';

const TOP_ALLOWED = ['schemaVersion', 'sources'];
const SOURCE_ALLOWED = ['id', 'displayName', 'termsUrl', 'redistribution', 'attribution', 'status', 'notes', 'licenseReview'];
const SOURCE_REQUIRED = ['id', 'displayName', 'redistribution', 'attribution', 'status', 'notes'];
const SOURCE_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;
const REDISTRIBUTION_STATUSES = ['VERIFIED', 'UNVERIFIED', 'NOT_APPLICABLE'];
const LIFECYCLE_STATUSES = ['IN_USE', 'PLANNED', 'RETIRED'];
const REVIEW_STATUSES = ['VERIFIED_ALLOWED', 'RESTRICTED', 'BLOCKED_UNVERIFIED', 'NOT_APPLICABLE'];
const REVIEW_DATE_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;
const REVIEW_REPORT_PATH = 'docs/LICENSE_REVIEW.md';

export function validateSources(value) {
  const errors = [];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return ['registry: must be an object'];
  }
  for (const key of Object.keys(value)) {
    if (!TOP_ALLOWED.includes(key)) {
      errors.push(`registry: unknown property "${key}"`);
    }
  }
  for (const key of TOP_ALLOWED) {
    if (value[key] === undefined) {
      errors.push(`registry: missing required property "${key}"`);
    }
  }
  if (value['schemaVersion'] !== undefined && value['schemaVersion'] !== SOURCES_SCHEMA) {
    errors.push(`schemaVersion: must be exactly "${SOURCES_SCHEMA}"`);
  }
  if (value['sources'] !== undefined) {
    const sources = value['sources'];
    if (!Array.isArray(sources)) {
      errors.push('sources: must be an array');
    } else {
      if (sources.length < 1 || sources.length > 50) {
        errors.push(`sources: must have 1..50 entries (got ${sources.length})`);
      }
      const seenIds = new Set();
      sources.forEach((entry, index) => {
        const path = `sources[${index}]`;
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
          errors.push(`${path}: must be an object`);
          return;
        }
        for (const key of Object.keys(entry)) {
          if (!SOURCE_ALLOWED.includes(key)) {
            errors.push(`${path}: unknown property "${key}"`);
          }
        }
        for (const key of SOURCE_REQUIRED) {
          if (entry[key] === undefined) {
            errors.push(`${path}: missing required property "${key}"`);
          }
        }
        if (entry['id'] !== undefined) {
          if (typeof entry['id'] !== 'string' || !SOURCE_ID_PATTERN.test(entry['id'])) {
            errors.push(`${path}.id: must match ^[A-Za-z][A-Za-z0-9_-]{0,31}$`);
          } else if (seenIds.has(entry['id'])) {
            errors.push(`${path}.id: duplicate source id "${entry['id']}"`);
          } else {
            seenIds.add(entry['id']);
          }
        }
        if (entry['displayName'] !== undefined) checkBoundedText(errors, `${path}.displayName`, entry['displayName'], 120);
        if (entry['termsUrl'] !== undefined) {
          checkBoundedText(errors, `${path}.termsUrl`, entry['termsUrl'], 400);
          if (typeof entry['termsUrl'] === 'string' && !entry['termsUrl'].startsWith('https://')) {
            errors.push(`${path}.termsUrl: must start with https://`);
          }
        }
        if (entry['redistribution'] !== undefined && !REDISTRIBUTION_STATUSES.includes(entry['redistribution'])) {
          errors.push(`${path}.redistribution: must be one of ${REDISTRIBUTION_STATUSES.join(', ')}`);
        }
        if (entry['attribution'] !== undefined) checkBoundedText(errors, `${path}.attribution`, entry['attribution'], 200);
        if (entry['status'] !== undefined && !LIFECYCLE_STATUSES.includes(entry['status'])) {
          errors.push(`${path}.status: must be one of ${LIFECYCLE_STATUSES.join(', ')}`);
        }
        if (entry['notes'] !== undefined) checkBoundedText(errors, `${path}.notes`, entry['notes'], 500);
        if (entry['licenseReview'] === undefined) {
          errors.push(`${path}: missing required property "licenseReview"`);
        } else {
          const review = entry['licenseReview'];
          if (typeof review !== 'object' || review === null || Array.isArray(review)) {
            errors.push(`${path}.licenseReview: must be an object`);
          } else {
            for (const key of Object.keys(review)) {
              if (!['status', 'reviewedAt', 'report'].includes(key)) {
                errors.push(`${path}.licenseReview: unknown property "${key}"`);
              }
            }
            if (!REVIEW_STATUSES.includes(review['status'])) {
              errors.push(`${path}.licenseReview.status: must be one of ${REVIEW_STATUSES.join(', ')}`);
            }
            if (typeof review['reviewedAt'] !== 'string' || !REVIEW_DATE_PATTERN.test(review['reviewedAt'])) {
              errors.push(`${path}.licenseReview.reviewedAt: must be a YYYY-MM-DD date`);
            }
            if (review['report'] !== REVIEW_REPORT_PATH) {
              errors.push(`${path}.licenseReview.report: must be "${REVIEW_REPORT_PATH}"`);
            }
          }
        }
      });
    }
  }
  return errors;
}

export function validateSourcesPath(filePath) {
  const loaded = readJsonFile(filePath);
  if (loaded.errors !== undefined) return loaded.errors;
  return validateSources(loaded.value).map((error) => `${filePath}: ${error}`);
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedAsScript) {
  const targets = process.argv.slice(2);
  const roots = (targets.length > 0 ? targets : ['vuln-intel/sources.json']).map((target) =>
    resolve(process.cwd(), target),
  );
  const failures = [];
  let fileCount = 0;
  for (const root of roots) {
    try {
      if (!statSync(root).isFile()) {
        failures.push(`${root}: not a file`);
        continue;
      }
    } catch (err) {
      failures.push(`${root}: cannot read: ${err.message}`);
      continue;
    }
    fileCount += 1;
    failures.push(...validateSourcesPath(root));
  }
  if (fileCount === 0 && failures.length === 0) {
    failures.push('no files found (refusing to pass on empty input)');
  }
  for (const failure of failures) {
    process.stdout.write(`${failure}\n`);
  }
  if (failures.length > 0) {
    process.stdout.write(`validate-sources: FAIL (${fileCount} files, ${failures.length} errors)\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`validate-sources: PASS (${fileCount} files, 0 errors)\n`);
  }
}
