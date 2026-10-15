#!/usr/bin/env node
/**
 * Zero-dependency validator for audience datasets (user-type content):
 *   drobon.knowledge.remediation/v1  (Developer + Security Professional)
 *   drobon.learning.lesson/v1        (Student)
 *   drobon.assessment.template/v1    (Security Professional)
 *   drobon.engagement.template/v1    (Pentester — authorized + passive ONLY)
 *
 * Executable spec (see docs/AUDIENCES.md). Beyond closed shapes and
 * app-mirrored bounds it EXECUTES what is executable:
 * - lesson quiz answerIndex must point at a real option;
 * - lesson practice files targeting a DPK-SAST-* rule are run against
 *   that pack rule: starters must trigger it, fixed files must not;
 * - engagement text passes a banned-phrase lint (high-precision
 *   offensive-tooling tripwire; human review still required).
 *
 * Usage: node scripts/validate-audiences.mjs [path...]
 *   (defaults: knowledge/remediation learning/lessons
 *   assessments/templates engagements; root = cwd)
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkClosed, readJsonFile } from './validate.mjs';

export const AUDIENCE_SCHEMAS = {
  remediation: 'drobon.knowledge.remediation/v1',
  lesson: 'drobon.learning.lesson/v1',
  template: 'drobon.assessment.template/v1',
  engagement: 'drobon.engagement.template/v1',
};

const RULE_ID_PATTERN =
  /^(DG-SAST-[0-9]{3,}|DG-SEC-[0-9]{3,}|DG-DAST-[0-9]{3,}|DPK-SAST-[0-9]{3,}|DPK-SEC-[0-9]{3,}|DPK-DAST-[0-9]{3,})$/;
const LESSON_ID_PATTERN = /^lsn_[a-z0-9_]{3,40}$/; // mirrors STUDENT_LESSON_ID_PATTERN
const TEMPLATE_ID_PATTERN = /^tmpl_[a-z0-9_]{3,40}$/;
const ENGAGEMENT_ID_PATTERN = /^eng_[a-z0-9_]{3,40}$/;
// Mirrors FINDING_CWE_PATTERN (Drobon app, packages/shared/src/scans.ts): no leading zeros.
const CWE_PATTERN = /^CWE-[1-9][0-9]{0,5}$/;
const HOSTNAME_PATTERN =
  /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
const CHECKLIST_KINDS = ['authorization', 'scope', 'evidence', 'safety'];
// High-precision offensive-tooling tripwire (see docs/AUDIENCES.md).
const BANNED_PHRASES =
  /\b(reverse[\s-]?shells?|msfvenom|sqlmap|mimikatz|meterpreter|shellcode|cobalt[\s-]?strike|zero[\s-]?days?|0days?|kerberoast|pass[\s-]?the[\s-]?hash|bloodhound|burp)\b/i;

const MAX_TITLE = 120; // mirrors ASSESSMENT_TITLE_MAX_LENGTH
const MAX_TEXT = 2000; // mirrors STUDENT_LESSON_TEXT_MAX
const MAX_WHY = 1000;
const MAX_ACTION = 400;
const MAX_ACTIONS = 8;
const MAX_EXAMPLE = 800;
const MAX_OBJECTIVES = 10; // mirrors ASSESSMENT_OBJECTIVES_MAX_COUNT
const MAX_OBJECTIVE_LEN = 240; // mirrors ASSESSMENT_OBJECTIVE_MAX_LENGTH
const MAX_HOSTS = 20; // mirrors ASSESSMENT_HOSTS_MAX_COUNT
const MAX_HOST_LEN = 253;
const MAX_NOTES = 1000; // mirrors ASSESSMENT_SCOPE_NOTES_MAX_LENGTH
const MAX_LESSON_OBJECTIVES = 5; // mirrors STUDENT_LESSON_OBJECTIVES_MAX
const MAX_QUIZ = 6; // mirrors STUDENT_QUIZ_QUESTIONS_MAX
const MAX_OPTIONS = 5; // mirrors STUDENT_QUIZ_OPTIONS_MAX
const MAX_PROMPT = 500;
const MAX_EXPLANATION = 1000;
const MAX_PRACTICE_FILES = 3; // mirrors STUDENT_PRACTICE_FILES_MAX
const MAX_FILE_CHARS = 800; // mirrors STUDENT_PRACTICE_FILE_MAX_CHARS
const MAX_PATH = 160; // app source-path policy
const MAX_BOUNDARIES = 10;
const MAX_CHECKLIST = 20;

const REMEDIATION_ALLOWED = [
  'schemaVersion',
  'ruleId',
  'whyItMatters',
  'actions',
  'verification',
  'standardId',
  'example',
];
const REMEDIATION_REQUIRED = ['schemaVersion', 'ruleId', 'whyItMatters', 'actions', 'verification'];
const LESSON_ALLOWED = [
  'schemaVersion',
  'id',
  'title',
  'summary',
  'concept',
  'objectives',
  'practice',
  'quiz',
];
const TEMPLATE_ALLOWED = ['schemaVersion', 'id', 'title', 'objectives', 'scope'];
const ENGAGEMENT_ALLOWED = ['schemaVersion', 'id', 'title', 'scopeTemplate', 'checklist'];

function hasControlChars(value, multiline) {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (multiline && (code === 0x0a || code === 0x09)) {
      continue;
    }
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function checkText(errors, path, value, max, multiline = false) {
  if (typeof value !== 'string') {
    errors.push(`${path}: must be a string`);
    return;
  }
  if (value.length < 1 || value.length > max) {
    errors.push(`${path}: must be 1..${max} characters (got ${value.length})`);
    return;
  }
  if (hasControlChars(value, multiline)) {
    errors.push(`${path}: must not contain control characters`);
  }
}

function kindOf(schemaVersion) {
  return (
    Object.keys(AUDIENCE_SCHEMAS).find((kind) => AUDIENCE_SCHEMAS[kind] === schemaVersion) ?? null
  );
}

export function validateRemediation(record) {
  const errors = [];
  checkClosed(errors, 'record', record, REMEDIATION_ALLOWED, REMEDIATION_REQUIRED);
  if (record['ruleId'] !== undefined) {
    if (typeof record['ruleId'] !== 'string' || !RULE_ID_PATTERN.test(record['ruleId'])) {
      errors.push('ruleId: must be a DG-* or DPK-* rule id');
    }
  }
  if (record['whyItMatters'] !== undefined) {
    checkText(errors, 'whyItMatters', record['whyItMatters'], MAX_WHY);
  }
  if (record['actions'] !== undefined) {
    if (!Array.isArray(record['actions'])) {
      errors.push('actions: must be an array');
    } else if (record['actions'].length < 1 || record['actions'].length > MAX_ACTIONS) {
      errors.push(`actions: must have 1..${MAX_ACTIONS} entries`);
    } else {
      record['actions'].forEach((entry, index) => {
        checkText(errors, `actions[${index}]`, entry, MAX_ACTION);
      });
    }
  }
  if (record['verification'] !== undefined) {
    checkText(errors, 'verification', record['verification'], MAX_WHY);
  }
  if (record['standardId'] !== undefined) {
    if (typeof record['standardId'] !== 'string' || !CWE_PATTERN.test(record['standardId'])) {
      errors.push('standardId: must match ^CWE-[1-9][0-9]{0,5}$ (omit when uncertain)');
    }
  }
  if (record['example'] !== undefined) {
    const example = record['example'];
    if (typeof example !== 'object' || example === null || Array.isArray(example)) {
      errors.push('example: must be an object');
    } else {
      checkClosed(errors, 'example', example, ['before', 'after', 'caveat'], ['before', 'after']);
      if (example['before'] !== undefined) {
        checkText(errors, 'example.before', example['before'], MAX_EXAMPLE);
      }
      if (example['after'] !== undefined) {
        checkText(errors, 'example.after', example['after'], MAX_EXAMPLE);
      }
      if (example['caveat'] !== undefined) {
        checkText(errors, 'example.caveat', example['caveat'], MAX_ACTION);
      }
    }
  }
  return errors;
}

function loadPackSastRule(root, ruleId) {
  const file = join(root, 'packs', 'sast', 'v1', 'rules', `${ruleId}.json`);
  const parsed = JSON.parse(readFileSync(file, 'utf8'));
  if (!Array.isArray(parsed.patterns) || parsed.patterns.length === 0) {
    throw new Error(`pack rule ${ruleId} has no patterns`);
  }
  return parsed.patterns.map((entry) => new RegExp(entry.source, entry.flags ?? ''));
}

function checkPracticeFiles(errors, path, value) {
  if (!Array.isArray(value)) {
    errors.push(`${path}: must be an array`);
    return [];
  }
  if (value.length < 1 || value.length > MAX_PRACTICE_FILES) {
    errors.push(`${path}: must have 1..${MAX_PRACTICE_FILES} files`);
    return [];
  }
  const out = [];
  value.forEach((entry, index) => {
    const entryPath = `${path}[${index}]`;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      errors.push(`${entryPath}: must be an object`);
      return;
    }
    checkClosed(errors, entryPath, entry, ['path', 'content'], ['path', 'content']);
    if (entry['path'] !== undefined) {
      checkText(errors, `${entryPath}.path`, entry['path'], MAX_PATH);
    }
    if (entry['content'] !== undefined) {
      checkText(errors, `${entryPath}.content`, entry['content'], MAX_FILE_CHARS, true);
    }
    if (typeof entry['content'] === 'string') {
      out.push(entry['content']);
    }
  });
  return out;
}

export function validateLesson(record, root) {
  const errors = [];
  checkClosed(errors, 'record', record, LESSON_ALLOWED, LESSON_ALLOWED);
  if (record['id'] !== undefined) {
    if (typeof record['id'] !== 'string' || !LESSON_ID_PATTERN.test(record['id'])) {
      errors.push('id: must match ^lsn_[a-z0-9_]{3,40}$');
    }
  }
  if (record['title'] !== undefined) {
    checkText(errors, 'title', record['title'], MAX_TITLE);
  }
  if (record['summary'] !== undefined) {
    checkText(errors, 'summary', record['summary'], MAX_TEXT, true);
  }
  if (record['concept'] !== undefined) {
    checkText(errors, 'concept', record['concept'], MAX_TEXT, true);
  }
  if (record['objectives'] !== undefined) {
    if (!Array.isArray(record['objectives'])) {
      errors.push('objectives: must be an array');
    } else if (
      record['objectives'].length < 1 ||
      record['objectives'].length > MAX_LESSON_OBJECTIVES
    ) {
      errors.push(`objectives: must have 1..${MAX_LESSON_OBJECTIVES} entries`);
    } else {
      record['objectives'].forEach((entry, index) => {
        checkText(errors, `objectives[${index}]`, entry, MAX_OBJECTIVE_LEN);
      });
    }
  }
  let starterContents = [];
  let fixedContents = [];
  let targetRuleId = null;
  if (record['practice'] !== undefined) {
    const practice = record['practice'];
    if (typeof practice !== 'object' || practice === null || Array.isArray(practice)) {
      errors.push('practice: must be an object');
    } else {
      checkClosed(
        errors,
        'practice',
        practice,
        ['instruction', 'targetRuleId', 'starterFiles', 'fixInstruction', 'fixedFiles'],
        ['instruction', 'targetRuleId', 'starterFiles', 'fixInstruction', 'fixedFiles'],
      );
      if (practice['instruction'] !== undefined) {
        checkText(errors, 'practice.instruction', practice['instruction'], MAX_TEXT, true);
      }
      if (practice['fixInstruction'] !== undefined) {
        checkText(errors, 'practice.fixInstruction', practice['fixInstruction'], MAX_TEXT, true);
      }
      if (practice['targetRuleId'] !== undefined) {
        if (typeof practice['targetRuleId'] !== 'string' || !RULE_ID_PATTERN.test(practice['targetRuleId'])) {
          errors.push('practice.targetRuleId: must be a DG-* or DPK-* rule id');
        } else {
          targetRuleId = practice['targetRuleId'];
        }
      }
      if (practice['starterFiles'] !== undefined) {
        starterContents = checkPracticeFiles(errors, 'practice.starterFiles', practice['starterFiles']);
      }
      if (practice['fixedFiles'] !== undefined) {
        fixedContents = checkPracticeFiles(errors, 'practice.fixedFiles', practice['fixedFiles']);
      }
    }
  }
  if (record['quiz'] !== undefined) {
    if (!Array.isArray(record['quiz'])) {
      errors.push('quiz: must be an array');
    } else if (record['quiz'].length < 1 || record['quiz'].length > MAX_QUIZ) {
      errors.push(`quiz: must have 1..${MAX_QUIZ} questions`);
    } else {
      record['quiz'].forEach((entry, index) => {
        const path = `quiz[#${index}]`;
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
          errors.push(`${path}: must be an object`);
          return;
        }
        checkClosed(errors, path, entry, ['prompt', 'options', 'answerIndex', 'explanation'], ['prompt', 'options', 'answerIndex', 'explanation']);
        if (entry['prompt'] !== undefined) {
          checkText(errors, `${path}.prompt`, entry['prompt'], MAX_PROMPT);
        }
        if (entry['options'] !== undefined) {
          if (!Array.isArray(entry['options'])) {
            errors.push(`${path}.options: must be an array`);
          } else if (entry['options'].length < 2 || entry['options'].length > MAX_OPTIONS) {
            errors.push(`${path}.options: must have 2..${MAX_OPTIONS} options`);
          } else {
            entry['options'].forEach((option, optionIndex) => {
              checkText(errors, `${path}.options[${optionIndex}]`, option, MAX_OBJECTIVE_LEN);
            });
          }
        }
        if (entry['answerIndex'] !== undefined) {
          const optionCount = Array.isArray(entry['options']) ? entry['options'].length : 0;
          if (
            typeof entry['answerIndex'] !== 'number' ||
            !Number.isInteger(entry['answerIndex']) ||
            entry['answerIndex'] < 0 ||
            entry['answerIndex'] >= optionCount
          ) {
            errors.push(`${path}.answerIndex: must be an integer 0..${optionCount - 1}`);
          }
        }
        if (entry['explanation'] !== undefined) {
          checkText(errors, `${path}.explanation`, entry['explanation'], MAX_EXPLANATION, true);
        }
      });
    }
  }
  // Executable practice check: DPK-SAST targets run against the pack rule.
  if (targetRuleId !== null && errors.length === 0) {
    if (targetRuleId.startsWith('DPK-SEC-') || targetRuleId.startsWith('DPK-DAST-')) {
      errors.push('practice.targetRuleId: lesson practice is SAST-scan based; DPK-SEC-*/DPK-DAST-* targets are unsupported in v1');
    } else if (targetRuleId.startsWith('DPK-SAST-')) {
      let regexes;
      try {
        regexes = loadPackSastRule(root, targetRuleId);
      } catch {
        errors.push(`practice.targetRuleId: pack rule ${targetRuleId} not found under packs/sast/v1/rules/`);
        return errors;
      }
      const hits = (content) =>
        content.split('\n').some((line) =>
          regexes.some((regex) => {
            regex.lastIndex = 0;
            return regex.test(line);
          }),
        );
      if (!starterContents.some(hits)) {
        errors.push(`practice.starterFiles: no line triggers ${targetRuleId} (the exercise would have nothing to find)`);
      }
      if (fixedContents.some(hits)) {
        errors.push(`practice.fixedFiles: a line still triggers ${targetRuleId} (the fix does not fix)`);
      }
    }
    // DG-* targets are app-owned: shape-only here (the loader verifies).
  }
  return errors;
}

function checkHosts(errors, path, value) {
  if (!Array.isArray(value)) {
    errors.push(`${path}: must be an array`);
    return 0;
  }
  if (value.length > MAX_HOSTS) {
    errors.push(`${path}: at most ${MAX_HOSTS} hosts`);
  }
  value.forEach((entry, index) => {
    if (typeof entry !== 'string' || entry.length < 1 || entry.length > MAX_HOST_LEN) {
      errors.push(`${path}[${index}]: must be 1..${MAX_HOST_LEN} characters`);
    } else if (!HOSTNAME_PATTERN.test(entry)) {
      errors.push(`${path}[${index}]: must be an exact DNS hostname (no wildcards, no IPs, no URLs)`);
    }
  });
  return value.length;
}

export function validateAssessmentTemplate(record) {
  const errors = [];
  checkClosed(errors, 'record', record, TEMPLATE_ALLOWED, TEMPLATE_ALLOWED);
  if (record['id'] !== undefined) {
    if (typeof record['id'] !== 'string' || !TEMPLATE_ID_PATTERN.test(record['id'])) {
      errors.push('id: must match ^tmpl_[a-z0-9_]{3,40}$');
    }
  }
  if (record['title'] !== undefined) {
    checkText(errors, 'title', record['title'], MAX_TITLE);
  }
  if (record['objectives'] !== undefined) {
    if (!Array.isArray(record['objectives'])) {
      errors.push('objectives: must be an array');
    } else if (record['objectives'].length < 1 || record['objectives'].length > MAX_OBJECTIVES) {
      errors.push(`objectives: must have 1..${MAX_OBJECTIVES} entries`);
    } else {
      record['objectives'].forEach((entry, index) => {
        checkText(errors, `objectives[${index}]`, entry, MAX_OBJECTIVE_LEN);
      });
    }
  }
  if (record['scope'] !== undefined) {
    const scope = record['scope'];
    if (typeof scope !== 'object' || scope === null || Array.isArray(scope)) {
      errors.push('scope: must be an object');
    } else {
      // No authorizationDeclarations: templates never pre-declare
      // authorization (closed shape rejects the field outright).
      checkClosed(errors, 'scope', scope, ['inScopeHosts', 'outOfScopeHosts', 'notes'], ['inScopeHosts', 'outOfScopeHosts']);
      let total = 0;
      if (scope['inScopeHosts'] !== undefined) {
        total += checkHosts(errors, 'scope.inScopeHosts', scope['inScopeHosts']);
      }
      if (scope['outOfScopeHosts'] !== undefined) {
        total += checkHosts(errors, 'scope.outOfScopeHosts', scope['outOfScopeHosts']);
      }
      if (total > MAX_HOSTS) {
        errors.push(`scope: at most ${MAX_HOSTS} hosts in total (got ${total})`);
      }
      if (scope['notes'] !== undefined) {
        checkText(errors, 'scope.notes', scope['notes'], MAX_NOTES, true);
      }
    }
  }
  return errors;
}

export function validateEngagementTemplate(record) {
  const errors = [];
  checkClosed(errors, 'record', record, ENGAGEMENT_ALLOWED, ENGAGEMENT_ALLOWED);
  if (record['id'] !== undefined) {
    if (typeof record['id'] !== 'string' || !ENGAGEMENT_ID_PATTERN.test(record['id'])) {
      errors.push('id: must match ^eng_[a-z0-9_]{3,40}$');
    }
  }
  const linted = [];
  if (record['title'] !== undefined) {
    checkText(errors, 'title', record['title'], MAX_TITLE);
    if (typeof record['title'] === 'string') {
      linted.push(['title', record['title']]);
    }
  }
  if (record['scopeTemplate'] !== undefined) {
    const scope = record['scopeTemplate'];
    if (typeof scope !== 'object' || scope === null || Array.isArray(scope)) {
      errors.push('scopeTemplate: must be an object');
    } else {
      checkClosed(errors, 'scopeTemplate', scope, ['notes', 'boundaries'], ['notes', 'boundaries']);
      if (scope['notes'] !== undefined) {
        checkText(errors, 'scopeTemplate.notes', scope['notes'], MAX_NOTES, true);
        if (typeof scope['notes'] === 'string') {
          linted.push(['scopeTemplate.notes', scope['notes']]);
        }
      }
      if (scope['boundaries'] !== undefined) {
        if (!Array.isArray(scope['boundaries'])) {
          errors.push('scopeTemplate.boundaries: must be an array');
        } else if (scope['boundaries'].length < 1 || scope['boundaries'].length > MAX_BOUNDARIES) {
          errors.push(`scopeTemplate.boundaries: must have 1..${MAX_BOUNDARIES} entries`);
        } else {
          scope['boundaries'].forEach((entry, index) => {
            checkText(errors, `scopeTemplate.boundaries[${index}]`, entry, MAX_OBJECTIVE_LEN);
            if (typeof entry === 'string') {
              linted.push([`scopeTemplate.boundaries[${index}]`, entry]);
            }
          });
        }
      }
    }
  }
  if (record['checklist'] !== undefined) {
    if (!Array.isArray(record['checklist'])) {
      errors.push('checklist: must be an array');
    } else if (record['checklist'].length < 1 || record['checklist'].length > MAX_CHECKLIST) {
      errors.push(`checklist: must have 1..${MAX_CHECKLIST} entries`);
    } else {
      record['checklist'].forEach((entry, index) => {
        const path = `checklist[#${index}]`;
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
          errors.push(`${path}: must be an object`);
          return;
        }
        checkClosed(errors, path, entry, ['item', 'kind'], ['item', 'kind']);
        if (entry['item'] !== undefined) {
          checkText(errors, `${path}.item`, entry['item'], MAX_OBJECTIVE_LEN);
          if (typeof entry['item'] === 'string') {
            linted.push([`${path}.item`, entry['item']]);
          }
        }
        if (entry['kind'] !== undefined && !CHECKLIST_KINDS.includes(entry['kind'])) {
          errors.push(`${path}.kind: must be one of ${CHECKLIST_KINDS.join(', ')}`);
        }
      });
    }
  }
  for (const [path, text] of linted) {
    const banned = BANNED_PHRASES.exec(text);
    if (banned !== null) {
      errors.push(`${path}: banned phrase "${banned[0]}" (engagements are authorized + passive only)`);
    }
  }
  return errors;
}

/** Validate one parsed audience file. Routes on schemaVersion. */
export function validateAudienceFile(value, root) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return ['record: must be an object'];
  }
  const kind = kindOf(value['schemaVersion']);
  if (kind === 'remediation') {
    return validateRemediation(value);
  }
  if (kind === 'lesson') {
    return validateLesson(value, root);
  }
  if (kind === 'template') {
    return validateAssessmentTemplate(value);
  }
  if (kind === 'engagement') {
    return validateEngagementTemplate(value);
  }
  return [`schemaVersion: must be one of ${Object.values(AUDIENCE_SCHEMAS).join(', ')}`];
}

export function validateAudiencePath(filePath, root) {
  const loaded = readJsonFile(filePath);
  if (loaded.errors !== undefined) return loaded.errors;
  return validateAudienceFile(loaded.value, root).map((error) => `${filePath}: ${error}`);
}

function collectJsonFiles(target) {
  const stat = statSync(target);
  if (stat.isFile()) {
    return target.endsWith('.json') ? [target] : [];
  }
  const found = [];
  const walk = (dir) => {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        found.push(full);
      }
    }
  };
  walk(target);
  return found;
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedAsScript) {
  const targets = process.argv.slice(2);
  const defaults = [
    'knowledge/remediation',
    'learning/lessons',
    'assessments/templates',
    'engagements',
  ];
  const roots = (targets.length > 0 ? targets : defaults).map((target) =>
    resolve(process.cwd(), target),
  );
  const failures = [];
  let fileCount = 0;
  for (const root of roots) {
    let files;
    try {
      files = collectJsonFiles(root);
    } catch (err) {
      failures.push(`${root}: cannot read: ${err.message}`);
      continue;
    }
    fileCount += files.length;
    for (const file of files) {
      failures.push(...validateAudiencePath(file, process.cwd()));
    }
  }
  if (fileCount === 0 && failures.length === 0) {
    failures.push('no JSON files found (refusing to pass on empty input)');
  }
  for (const failure of failures) {
    process.stdout.write(`${failure}\n`);
  }
  if (failures.length > 0) {
    process.stdout.write(`validate-audiences: FAIL (${fileCount} files, ${failures.length} errors)\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`validate-audiences: PASS (${fileCount} files, 0 errors)\n`);
  }
}
