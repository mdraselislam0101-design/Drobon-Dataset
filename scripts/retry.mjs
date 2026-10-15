/**
 * Bounded retry with exponential backoff for importer retrieval.
 *
 * Retries transient failures only (network reset, 429, 5xx) per
 * INGESTION_PROTOCOL.md section 8: max 5 attempts, base delays
 * 2s/4s/8s/16s/32s plus jitter. Anything else (4xx except 429, schema
 * violations, unknown shapes) throws immediately - fail-closed, the
 * batch aborts and the item quarantines. `sleep` and `random` are
 * injectable so tests never wait on real clocks.
 */

export const MAX_ATTEMPTS = 5;
export const RETRY_DELAYS_MS = [2000, 4000, 8000, 16000, 32000];
export const JITTER_MAX_MS = 1000;

const TRANSIENT_CODES = ['ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN'];

export class HttpError extends Error {
  constructor(status, statusText, url) {
    super(`HTTP ${status} ${statusText} for ${url}`);
    this.name = 'HttpError';
    this.status = status;
  }
}

/** True only for failures worth retrying. Unknown shapes are NOT transient. */
export function isTransientError(err) {
  if (typeof err?.status === 'number') {
    return err.status === 429 || (err.status >= 500 && err.status <= 599);
  }
  if (typeof err?.code === 'string' && TRANSIENT_CODES.includes(err.code)) {
    return true;
  }
  return err instanceof TypeError && /fetch failed|network/i.test(err.message ?? '');
}

/** Base delay for attempt N (1-based). Past the table, the last delay repeats. */
export function backoffDelayMs(attempt) {
  if (!Number.isInteger(attempt) || attempt < 1) {
    throw new Error('backoffDelayMs: attempt must be an integer >= 1');
  }
  return RETRY_DELAYS_MS[Math.min(attempt, RETRY_DELAYS_MS.length) - 1];
}

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Run fn(attempt) until it succeeds, the error is non-transient, or attempts
 * run out. Returns fn's result; otherwise throws the last error. onRetry is
 * called as onRetry(attempt, error, delayMs) before each wait (logging hook).
 */
export async function withRetries(fn, options = {}) {
  const attempts = options.attempts ?? MAX_ATTEMPTS;
  const sleep = options.sleep ?? defaultSleep;
  const random = options.random ?? Math.random;
  const onRetry = options.onRetry ?? null;
  if (!Number.isInteger(attempts) || attempts < 1) {
    throw new Error('withRetries: attempts must be an integer >= 1');
  }
  let lastError = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastError = err;
      if (attempt >= attempts || !isTransientError(err)) {
        throw err;
      }
      const delayMs = backoffDelayMs(attempt) + Math.floor(random() * JITTER_MAX_MS);
      if (onRetry !== null) onRetry(attempt, err, delayMs);
      await sleep(delayMs);
    }
  }
  throw lastError;
}
