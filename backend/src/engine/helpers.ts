import type { CheckDefinition, CheckOutcome, ResourceResult } from './types.js';

export function defineCheck(def: CheckDefinition): CheckDefinition {
  return def;
}

/**
 * Evaluates every item. `violation` returns evidence (an object) when the item fails,
 * or `undefined` when it passes. An empty list means the check is not applicable.
 */
export function evaluateEach<T>(
  items: T[],
  name: (item: T) => string,
  violation: (item: T) => Record<string, unknown> | undefined,
  emptyReason: string,
): CheckOutcome {
  if (items.length === 0) return { kind: 'not_applicable', reason: emptyReason };
  const resources: ResourceResult[] = items.map((item) => {
    const evidence = violation(item);
    return evidence ? { resource: name(item), status: 'FAIL', evidence } : { resource: name(item), status: 'PASS' };
  });
  return { kind: 'evaluated', resources };
}

/** Last path segment of a GCP self link / resource URL. */
export function shortName(url: string | undefined): string {
  if (!url) return '';
  const parts = url.split('/');
  return parts[parts.length - 1];
}

export function metadataValue(items: { key: string; value?: string }[] | undefined, key: string): string | undefined {
  return items?.find((i) => i.key === key)?.value;
}

export function isTrue(v: string | undefined): boolean {
  return v !== undefined && ['true', '1', 'yes', 'y'].includes(v.trim().toLowerCase());
}

export function isFalse(v: string | undefined): boolean {
  return v !== undefined && ['false', '0', 'no', 'n'].includes(v.trim().toLowerCase());
}

/** Converts a simple `*` glob into an anchored RegExp. */
export function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}
