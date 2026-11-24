import { globToRegExp } from './helpers.js';
import type { AppliedException } from './types.js';

export interface ExceptionRule {
  check: string;
  /** Project id or glob; defaults to every project. */
  project: string;
  /** Resource name or glob, e.g. "bastion-*". */
  resource: string;
  reason: string;
  owner: string;
  /** ISO date (YYYY-MM-DD). The exception stops applying after this day. */
  expires: string;
}

export function validateExceptions(raw: unknown, source: string): ExceptionRule[] {
  const list = (raw as { exceptions?: unknown[] } | null)?.exceptions ?? [];
  if (!Array.isArray(list)) throw new Error(`${source}: "exceptions" must be a list`);
  return list.map((item, i) => {
    const e = item as Partial<ExceptionRule>;
    const missing = (['check', 'resource', 'reason', 'owner', 'expires'] as const).filter((k) => !e?.[k]);
    if (missing.length) throw new Error(`${source}: exception #${i + 1} is missing ${missing.join(', ')}`);
    const expires = String(e.expires);
    if (Number.isNaN(Date.parse(expires))) throw new Error(`${source}: exception #${i + 1} has an invalid expires date "${expires}"`);
    return { check: e.check!, project: e.project ?? '*', resource: e.resource!, reason: e.reason!, owner: e.owner!, expires };
  });
}

export class ExceptionMatcher {
  readonly warnings: string[] = [];

  constructor(
    private readonly rules: ExceptionRule[],
    private readonly projectId: string,
    private readonly now: Date,
  ) {}

  match(checkId: string, resource: string): AppliedException | undefined {
    for (const rule of this.rules) {
      if (rule.check !== checkId) continue;
      if (!globToRegExp(rule.project).test(this.projectId)) continue;
      if (!globToRegExp(rule.resource).test(resource)) continue;
      // Expires at the end of the given day (UTC).
      if (Date.parse(rule.expires) + 86_400_000 <= this.now.getTime()) {
        const msg = `Exception for ${checkId} on ${resource} expired on ${rule.expires} (owner: ${rule.owner}); finding is reported again.`;
        if (!this.warnings.includes(msg)) this.warnings.push(msg);
        continue;
      }
      return { reason: rule.reason, owner: rule.owner, expires: rule.expires };
    }
    return undefined;
  }
}
