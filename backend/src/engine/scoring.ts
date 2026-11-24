import type { Profile } from './profiles.js';
import type { CheckResult, GateStatus, Severity } from './types.js';

export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 10, high: 5, medium: 3, low: 1, info: 0, off: 0 };

/**
 * Weighted score 0-100. Each evaluated check contributes its severity weight times the share of
 * resources that passed (excepted resources count as passed). Errors, N/A and skipped checks are left out.
 */
export function score(checks: CheckResult[]): number {
  let total = 0;
  let earned = 0;
  for (const c of checks) {
    if (c.status !== 'PASS' && c.status !== 'FAIL') continue;
    const w = SEVERITY_WEIGHT[c.severity];
    if (w === 0) continue;
    const ratio = c.resources.total === 0 ? 1 : (c.resources.passed + c.resources.excepted) / c.resources.total;
    total += w;
    earned += w * ratio;
  }
  return total === 0 ? 100 : Math.round((earned / total) * 100);
}

export function gate(checks: CheckResult[], profile: Profile): { status: GateStatus; reasons: string[] } {
  const failOn = new Set(profile.gate.failOn);
  const warnOn = new Set(profile.gate.warnOn);
  const blocking = checks.filter((c) => c.status === 'FAIL' && failOn.has(c.severity));
  if (blocking.length) {
    return { status: 'BLOCKED', reasons: blocking.map((c) => `[${c.severity}] ${c.title} (${c.resources.failed} resource(s))`) };
  }
  const unknown = checks.filter((c) => c.status === 'ERROR' && failOn.has(c.severity));
  if (unknown.length) {
    return { status: 'INCOMPLETE', reasons: unknown.map((c) => `[${c.severity}] ${c.title} could not be evaluated: ${c.message ?? 'error'}`) };
  }
  const warnings = checks.filter((c) => c.status === 'FAIL' && warnOn.has(c.severity));
  if (warnings.length) {
    return { status: 'WARN', reasons: warnings.map((c) => `[${c.severity}] ${c.title} (${c.resources.failed} resource(s))`) };
  }
  return { status: 'PASS', reasons: [] };
}
