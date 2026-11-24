import { randomUUID } from 'node:crypto';
import { GcpApiError } from '../gcp/client.js';
import type { Project } from '../gcp/types.js';
import { ExceptionMatcher, type ExceptionRule } from './exceptions.js';
import type { Profile } from './profiles.js';
import { resolveSeverity } from './profiles.js';
import { gate, score } from './scoring.js';
import type {
  CheckDefinition,
  CheckResult,
  CheckStatus,
  Environment,
  Finding,
  ScanContext,
  ScanReport,
  ServiceId,
  Severity,
} from './types.js';

export interface RunOptions {
  profile: Profile;
  environmentSource: ScanReport['environmentSource'];
  exceptions: ExceptionRule[];
  project?: Project;
}

function base(check: CheckDefinition, severity: Severity) {
  return {
    id: check.id,
    title: check.title,
    service: check.service,
    category: check.category,
    cis: check.cis ?? [],
    severity,
    rationale: check.rationale,
    remediation: check.remediation,
    docs: check.docs,
  };
}

const EMPTY = { total: 0, passed: 0, failed: 0, excepted: 0 };

export async function runCheck(check: CheckDefinition, ctx: ScanContext, severity: Severity, matcher: ExceptionMatcher): Promise<CheckResult> {
  if (severity === 'off') {
    return { ...base(check, severity), status: 'SKIPPED', message: 'Disabled for this environment', resources: EMPTY, findings: [] };
  }
  try {
    const outcome = await check.run(ctx);
    if (outcome.kind === 'not_applicable') {
      return { ...base(check, severity), status: 'NOT_APPLICABLE', message: outcome.reason, resources: EMPTY, findings: [] };
    }
    const findings: Finding[] = outcome.resources.map((r) => {
      if (r.status !== 'FAIL') return r;
      const excepted = matcher.match(check.id, r.resource);
      return excepted ? { ...r, excepted } : r;
    });
    const failed = findings.filter((f) => f.status === 'FAIL' && !f.excepted).length;
    const excepted = findings.filter((f) => f.excepted).length;
    const passed = findings.filter((f) => f.status === 'PASS').length;
    const status: CheckStatus = failed > 0 ? 'FAIL' : 'PASS';
    // Failing resources first so the UI can show them at the top.
    findings.sort((a, b) => Number(b.status === 'FAIL' && !b.excepted) - Number(a.status === 'FAIL' && !a.excepted));
    return { ...base(check, severity), status, resources: { total: findings.length, passed, failed, excepted }, findings };
  } catch (err) {
    if (err instanceof GcpApiError && err.kind === 'API_DISABLED') {
      return {
        ...base(check, severity),
        status: 'NOT_APPLICABLE',
        message: `The required API is not enabled in this project, so there are no resources to check (${new URL(err.url).hostname}).`,
        resources: EMPTY,
        findings: [],
      };
    }
    const message =
      err instanceof GcpApiError && err.kind === 'PERMISSION_DENIED'
        ? `Permission denied: ${err.message}`
        : err instanceof Error
          ? err.message
          : String(err);
    return { ...base(check, severity), status: 'ERROR', message, resources: EMPTY, findings: [] };
  }
}

export async function runScan(ctx: ScanContext, checks: CheckDefinition[], opts: RunOptions): Promise<ScanReport> {
  const startedAt = new Date().toISOString();
  const matcher = new ExceptionMatcher(opts.exceptions, ctx.projectId, ctx.now);
  const results = await Promise.all(checks.map((c) => runCheck(c, ctx, resolveSeverity(c, opts.profile), matcher)));

  const byStatus: Record<CheckStatus, number> = { PASS: 0, FAIL: 0, ERROR: 0, NOT_APPLICABLE: 0, SKIPPED: 0 };
  const failedBySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of results) {
    byStatus[r.status]++;
    if (r.status === 'FAIL' && r.severity !== 'off') failedBySeverity[r.severity]++;
  }
  const serviceIds = [...new Set(results.map((r) => r.service))] as ServiceId[];
  const services = serviceIds.map((id) => {
    const own = results.filter((r) => r.service === id);
    return { id, score: score(own), checks: own.filter((r) => r.status !== 'SKIPPED').length, failed: own.filter((r) => r.status === 'FAIL').length };
  });

  const warnings = [...matcher.warnings];
  if (opts.environmentSource.source === 'default') warnings.unshift(opts.environmentSource.detail);
  const errors = results.filter((r) => r.status === 'ERROR');
  if (errors.length) warnings.push(`${errors.length} check(s) could not be evaluated. Check the scanner identity's roles (see README).`);

  return {
    id: randomUUID(),
    projectId: ctx.projectId,
    projectName: opts.project?.displayName,
    environment: opts.profile.environment as Environment,
    environmentSource: opts.environmentSource,
    profile: opts.profile.name,
    startedAt,
    finishedAt: new Date().toISOString(),
    score: score(results),
    gate: gate(results, opts.profile),
    summary: { byStatus, failedBySeverity, services },
    warnings,
    checks: results,
  };
}
