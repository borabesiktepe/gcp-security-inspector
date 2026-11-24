import { SEVERITIES, type CheckDefinition, type Environment, type Severity } from './types.js';

export interface Profile {
  name: string;
  environment: Environment;
  description: string;
  gate: { failOn: Severity[]; warnOn: Severity[] };
  /** checkId -> severity. Replaces the check's built-in severity for this profile. */
  overrides: Record<string, Severity>;
}

export function isSeverity(v: unknown): v is Severity {
  return typeof v === 'string' && (SEVERITIES as readonly string[]).includes(v);
}

export function resolveSeverity(check: CheckDefinition, profile: Profile): Severity {
  return profile.overrides[check.id] ?? check.severity[profile.environment];
}

export function validateProfile(raw: unknown, source: string, knownCheckIds: Set<string>): Profile {
  const p = raw as Partial<Profile> & { environment?: string };
  const errors: string[] = [];
  if (!p || typeof p !== 'object') throw new Error(`${source}: profile must be a mapping`);
  if (typeof p.name !== 'string') errors.push('name is required');
  if (!['poc', 'test', 'prod'].includes(p.environment ?? '')) errors.push('environment must be poc, test or prod');
  const gate = p.gate ?? { failOn: [], warnOn: [] };
  for (const s of [...(gate.failOn ?? []), ...(gate.warnOn ?? [])]) if (!isSeverity(s)) errors.push(`unknown severity "${s}" in gate`);
  const overrides = p.overrides ?? {};
  for (const [id, s] of Object.entries(overrides)) {
    if (!knownCheckIds.has(id)) errors.push(`override for unknown check "${id}"`);
    if (!isSeverity(s)) errors.push(`unknown severity "${s}" for "${id}"`);
  }
  if (errors.length) throw new Error(`${source}: ${errors.join('; ')}`);
  return {
    name: p.name!,
    environment: p.environment as Environment,
    description: p.description ?? '',
    gate: { failOn: gate.failOn ?? [], warnOn: gate.warnOn ?? [] },
    overrides,
  };
}
