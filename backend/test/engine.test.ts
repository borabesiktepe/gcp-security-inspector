import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../src/checks/index.js';
import { loadConfig } from '../src/config/load.js';
import { resolveEnvironment } from '../src/engine/environment.js';
import { validateExceptions } from '../src/engine/exceptions.js';
import { defineCheck } from '../src/engine/helpers.js';
import type { Profile } from '../src/engine/profiles.js';
import { runScan } from '../src/engine/runner.js';
import { gate, score } from '../src/engine/scoring.js';
import { GcpApiError } from '../src/gcp/client.js';
import { config, fakeContext } from './fakes.js';

const profile = (env: 'poc' | 'test' | 'prod', overrides: Profile['overrides'] = {}): Profile => ({
  name: env,
  environment: env,
  description: '',
  gate: { failOn: ['critical'], warnOn: ['high'] },
  overrides,
});

const sample = defineCheck({
  id: 'sample.public-thing',
  title: 'Sample',
  service: 'compute',
  category: 'security',
  severity: { poc: 'off', test: 'high', prod: 'critical' },
  rationale: 'r',
  remediation: 'fix it',
  async run(ctx) {
    const items = await ctx.data('instances');
    return {
      kind: 'evaluated',
      resources: items.map((i) => ({ resource: i.name, status: i.canIpForward ? ('FAIL' as const) : ('PASS' as const) })),
    };
  },
});

const env = { source: 'request' as const, detail: '' };

describe('environment resolution', () => {
  it('prefers explicit request, then label, then folder, then default', () => {
    expect(resolveEnvironment('poc', { projectId: 'x', labels: { environment: 'production' } }, config).environment).toBe('poc');
    expect(resolveEnvironment(undefined, { projectId: 'x', labels: { env: 'staging' } }, config)).toMatchObject({ environment: 'test', source: { source: 'label' } });
    expect(resolveEnvironment(undefined, { projectId: 'x', parent: 'folders/42' }, config)).toMatchObject({ environment: 'test', source: { source: 'folder' } });
    expect(resolveEnvironment(undefined, { projectId: 'x' }, config)).toMatchObject({ environment: 'prod', source: { source: 'default' } });
  });
  it('rejects unknown environments', () => {
    expect(() => resolveEnvironment('qa', undefined, config)).toThrow(/Unknown environment/);
  });
});

describe('runner', () => {
  const ctx = fakeContext({ instances: [{ name: 'a', canIpForward: true }, { name: 'b' }] });

  it('skips checks that are off for the environment', async () => {
    const r = await runScan(ctx, [sample], { profile: profile('poc'), environmentSource: env, exceptions: [] });
    expect(r.checks[0].status).toBe('SKIPPED');
    expect(r.gate.status).toBe('PASS');
  });

  it('same finding blocks prod but only warns in test', async () => {
    const prod = await runScan(ctx, [sample], { profile: profile('prod'), environmentSource: env, exceptions: [] });
    expect(prod.checks[0]).toMatchObject({ status: 'FAIL', severity: 'critical', resources: { total: 2, passed: 1, failed: 1 } });
    expect(prod.gate.status).toBe('BLOCKED');
    const test = await runScan(ctx, [sample], { profile: profile('test'), environmentSource: env, exceptions: [] });
    expect(test.gate.status).toBe('WARN');
  });

  it('profile overrides replace the built-in severity', async () => {
    const r = await runScan(ctx, [sample], { profile: profile('prod', { 'sample.public-thing': 'low' }), environmentSource: env, exceptions: [] });
    expect(r.checks[0].severity).toBe('low');
    expect(r.gate.status).toBe('PASS');
  });

  it('applies valid exceptions and reports expired ones', async () => {
    const exceptions = validateExceptions(
      { exceptions: [{ check: 'sample.public-thing', resource: 'a', reason: 'accepted', owner: 'team', expires: '2026-12-31' }] },
      'test',
    );
    const r = await runScan(ctx, [sample], { profile: profile('prod'), environmentSource: env, exceptions });
    expect(r.checks[0]).toMatchObject({ status: 'PASS', resources: { failed: 0, excepted: 1 } });
    expect(r.score).toBe(100);

    const expired = validateExceptions({ exceptions: [{ ...exceptions[0], expires: '2026-01-01' }] }, 'test');
    const r2 = await runScan(ctx, [sample], { profile: profile('prod'), environmentSource: env, exceptions: expired });
    expect(r2.checks[0].status).toBe('FAIL');
    expect(r2.warnings.join(' ')).toMatch(/expired/);
  });

  it('reports permission problems as ERROR (never PASS) and marks the gate INCOMPLETE', async () => {
    const denied = fakeContext({ instances: new GcpApiError('PERMISSION_DENIED', 403, 'compute.instances.list denied', 'https://compute.googleapis.com/x') });
    const r = await runScan(denied, [sample], { profile: profile('prod'), environmentSource: env, exceptions: [] });
    expect(r.checks[0].status).toBe('ERROR');
    expect(r.gate.status).toBe('INCOMPLETE');
  });

  it('treats a disabled API as not applicable', async () => {
    const off = fakeContext({ instances: new GcpApiError('API_DISABLED', 403, 'Compute Engine API has not been used', 'https://compute.googleapis.com/x') });
    const r = await runScan(off, [sample], { profile: profile('prod'), environmentSource: env, exceptions: [] });
    expect(r.checks[0].status).toBe('NOT_APPLICABLE');
  });
});

describe('scoring', () => {
  const base = { id: 'x', title: 'x', service: 'iam' as const, category: 'security' as const, cis: [], rationale: '', remediation: '', findings: [] };
  it('weights by severity and partial pass ratio', () => {
    const s = score([
      { ...base, severity: 'critical', status: 'FAIL', resources: { total: 2, passed: 1, failed: 1, excepted: 0 } },
      { ...base, severity: 'low', status: 'PASS', resources: { total: 1, passed: 1, failed: 0, excepted: 0 } },
      { ...base, severity: 'high', status: 'ERROR', resources: { total: 0, passed: 0, failed: 0, excepted: 0 } },
    ]);
    // (10*0.5 + 1*1) / 11
    expect(s).toBe(55);
  });
  it('gate passes when nothing is configured to block', () => {
    expect(gate([], profile('prod')).status).toBe('PASS');
  });
});

describe('shipped configuration', () => {
  it('loads and validates config/', async () => {
    const loaded = await loadConfig(path.resolve(__dirname, '..', 'config'), new Set(ALL_CHECKS.map((c) => c.id)));
    expect(Object.keys(loaded.profiles).sort()).toEqual(['poc', 'prod', 'test']);
    expect(loaded.config.environment.default).toBe('prod');
  });
});
