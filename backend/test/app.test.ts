import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { ALL_CHECKS } from '../src/checks/index.js';
import { loadConfig } from '../src/config/load.js';
import { GcpApiError, GcpClient } from '../src/gcp/client.js';

/** Routes REST calls to fixture data. Unknown URLs behave like a disabled API. */
class FixtureGcp extends GcpClient {
  constructor(private readonly routes: Record<string, unknown>) {
    super({} as never);
  }
  private lookup(url: string): unknown {
    for (const [suffix, value] of Object.entries(this.routes)) if (url.endsWith(suffix)) return value;
    throw new GcpApiError('API_DISABLED', 403, `API disabled for ${url}`, url);
  }
  override async request<T>(url: string): Promise<T> {
    const v = this.lookup(url);
    if (v instanceof Error) throw v;
    return v as T;
  }
  override async listAll<T>(url: string): Promise<T[]> {
    return (await this.request<T[]>(url)) ?? [];
  }
  override async listAggregated<T>(url: string): Promise<T[]> {
    return this.listAll<T>(url);
  }
  override async identity() {
    return { principal: 'scanner@demo.iam.gserviceaccount.com' };
  }
}

let base = '';
let close: () => void;

beforeAll(async () => {
  const loaded = await loadConfig(path.resolve(__dirname, '..', 'config'), new Set(ALL_CHECKS.map((c) => c.id)));
  const gcp = new FixtureGcp({
    '/v3/projects/poc-project-1': { projectId: 'poc-project-1', displayName: 'POC', labels: { environment: 'sandbox' } },
    '/v1/projects/poc-project-1:getIamPolicy': { bindings: [{ role: 'roles/owner', members: ['user:alice@example.com'] }] },
    '/compute/v1/projects/poc-project-1': { name: 'poc-project-1' },
    '/aggregated/instances': [{ name: 'vm-1', zone: 'zones/europe-west1-b', networkInterfaces: [{ accessConfigs: [{ natIP: '34.1.1.1' }] }] }],
    '/aggregated/disks': [],
    '/global/firewalls': [{ name: 'default-allow-ssh', direction: 'INGRESS', sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['22'] }] }],
    '/global/networks': [{ name: 'default' }],
    '/aggregated/subnetworks': [],
    '/aggregated/addresses': [],
    '/storage/v1/b': [],
    '/serviceAccounts': [],
  });
  const server = createApp({ loaded, gcp }).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  close = () => server.close();
});
afterAll(() => close());

const post = (body: unknown) => fetch(`${base}/api/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

describe('API', () => {
  it('rejects invalid project ids', async () => {
    expect((await post({ projectId: '../../etc' })).status).toBe(400);
    expect((await post({ projectId: 'poc-project-1', environment: 'qa' })).status).toBe(400);
  });

  it('detects POC from the project label and scans', async () => {
    const res = await post({ projectId: 'poc-project-1' });
    expect(res.status).toBe(201);
    const report = await res.json();
    expect(report.environment).toBe('poc');
    expect(report.environmentSource.source).toBe('label');
    const ssh = report.checks.find((c: { id: string }) => c.id === 'vpc.firewall.ssh-from-internet');
    expect(ssh).toMatchObject({ status: 'FAIL', severity: 'medium' });
    expect(report.checks.find((c: { id: string }) => c.id === 'gke.cluster.legacy-abac').status).toBe('NOT_APPLICABLE');
    expect(report.gate.status).toBe('PASS');
  });

  it('the same project reviewed as prod is blocked', async () => {
    const report = await (await post({ projectId: 'poc-project-1', environment: 'prod' })).json();
    expect(report.gate.status).toBe('BLOCKED');
    expect(report.gate.reasons.join('\n')).toMatch(/SSH/);
    const stored = await (await fetch(`${base}/api/scans/${report.id}`)).json();
    expect(stored.id).toBe(report.id);
  });

  it('serves the catalog with per-environment severities', async () => {
    const catalog = await (await fetch(`${base}/api/catalog`)).json();
    expect(catalog.checks.length).toBe(ALL_CHECKS.length);
    expect(catalog.checks.find((c: { id: string }) => c.id === 'vpc.firewall.ssh-from-internet').severity).toEqual({ poc: 'medium', test: 'high', prod: 'critical' });
  });
});
