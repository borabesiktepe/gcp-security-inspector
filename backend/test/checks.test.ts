import { describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../src/checks/index.js';
import { allowsPort } from '../src/checks/vpc.js';
import type { CheckOutcome } from '../src/engine/types.js';
import { fakeContext } from './fakes.js';

const check = (id: string) => {
  const c = ALL_CHECKS.find((x) => x.id === id);
  if (!c) throw new Error(`no check ${id}`);
  return c;
};
const failed = (o: CheckOutcome) => (o.kind === 'evaluated' ? o.resources.filter((r) => r.status === 'FAIL').map((r) => r.resource) : []);

describe('catalog', () => {
  it('every check has a severity for every environment and docs', () => {
    for (const c of ALL_CHECKS) {
      expect(Object.keys(c.severity).sort(), c.id).toEqual(['poc', 'prod', 'test']);
      expect(c.remediation.length, c.id).toBeGreaterThan(10);
    }
  });
  it('prod is never more lenient than poc', () => {
    const rank = { off: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };
    for (const c of ALL_CHECKS) expect(rank[c.severity.prod], c.id).toBeGreaterThanOrEqual(rank[c.severity.poc]);
  });
});

describe('allowsPort', () => {
  it('handles exact ports, ranges, missing ports and protocol all', () => {
    expect(allowsPort({ IPProtocol: 'tcp', ports: ['22'] }, 'tcp', 22)).toBe(true);
    expect(allowsPort({ IPProtocol: 'tcp', ports: ['20-25'] }, 'tcp', 22)).toBe(true);
    expect(allowsPort({ IPProtocol: 'tcp', ports: ['2222'] }, 'tcp', 22)).toBe(false);
    expect(allowsPort({ IPProtocol: 'tcp' }, 'tcp', 22)).toBe(true);
    expect(allowsPort({ IPProtocol: 'all' }, 'udp', 11211)).toBe(true);
    expect(allowsPort({ IPProtocol: 'udp', ports: ['22'] }, 'tcp', 22)).toBe(false);
  });
});

describe('firewall checks', () => {
  const firewalls = [
    { name: 'ssh-range', direction: 'INGRESS' as const, sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['20-30'] }] },
    { name: 'ssh-v6', direction: 'INGRESS' as const, sourceRanges: ['::/0'], allowed: [{ IPProtocol: 'tcp', ports: ['22'] }] },
    { name: 'ssh-disabled', direction: 'INGRESS' as const, disabled: true, sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['22'] }] },
    { name: 'ssh-iap', direction: 'INGRESS' as const, sourceRanges: ['35.235.240.0/20'], allowed: [{ IPProtocol: 'tcp', ports: ['22'] }] },
    { name: 'web', direction: 'INGRESS' as const, sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] },
    { name: 'everything', direction: 'INGRESS' as const, sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'all' }] },
    { name: 'redis', direction: 'INGRESS' as const, sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['6379'] }] },
  ];
  const ctx = fakeContext({ firewalls });

  it('finds SSH exposure through ranges, IPv6 and allow-all; ignores disabled and IAP rules', async () => {
    expect(failed(await check('vpc.firewall.ssh-from-internet').run(ctx)).sort()).toEqual(['everything', 'ssh-range', 'ssh-v6']);
  });
  it('finds allow-all rules', async () => {
    expect(failed(await check('vpc.firewall.all-ports-from-internet').run(ctx))).toEqual(['everything']);
  });
  it('finds data store ports', async () => {
    expect(failed(await check('vpc.firewall.data-ports-from-internet').run(ctx)).sort()).toEqual(['everything', 'redis']);
  });
});

describe('compute checks', () => {
  const instances = [
    { name: 'web-1', zone: 'zones/europe-west1-b', networkInterfaces: [{ accessConfigs: [{ natIP: '34.1.2.3' }] }], metadata: { items: [{ key: 'enable-oslogin', value: 'FALSE' }] } },
    { name: 'app-1', zone: 'zones/europe-west1-b', networkInterfaces: [{}] },
    { name: 'gke-node', zone: 'zones/europe-west1-b', labels: { 'goog-gke-node': '' }, networkInterfaces: [{ accessConfigs: [{ natIP: '34.9.9.9' }] }] },
  ];
  const ctx = fakeContext({
    instances,
    computeProject: { name: 'demo-project', commonInstanceMetadata: { items: [{ key: 'enable-oslogin', value: 'TRUE' }] } },
  });

  it('flags public IPs and skips GKE nodes', async () => {
    expect(failed(await check('compute.vm.public-ip').run(ctx))).toEqual(['europe-west1-b/web-1']);
  });
  it('OS Login: project enabled, instance override to FALSE fails', async () => {
    expect(failed(await check('compute.project.os-login').run(ctx))).toEqual(['europe-west1-b/web-1']);
  });
  it('is not applicable when there are no VMs', async () => {
    const out = await check('compute.vm.public-ip').run(fakeContext({ instances: [] }));
    expect(out.kind).toBe('not_applicable');
  });
});

describe('iam checks', () => {
  const ctx = fakeContext({
    iamPolicy: {
      bindings: [
        { role: 'roles/editor', members: ['serviceAccount:123-compute@developer.gserviceaccount.com', 'user:alice@example.com'] },
        { role: 'roles/viewer', members: ['allAuthenticatedUsers'] },
      ],
    },
    serviceAccounts: [{ email: 'a@demo.iam.gserviceaccount.com' }, { email: 'b@demo.iam.gserviceaccount.com' }],
    serviceAccountKeys: {
      'a@demo.iam.gserviceaccount.com': [{ name: 'keys/old', validAfterTime: '2025-01-01T00:00:00Z' }],
      'b@demo.iam.gserviceaccount.com': [],
    },
  });
  it('flags SA with basic roles', async () => {
    expect(failed(await check('iam.project.basic-roles-service-accounts').run(ctx))).toEqual(['serviceAccount:123-compute@developer.gserviceaccount.com']);
  });
  it('flags public members', async () => {
    expect(failed(await check('iam.project.public-members').run(ctx))).toEqual(['allAuthenticatedUsers']);
  });
  it('flags user-managed keys and old keys', async () => {
    expect(failed(await check('iam.sa.user-managed-keys').run(ctx))).toEqual(['a@demo.iam.gserviceaccount.com']);
    expect(failed(await check('iam.sa.key-rotation').run(ctx))).toEqual(['keys/old']);
  });
});

describe('storage checks', () => {
  const ctx = fakeContext({
    buckets: [
      { name: 'public-assets', iamConfiguration: { publicAccessPrevention: 'inherited', uniformBucketLevelAccess: { enabled: true } } },
      { name: 'private', iamConfiguration: { publicAccessPrevention: 'enforced', uniformBucketLevelAccess: { enabled: true } }, softDeletePolicy: { retentionDurationSeconds: '604800' } },
    ],
    bucketPolicies: {
      'public-assets': { bindings: [{ role: 'roles/storage.objectViewer', members: ['allUsers'] }] },
      private: { bindings: [{ role: 'roles/storage.legacyBucketOwner', members: ['projectOwner:demo-project'] }] },
    },
  });
  it('flags public bucket and missing PAP', async () => {
    expect(failed(await check('storage.bucket.public').run(ctx))).toEqual(['public-assets']);
    expect(failed(await check('storage.bucket.public-access-prevention').run(ctx))).toEqual(['public-assets']);
  });
  it('soft delete counts as data protection; default legacy owner grants are ignored', async () => {
    expect(failed(await check('storage.bucket.versioning').run(ctx))).toEqual(['public-assets']);
    expect(failed(await check('storage.bucket.admin-grants').run(ctx))).toEqual([]);
  });
});

describe('gke checks', () => {
  const ctx = fakeContext({
    clusters: [
      {
        name: 'prod-1',
        location: 'europe-west1',
        privateClusterConfig: { enablePrivateNodes: true },
        masterAuthorizedNetworksConfig: { enabled: true, cidrBlocks: [{ cidrBlock: '0.0.0.0/0' }] },
        nodePools: [{ name: 'default-pool', config: { serviceAccount: 'default' }, management: { autoRepair: true, autoUpgrade: false } }],
      },
    ],
  });
  it('treats 0.0.0.0/0 in authorized networks as unrestricted', async () => {
    expect(failed(await check('gke.cluster.control-plane-access').run(ctx))).toEqual(['europe-west1/prod-1']);
  });
  it('evaluates node pools individually', async () => {
    expect(failed(await check('gke.nodepool.default-service-account').run(ctx))).toEqual(['europe-west1/prod-1/default-pool']);
    expect(failed(await check('gke.nodepool.auto-upgrade').run(ctx))).toEqual(['europe-west1/prod-1/default-pool']);
    expect(failed(await check('gke.nodepool.auto-repair').run(ctx))).toEqual([]);
  });
});
