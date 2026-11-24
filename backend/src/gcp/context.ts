import type { InspectorConfig, ScanContext } from '../engine/types.js';
import { GcpClient, mapLimit } from './client.js';
import type * as T from './types.js';

const CRM = 'https://cloudresourcemanager.googleapis.com';
const COMPUTE = 'https://compute.googleapis.com/compute/v1';
const STORAGE = 'https://storage.googleapis.com/storage/v1';
const CONTAINER = 'https://container.googleapis.com/v1';
const IAM = 'https://iam.googleapis.com/v1';

type Fetchers = { [K in keyof T.Collectors]: () => Promise<T.Collectors[K]> };

/** ScanContext backed by live, read-only GCP REST calls. Each dataset is fetched at most once per scan. */
export class GcpScanContext implements ScanContext {
  private readonly cache = new Map<keyof T.Collectors, Promise<unknown>>();
  private readonly fetchers: Fetchers;

  constructor(
    private readonly gcp: GcpClient,
    public readonly projectId: string,
    public readonly config: InspectorConfig,
    public readonly now: Date = new Date(),
  ) {
    const p = encodeURIComponent(projectId);
    this.fetchers = {
      project: () => gcp.request<T.Project>(`${CRM}/v3/projects/${p}`),
      iamPolicy: () =>
        gcp.request<T.IamPolicy>(`${CRM}/v1/projects/${p}:getIamPolicy`, {
          method: 'POST',
          body: { options: { requestedPolicyVersion: 3 } },
        }),
      computeProject: () => gcp.request<T.ComputeProject>(`${COMPUTE}/projects/${p}`),
      instances: () => gcp.listAggregated<T.Instance>(`${COMPUTE}/projects/${p}/aggregated/instances`, 'instances'),
      disks: () => gcp.listAggregated<T.Disk>(`${COMPUTE}/projects/${p}/aggregated/disks`, 'disks'),
      firewalls: () => gcp.listAll<T.FirewallRule>(`${COMPUTE}/projects/${p}/global/firewalls`, 'items'),
      networks: () => gcp.listAll<T.Network>(`${COMPUTE}/projects/${p}/global/networks`, 'items'),
      subnetworks: () => gcp.listAggregated<T.Subnetwork>(`${COMPUTE}/projects/${p}/aggregated/subnetworks`, 'subnetworks'),
      addresses: () => gcp.listAggregated<T.Address>(`${COMPUTE}/projects/${p}/aggregated/addresses`, 'addresses'),
      buckets: () => gcp.listAll<T.Bucket>(`${STORAGE}/b`, 'items', { project: projectId }),
      bucketPolicies: async () => {
        const buckets = await this.data('buckets');
        const policies = await mapLimit(buckets, 8, (b) =>
          gcp.request<T.IamPolicy>(`${STORAGE}/b/${encodeURIComponent(b.name)}/iam`, { params: { optionsRequestedPolicyVersion: '3' } }),
        );
        return Object.fromEntries(buckets.map((b, i) => [b.name, policies[i]]));
      },
      clusters: async () =>
        (await gcp.request<{ clusters?: T.GkeCluster[] }>(`${CONTAINER}/projects/${p}/locations/-/clusters`)).clusters ?? [],
      serviceAccounts: () => gcp.listAll<T.ServiceAccount>(`${IAM}/projects/${p}/serviceAccounts`, 'accounts'),
      serviceAccountKeys: async () => {
        const accounts = await this.data('serviceAccounts');
        const keys = await mapLimit(accounts, 8, async (sa) =>
          (
            await gcp.request<{ keys?: T.ServiceAccountKey[] }>(
              `${IAM}/projects/${p}/serviceAccounts/${encodeURIComponent(sa.email)}/keys`,
              { params: { keyTypes: 'USER_MANAGED' } },
            )
          ).keys ?? [],
        );
        return Object.fromEntries(accounts.map((sa, i) => [sa.email, keys[i]]));
      },
    };
  }

  data<K extends keyof T.Collectors>(key: K): Promise<T.Collectors[K]> {
    let pending = this.cache.get(key) as Promise<T.Collectors[K]> | undefined;
    if (!pending) {
      pending = this.fetchers[key]() as Promise<T.Collectors[K]>;
      this.cache.set(key, pending);
    }
    return pending;
  }
}
