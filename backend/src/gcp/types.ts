/* Minimal shapes of the GCP REST resources the checks read. Fields are optional on purpose. */

export interface IamBinding { role: string; members?: string[]; condition?: { title?: string; expression?: string } }
export interface AuditLogConfig { logType: 'ADMIN_READ' | 'DATA_READ' | 'DATA_WRITE'; exemptedMembers?: string[] }
export interface IamPolicy {
  bindings?: IamBinding[];
  auditConfigs?: { service: string; auditLogConfigs?: AuditLogConfig[] }[];
}

export interface Project {
  name?: string; // "projects/123"
  projectId: string;
  displayName?: string;
  parent?: string; // "folders/123" | "organizations/123"
  labels?: Record<string, string>;
  state?: string;
}

export interface MetadataItems { items?: { key: string; value?: string }[] }

export interface ComputeProject { name: string; commonInstanceMetadata?: MetadataItems }

export interface Instance {
  name: string;
  zone?: string;
  status?: string;
  labels?: Record<string, string>;
  canIpForward?: boolean;
  deletionProtection?: boolean;
  metadata?: MetadataItems;
  networkInterfaces?: {
    network?: string;
    accessConfigs?: { natIP?: string; type?: string }[];
    ipv6AccessConfigs?: { externalIpv6?: string }[];
  }[];
  disks?: { boot?: boolean; source?: string }[];
  serviceAccounts?: { email: string; scopes?: string[] }[];
  scheduling?: { onHostMaintenance?: string; automaticRestart?: boolean; preemptible?: boolean; provisioningModel?: string };
  shieldedInstanceConfig?: { enableSecureBoot?: boolean; enableVtpm?: boolean; enableIntegrityMonitoring?: boolean };
  confidentialInstanceConfig?: { enableConfidentialCompute?: boolean; confidentialInstanceType?: string };
}

export interface Disk { name: string; selfLink: string; sourceImage?: string }

export interface FirewallRule {
  name: string;
  network?: string;
  direction?: 'INGRESS' | 'EGRESS';
  disabled?: boolean;
  sourceRanges?: string[];
  allowed?: { IPProtocol: string; ports?: string[] }[];
  targetTags?: string[];
  targetServiceAccounts?: string[];
}

export interface Network { name: string; IPv4Range?: string; autoCreateSubnetworks?: boolean; subnetworks?: string[] }

export interface Subnetwork {
  name: string;
  region?: string;
  network?: string;
  purpose?: string;
  privateIpGoogleAccess?: boolean;
  logConfig?: { enable?: boolean };
}

export interface Address { name: string; region?: string; addressType?: 'EXTERNAL' | 'INTERNAL'; status?: string; users?: string[]; purpose?: string }

export interface Bucket {
  name: string;
  location?: string;
  iamConfiguration?: {
    uniformBucketLevelAccess?: { enabled?: boolean };
    publicAccessPrevention?: 'enforced' | 'inherited' | 'unspecified';
  };
  versioning?: { enabled?: boolean };
  softDeletePolicy?: { retentionDurationSeconds?: string };
  lifecycle?: { rule?: unknown[] };
  logging?: { logBucket?: string };
  website?: { mainPageSuffix?: string; notFoundPage?: string };
  cors?: { origin?: string[]; method?: string[] }[];
  labels?: Record<string, string>;
}

export interface GkeNodePool {
  name: string;
  config?: {
    serviceAccount?: string;
    imageType?: string;
    workloadMetadataConfig?: { mode?: string };
    shieldedInstanceConfig?: { enableSecureBoot?: boolean; enableIntegrityMonitoring?: boolean };
  };
  management?: { autoRepair?: boolean; autoUpgrade?: boolean };
}

export interface GkeCluster {
  name: string;
  location?: string;
  resourceLabels?: Record<string, string>;
  masterAuth?: { username?: string; clientCertificateConfig?: { issueClientCertificate?: boolean } };
  legacyAbac?: { enabled?: boolean };
  addonsConfig?: { kubernetesDashboard?: { disabled?: boolean } };
  privateClusterConfig?: { enablePrivateNodes?: boolean; enablePrivateEndpoint?: boolean };
  networkConfig?: { defaultEnablePrivateNodes?: boolean; datapathProvider?: string; enableIntraNodeVisibility?: boolean };
  masterAuthorizedNetworksConfig?: { enabled?: boolean; cidrBlocks?: { cidrBlock: string }[] };
  workloadIdentityConfig?: { workloadPool?: string };
  shieldedNodes?: { enabled?: boolean };
  releaseChannel?: { channel?: string };
  binaryAuthorization?: { enabled?: boolean; evaluationMode?: string };
  ipAllocationPolicy?: { useIpAliases?: boolean };
  networkPolicy?: { enabled?: boolean };
  loggingService?: string;
  monitoringService?: string;
  costManagementConfig?: { enabled?: boolean };
  nodePools?: GkeNodePool[];
}

export interface ServiceAccount { email: string; disabled?: boolean; displayName?: string }
export interface ServiceAccountKey { name: string; validAfterTime?: string; keyType?: string; disabled?: boolean }

export interface Collectors {
  project: Project;
  iamPolicy: IamPolicy;
  computeProject: ComputeProject;
  instances: Instance[];
  disks: Disk[];
  firewalls: FirewallRule[];
  networks: Network[];
  subnetworks: Subnetwork[];
  addresses: Address[];
  buckets: Bucket[];
  bucketPolicies: Record<string, IamPolicy>;
  clusters: GkeCluster[];
  serviceAccounts: ServiceAccount[];
  serviceAccountKeys: Record<string, ServiceAccountKey[]>;
}
