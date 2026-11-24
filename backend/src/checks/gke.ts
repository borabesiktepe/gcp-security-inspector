import { defineCheck, evaluateEach } from '../engine/helpers.js';
import type { CheckDefinition, ScanContext, Severity, Environment, Category } from '../engine/types.js';
import type { GkeCluster, GkeNodePool } from '../gcp/types.js';

const NO_CLUSTERS = 'No GKE clusters in this project.';
const clusterName = (c: GkeCluster) => `${c.location ?? '-'}/${c.name}`;

async function nodePools(ctx: ScanContext): Promise<{ cluster: GkeCluster; pool: GkeNodePool }[]> {
  return (await ctx.data('clusters')).flatMap((cluster) => (cluster.nodePools ?? []).map((pool) => ({ cluster, pool })));
}

interface Spec {
  id: string;
  title: string;
  cis?: string[];
  category?: Category;
  severity: Record<Environment, Severity>;
  rationale: string;
  remediation: string;
  docs: string;
}

function clusterCheck(spec: Spec, violation: (c: GkeCluster) => Record<string, unknown> | undefined): CheckDefinition {
  return defineCheck({
    ...spec,
    service: 'gke',
    category: spec.category ?? 'security',
    async run(ctx) {
      return evaluateEach(await ctx.data('clusters'), clusterName, violation, NO_CLUSTERS);
    },
  });
}

function poolCheck(spec: Spec, violation: (p: GkeNodePool) => Record<string, unknown> | undefined): CheckDefinition {
  return defineCheck({
    ...spec,
    service: 'gke',
    category: spec.category ?? 'security',
    async run(ctx) {
      return evaluateEach(await nodePools(ctx), ({ cluster, pool }) => `${clusterName(cluster)}/${pool.name}`, ({ pool }) => violation(pool), NO_CLUSTERS);
    },
  });
}

const DOCS_HARDENING = 'https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster';

export const gkeChecks = [
  clusterCheck(
    {
      id: 'gke.cluster.legacy-abac',
      title: 'Legacy ABAC authorization is disabled',
      cis: ['GKE 5.8.4'],
      severity: { poc: 'high', test: 'critical', prod: 'critical' },
      rationale: 'Legacy ABAC grants broad, static permissions and bypasses Kubernetes RBAC.',
      remediation: 'gcloud container clusters update CLUSTER --no-enable-legacy-authorization',
      docs: `${DOCS_HARDENING}#leave_abac_disabled_default_for_110`,
    },
    (c) => (c.legacyAbac?.enabled ? { legacyAbac: true } : undefined),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.legacy-credentials',
      title: 'Basic authentication and client certificates are disabled',
      cis: ['GKE 5.8.1'],
      severity: { poc: 'medium', test: 'high', prod: 'high' },
      rationale: 'Static passwords and client certificates cannot be revoked easily. Use IAM / Google identities.',
      remediation: 'Recreate the cluster without --issue-client-certificate; basic auth is removed in current GKE versions.',
      docs: `${DOCS_HARDENING}#restrict_authn_methods`,
    },
    (c) => {
      const basic = !!c.masterAuth?.username;
      const cert = !!c.masterAuth?.clientCertificateConfig?.issueClientCertificate;
      return basic || cert ? { basicAuth: basic, clientCertificate: cert } : undefined;
    },
  ),
  clusterCheck(
    {
      id: 'gke.cluster.dashboard',
      title: 'Kubernetes Dashboard add-on is disabled',
      severity: { poc: 'medium', test: 'high', prod: 'high' },
      rationale: 'The legacy dashboard add-on has been abused for cluster takeover; use the Cloud Console instead.',
      remediation: 'gcloud container clusters update CLUSTER --update-addons=KubernetesDashboard=DISABLED',
      docs: DOCS_HARDENING,
    },
    (c) => (c.addonsConfig?.kubernetesDashboard && c.addonsConfig.kubernetesDashboard.disabled === false ? { kubernetesDashboard: 'enabled' } : undefined),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.private-nodes',
      title: 'Cluster nodes have private IPs only',
      cis: ['GKE 5.6.5'],
      severity: { poc: 'info', test: 'medium', prod: 'high' },
      rationale: 'Nodes with public IPs are directly reachable from the internet.',
      remediation: 'Enable private nodes (new node pools: --enable-private-nodes) and use Cloud NAT for egress.',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/legacy/network-isolation',
    },
    (c) => (c.privateClusterConfig?.enablePrivateNodes || c.networkConfig?.defaultEnablePrivateNodes ? undefined : { privateNodes: false }),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.control-plane-access',
      title: 'Control plane access is restricted (authorized networks or private endpoint)',
      cis: ['GKE 5.6.3'],
      severity: { poc: 'low', test: 'medium', prod: 'high' },
      rationale: 'A control plane reachable from any IP is exposed to credential stuffing and to future Kubernetes API vulnerabilities.',
      remediation: 'Enable master authorized networks with specific CIDRs, or use the private endpoint / DNS-based endpoint with IAM.',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks',
    },
    (c) => {
      if (c.privateClusterConfig?.enablePrivateEndpoint) return undefined;
      const man = c.masterAuthorizedNetworksConfig;
      if (!man?.enabled) return { masterAuthorizedNetworks: false };
      const open = (man.cidrBlocks ?? []).filter((b) => b.cidrBlock === '0.0.0.0/0');
      return open.length ? { masterAuthorizedNetworks: 'includes 0.0.0.0/0' } : undefined;
    },
  ),
  clusterCheck(
    {
      id: 'gke.cluster.workload-identity',
      title: 'Workload Identity Federation for GKE is enabled',
      cis: ['GKE 5.2.2'],
      severity: { poc: 'low', test: 'medium', prod: 'high' },
      rationale: 'Pods get their own IAM identity instead of sharing the node service account, and keys are not needed.',
      remediation: 'gcloud container clusters update CLUSTER --workload-pool=PROJECT_ID.svc.id.goog, then migrate node pools to GKE_METADATA.',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity',
    },
    (c) => (c.workloadIdentityConfig?.workloadPool ? undefined : { workloadIdentity: false }),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.shielded-nodes',
      title: 'Shielded GKE nodes are enabled',
      cis: ['GKE 5.5.5'],
      severity: { poc: 'info', test: 'medium', prod: 'high' },
      rationale: 'Shielded nodes give verifiable node identity and prevent node impersonation by a compromised pod.',
      remediation: 'gcloud container clusters update CLUSTER --enable-shielded-nodes',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes',
    },
    (c) => (c.shieldedNodes?.enabled ? undefined : { shieldedNodes: false }),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.release-channel',
      title: 'Cluster is enrolled in a release channel',
      cis: ['GKE 5.5.4'],
      category: 'reliability',
      severity: { poc: 'info', test: 'low', prod: 'medium' },
      rationale: 'Release channels keep control plane and nodes on supported, patched versions automatically.',
      remediation: 'gcloud container clusters update CLUSTER --release-channel=regular',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/concepts/release-channels',
    },
    (c) => (c.releaseChannel?.channel && c.releaseChannel.channel !== 'UNSPECIFIED' ? undefined : { releaseChannel: 'none' }),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.network-policy',
      title: 'Network policy enforcement is enabled (or GKE Dataplane V2)',
      cis: ['GKE 5.6.7'],
      severity: { poc: 'info', test: 'low', prod: 'medium' },
      rationale: 'Without network policy enforcement every pod can talk to every other pod.',
      remediation: 'Use GKE Dataplane V2 for new clusters, or enable network policy enforcement, then add NetworkPolicy objects.',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy',
    },
    (c) => (c.networkPolicy?.enabled || c.networkConfig?.datapathProvider === 'ADVANCED_DATAPATH' ? undefined : { networkPolicy: false, datapath: c.networkConfig?.datapathProvider ?? 'LEGACY' }),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.binary-authorization',
      title: 'Binary Authorization is enabled',
      cis: ['GKE 5.10.5'],
      severity: { poc: 'off', test: 'low', prod: 'medium' },
      rationale: 'Ensures only trusted, attested container images are deployed.',
      remediation: 'gcloud container clusters update CLUSTER --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE',
      docs: 'https://cloud.google.com/binary-authorization/docs/setting-up',
    },
    (c) => {
      const mode = c.binaryAuthorization?.evaluationMode;
      return (mode && mode !== 'DISABLED' && mode !== 'EVALUATION_MODE_UNSPECIFIED') || c.binaryAuthorization?.enabled ? undefined : { binaryAuthorization: mode ?? 'DISABLED' };
    },
  ),
  clusterCheck(
    {
      id: 'gke.cluster.vpc-native',
      title: 'Cluster is VPC-native (alias IPs)',
      cis: ['GKE 5.6.2'],
      severity: { poc: 'low', test: 'medium', prod: 'medium' },
      rationale: 'VPC-native clusters get anti-spoofing checks, firewall rules for pod IPs and Private Service Connect support.',
      remediation: 'Recreate the cluster with --enable-ip-alias (cannot be changed in place).',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/concepts/alias-ips',
    },
    (c) => (c.ipAllocationPolicy?.useIpAliases ? undefined : { vpcNative: false }),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.logging',
      title: 'Cloud Logging is enabled for the cluster',
      cis: ['GKE 5.7.1'],
      severity: { poc: 'low', test: 'medium', prod: 'high' },
      rationale: 'Control plane and workload logs are required for audit and incident response.',
      remediation: 'gcloud container clusters update CLUSTER --logging=SYSTEM,WORKLOAD',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/config-logging-monitoring',
    },
    (c) => (c.loggingService && c.loggingService !== 'none' ? undefined : { loggingService: c.loggingService ?? 'none' }),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.monitoring',
      title: 'Cloud Monitoring is enabled for the cluster',
      category: 'operations',
      severity: { poc: 'low', test: 'medium', prod: 'medium' },
      rationale: 'Metrics are needed to detect resource exhaustion and abnormal behaviour.',
      remediation: 'gcloud container clusters update CLUSTER --monitoring=SYSTEM',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/config-logging-monitoring',
    },
    (c) => (c.monitoringService && c.monitoringService !== 'none' ? undefined : { monitoringService: c.monitoringService ?? 'none' }),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.intranode-visibility',
      title: 'Intranode visibility is enabled',
      severity: { poc: 'off', test: 'info', prod: 'low' },
      rationale: 'Makes pod-to-pod traffic on the same node visible to VPC Flow Logs and firewall rules.',
      remediation: 'gcloud container clusters update CLUSTER --enable-intra-node-visibility',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/intranode-visibility',
    },
    (c) => (c.networkConfig?.enableIntraNodeVisibility ? undefined : { intraNodeVisibility: false }),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.cost-allocation',
      title: 'GKE cost allocation is enabled',
      category: 'cost',
      severity: { poc: 'off', test: 'off', prod: 'info' },
      rationale: 'Breaks down cluster cost by namespace and label in billing export.',
      remediation: 'gcloud container clusters update CLUSTER --enable-cost-allocation',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/cost-allocations',
    },
    (c) => (c.costManagementConfig?.enabled ? undefined : { costAllocation: false }),
  ),
  clusterCheck(
    {
      id: 'gke.cluster.labels',
      title: 'Cluster has resource labels',
      category: 'operations',
      severity: { poc: 'off', test: 'info', prod: 'low' },
      rationale: 'Labels (owner, environment, cost-center) drive ownership, billing and policy.',
      remediation: 'gcloud container clusters update CLUSTER --update-labels=owner=TEAM,environment=prod',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/creating-managing-labels',
    },
    (c) => (Object.keys(c.resourceLabels ?? {}).some((k) => !k.startsWith('goog-')) ? undefined : { labels: 0 }),
  ),
  poolCheck(
    {
      id: 'gke.nodepool.metadata-server',
      title: 'Node pools use the GKE metadata server',
      cis: ['GKE 5.4.2'],
      severity: { poc: 'low', test: 'medium', prod: 'high' },
      rationale: 'Hides node credentials and the kubelet bootstrap credentials from pods.',
      remediation: 'gcloud container node-pools update POOL --cluster=CLUSTER --workload-metadata=GKE_METADATA',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity',
    },
    (p) => (p.config?.workloadMetadataConfig?.mode === 'GKE_METADATA' ? undefined : { workloadMetadataMode: p.config?.workloadMetadataConfig?.mode ?? 'unset' }),
  ),
  poolCheck(
    {
      id: 'gke.nodepool.default-service-account',
      title: 'Node pools do not use the default Compute Engine service account',
      cis: ['GKE 5.2.1'],
      severity: { poc: 'low', test: 'medium', prod: 'high' },
      rationale: 'The default service account usually has Editor. Nodes should run as a minimal service account (logging/monitoring writer, artifact reader).',
      remediation: 'Create a least-privilege node SA and new node pools with --service-account=SA.',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/service-accounts#default-gke-service-agent',
    },
    (p) => {
      const sa = p.config?.serviceAccount;
      return !sa || sa === 'default' || sa.endsWith('-compute@developer.gserviceaccount.com') ? { serviceAccount: sa || 'default' } : undefined;
    },
  ),
  poolCheck(
    {
      id: 'gke.nodepool.secure-boot',
      title: 'Node pools have Secure Boot enabled',
      cis: ['GKE 5.5.7'],
      severity: { poc: 'info', test: 'low', prod: 'medium' },
      rationale: 'Protects nodes against boot-level rootkits.',
      remediation: 'Create node pools with --shielded-secure-boot.',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes#secure_boot',
    },
    (p) => (p.config?.shieldedInstanceConfig?.enableSecureBoot ? undefined : { secureBoot: false }),
  ),
  poolCheck(
    {
      id: 'gke.nodepool.integrity-monitoring',
      title: 'Node pools have integrity monitoring enabled',
      cis: ['GKE 5.5.6'],
      severity: { poc: 'info', test: 'low', prod: 'medium' },
      rationale: 'Detects changes to the node boot sequence.',
      remediation: 'Create node pools with --shielded-integrity-monitoring.',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes',
    },
    (p) => (p.config?.shieldedInstanceConfig?.enableIntegrityMonitoring ? undefined : { integrityMonitoring: false }),
  ),
  poolCheck(
    {
      id: 'gke.nodepool.cos-image',
      title: 'Node pools use Container-Optimized OS with containerd',
      cis: ['GKE 5.5.1'],
      severity: { poc: 'info', test: 'low', prod: 'low' },
      rationale: 'COS is a minimal, hardened, auto-updated OS built for running containers.',
      remediation: 'Create node pools with --image-type=COS_CONTAINERD.',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/concepts/node-images',
    },
    (p) => (p.config?.imageType?.toUpperCase().startsWith('COS_CONTAINERD') ? undefined : { imageType: p.config?.imageType ?? 'unknown' }),
  ),
  poolCheck(
    {
      id: 'gke.nodepool.auto-repair',
      title: 'Node auto-repair is enabled',
      cis: ['GKE 5.5.2'],
      category: 'reliability',
      severity: { poc: 'info', test: 'medium', prod: 'high' },
      rationale: 'Unhealthy nodes are recreated automatically.',
      remediation: 'gcloud container node-pools update POOL --cluster=CLUSTER --enable-autorepair',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-repair',
    },
    (p) => (p.management?.autoRepair ? undefined : { autoRepair: false }),
  ),
  poolCheck(
    {
      id: 'gke.nodepool.auto-upgrade',
      title: 'Node auto-upgrade is enabled',
      cis: ['GKE 5.5.3'],
      severity: { poc: 'info', test: 'medium', prod: 'high' },
      rationale: 'Nodes receive security patches without manual work.',
      remediation: 'gcloud container node-pools update POOL --cluster=CLUSTER --enable-autoupgrade',
      docs: 'https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-upgrades',
    },
    (p) => (p.management?.autoUpgrade ? undefined : { autoUpgrade: false }),
  ),
];
