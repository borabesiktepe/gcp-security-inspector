import { defineCheck, evaluateEach, shortName } from '../engine/helpers.js';
import type { ScanContext } from '../engine/types.js';
import type { FirewallRule } from '../gcp/types.js';

const INTERNET = new Set(['0.0.0.0/0', '::/0']);

/** True when an allowed entry opens `port` for `protocol` (tcp/udp). Handles "all", missing ports and ranges like "20-25". */
export function allowsPort(allowed: { IPProtocol: string; ports?: string[] }, protocol: 'tcp' | 'udp', port: number): boolean {
  const proto = allowed.IPProtocol.toLowerCase();
  if (proto !== 'all' && proto !== protocol) return false;
  if (!allowed.ports || allowed.ports.length === 0) return true;
  return allowed.ports.some((p) => {
    const [lo, hi] = p.split('-').map((n) => Number.parseInt(n, 10));
    return hi === undefined || Number.isNaN(hi) ? lo === port : port >= lo && port <= hi;
  });
}

/** Enabled ingress rules whose source includes the whole internet (IPv4 or IPv6). */
function internetIngress(rules: FirewallRule[]): FirewallRule[] {
  return rules.filter((r) => r.direction !== 'EGRESS' && !r.disabled && (r.sourceRanges ?? []).some((s) => INTERNET.has(s)) && (r.allowed ?? []).length > 0);
}

function evidence(rule: FirewallRule, extra: Record<string, unknown> = {}) {
  return {
    network: shortName(rule.network),
    sourceRanges: (rule.sourceRanges ?? []).filter((s) => INTERNET.has(s)),
    allowed: (rule.allowed ?? []).map((a) => `${a.IPProtocol}:${(a.ports ?? ['all']).join(',')}`),
    targets: rule.targetTags ?? rule.targetServiceAccounts ?? ['all instances in network'],
    ...extra,
  };
}

function portCheck(ctx: ScanContext, ports: { port: number; protocol: 'tcp' | 'udp'; label: string }[]) {
  return ctx.data('firewalls').then((rules) =>
    evaluateEach(
      internetIngress(rules),
      (r) => r.name,
      (r) => {
        const open = ports.filter((p) => (r.allowed ?? []).some((a) => allowsPort(a, p.protocol, p.port)));
        return open.length ? evidence(r, { exposedPorts: open.map((p) => `${p.label} ${p.protocol}/${p.port}`) }) : undefined;
      },
      'No enabled firewall rules allow ingress from 0.0.0.0/0 or ::/0.',
    ),
  );
}

const DATA_PORTS: { port: number; protocol: 'tcp' | 'udp'; label: string }[] = [
  { port: 3306, protocol: 'tcp', label: 'MySQL' },
  { port: 5432, protocol: 'tcp', label: 'PostgreSQL' },
  { port: 1433, protocol: 'tcp', label: 'SQL Server' },
  { port: 1521, protocol: 'tcp', label: 'Oracle' },
  { port: 27017, protocol: 'tcp', label: 'MongoDB' },
  { port: 6379, protocol: 'tcp', label: 'Redis' },
  { port: 11211, protocol: 'tcp', label: 'Memcached' },
  { port: 11211, protocol: 'udp', label: 'Memcached' },
  { port: 9200, protocol: 'tcp', label: 'Elasticsearch' },
  { port: 9042, protocol: 'tcp', label: 'Cassandra' },
];

export const vpcChecks = [
  defineCheck({
    id: 'vpc.firewall.ssh-from-internet',
    title: 'Firewall rules do not allow SSH (22) from the internet',
    service: 'vpc',
    category: 'security',
    cis: ['3.6'],
    severity: { poc: 'medium', test: 'high', prod: 'critical' },
    rationale: 'SSH open to 0.0.0.0/0 is constantly brute-forced. IAP TCP forwarding gives SSH without any public exposure.',
    remediation: 'Restrict the source to 35.235.240.0/20 (IAP) and use `gcloud compute ssh --tunnel-through-iap`, or to known corporate ranges.',
    docs: 'https://cloud.google.com/iap/docs/using-tcp-forwarding',
    run: (ctx) => portCheck(ctx, [{ port: 22, protocol: 'tcp', label: 'SSH' }]),
  }),
  defineCheck({
    id: 'vpc.firewall.rdp-from-internet',
    title: 'Firewall rules do not allow RDP (3389) from the internet',
    service: 'vpc',
    category: 'security',
    cis: ['3.7'],
    severity: { poc: 'medium', test: 'high', prod: 'critical' },
    rationale: 'RDP open to the internet is a top ransomware entry point.',
    remediation: 'Restrict the source to 35.235.240.0/20 (IAP TCP forwarding) or a VPN range.',
    docs: 'https://cloud.google.com/iap/docs/using-tcp-forwarding',
    run: (ctx) => portCheck(ctx, [{ port: 3389, protocol: 'tcp', label: 'RDP' }, { port: 3389, protocol: 'udp', label: 'RDP' }]),
  }),
  defineCheck({
    id: 'vpc.firewall.all-ports-from-internet',
    title: 'Firewall rules do not allow all ports from the internet',
    service: 'vpc',
    category: 'security',
    severity: { poc: 'high', test: 'critical', prod: 'critical' },
    rationale: 'A rule with protocol "all" or the full port range exposes every service on the targeted VMs.',
    remediation: 'Replace the rule with rules that allow only the specific ports the service needs (typically tcp:443 via a load balancer).',
    docs: 'https://cloud.google.com/firewall/docs/using-firewalls',
    async run(ctx) {
      return evaluateEach(
        internetIngress(await ctx.data('firewalls')),
        (r) => r.name,
        (r) => {
          const wide = (r.allowed ?? []).some((a) => {
            const proto = a.IPProtocol.toLowerCase();
            if (proto === 'all') return true;
            if (proto !== 'tcp' && proto !== 'udp') return false;
            if (!a.ports || a.ports.length === 0) return true;
            return a.ports.some((p) => p === '0-65535' || p === '1-65535');
          });
          return wide ? evidence(r) : undefined;
        },
        'No enabled firewall rules allow ingress from 0.0.0.0/0 or ::/0.',
      );
    },
  }),
  defineCheck({
    id: 'vpc.firewall.data-ports-from-internet',
    title: 'Firewall rules do not expose database or cache ports to the internet',
    service: 'vpc',
    category: 'security',
    severity: { poc: 'high', test: 'critical', prod: 'critical' },
    rationale: 'MySQL, PostgreSQL, SQL Server, MongoDB, Redis, Memcached, Elasticsearch etc. should never be reachable from the internet.',
    remediation: 'Remove 0.0.0.0/0 from the rule; reach data stores over private IP, Private Service Connect or the Cloud SQL Auth Proxy.',
    docs: 'https://cloud.google.com/firewall/docs/firewalls',
    run: (ctx) => portCheck(ctx, DATA_PORTS),
  }),
  defineCheck({
    id: 'vpc.network.default-network',
    title: 'The default network does not exist',
    service: 'vpc',
    category: 'security',
    cis: ['3.1'],
    severity: { poc: 'info', test: 'low', prod: 'medium' },
    rationale: 'The default network has auto-created subnets in every region and permissive pre-populated firewall rules (default-allow-ssh/rdp/icmp/internal).',
    remediation: 'Create a custom-mode VPC, move workloads, delete the default network. Enforce compute.skipDefaultNetworkCreation org policy.',
    docs: 'https://cloud.google.com/vpc/docs/vpc#default-network',
    async run(ctx) {
      const networks = await ctx.data('networks');
      const resource = `projects/${ctx.projectId}`;
      const hasDefault = networks.some((n) => n.name === 'default');
      return { kind: 'evaluated', resources: [hasDefault ? { resource: 'default', status: 'FAIL', evidence: { network: 'default' } } : { resource, status: 'PASS' }] };
    },
  }),
  defineCheck({
    id: 'vpc.network.legacy',
    title: 'No legacy (non-subnet) networks exist',
    service: 'vpc',
    category: 'security',
    cis: ['3.2'],
    severity: { poc: 'medium', test: 'high', prod: 'high' },
    rationale: 'Legacy networks have a single global IP range, no subnet-level controls and no flow logs.',
    remediation: 'Migrate to a VPC network with subnets and delete the legacy network.',
    docs: 'https://cloud.google.com/vpc/docs/legacy',
    async run(ctx) {
      return evaluateEach(await ctx.data('networks'), (n) => n.name, (n) => (n.IPv4Range ? { IPv4Range: n.IPv4Range } : undefined), 'No VPC networks in this project.');
    },
  }),
  defineCheck({
    id: 'vpc.subnet.flow-logs',
    title: 'VPC Flow Logs are enabled on subnets',
    service: 'vpc',
    category: 'security',
    cis: ['3.8'],
    severity: { poc: 'off', test: 'low', prod: 'medium' },
    rationale: 'Flow logs are needed for incident investigation and network forensics.',
    remediation: 'gcloud compute networks subnets update SUBNET --region=REGION --enable-flow-logs (tune sampling to control cost).',
    docs: 'https://cloud.google.com/vpc/docs/using-flow-logs',
    async run(ctx) {
      const subnets = (await ctx.data('subnetworks')).filter((s) => !s.purpose || s.purpose === 'PRIVATE');
      return evaluateEach(subnets, (s) => `${shortName(s.region)}/${s.name}`, (s) => (s.logConfig?.enable ? undefined : { flowLogs: false, network: shortName(s.network) }), 'No regular subnets in this project.');
    },
  }),
  defineCheck({
    id: 'vpc.subnet.private-google-access',
    title: 'Private Google Access is enabled on subnets',
    service: 'vpc',
    category: 'security',
    severity: { poc: 'off', test: 'info', prod: 'low' },
    rationale: 'Lets VMs without external IPs reach Google APIs, removing a common reason to give VMs public IPs.',
    remediation: 'gcloud compute networks subnets update SUBNET --region=REGION --enable-private-ip-google-access',
    docs: 'https://cloud.google.com/vpc/docs/configure-private-google-access',
    async run(ctx) {
      const subnets = (await ctx.data('subnetworks')).filter((s) => !s.purpose || s.purpose === 'PRIVATE');
      return evaluateEach(subnets, (s) => `${shortName(s.region)}/${s.name}`, (s) => (s.privateIpGoogleAccess ? undefined : { privateIpGoogleAccess: false }), 'No regular subnets in this project.');
    },
  }),
  defineCheck({
    id: 'vpc.address.unused-external',
    title: 'No reserved external IP addresses are left unused',
    service: 'vpc',
    category: 'cost',
    severity: { poc: 'off', test: 'info', prod: 'low' },
    rationale: 'Unused static external IPs are billed and often point at forgotten DNS records (subdomain takeover risk).',
    remediation: 'gcloud compute addresses delete NAME --region=REGION (check DNS first).',
    docs: 'https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address#release_ip',
    async run(ctx) {
      const external = (await ctx.data('addresses')).filter((a) => a.addressType !== 'INTERNAL');
      return evaluateEach(external, (a) => `${shortName(a.region) || 'global'}/${a.name}`, (a) => (a.status === 'RESERVED' && !(a.users ?? []).length ? { status: a.status } : undefined), 'No reserved external IP addresses.');
    },
  }),
  defineCheck({
    id: 'vpc.address.unused-internal',
    title: 'No reserved internal IP addresses are left unused',
    service: 'vpc',
    category: 'cost',
    severity: { poc: 'off', test: 'off', prod: 'info' },
    rationale: 'Unused internal reservations clutter IP planning.',
    remediation: 'Release addresses that are no longer needed.',
    docs: 'https://cloud.google.com/compute/docs/ip-addresses/reserve-static-internal-ip-address',
    async run(ctx) {
      const internal = (await ctx.data('addresses')).filter((a) => a.addressType === 'INTERNAL' && (!a.purpose || a.purpose === 'GCE_ENDPOINT'));
      return evaluateEach(internal, (a) => `${shortName(a.region) || 'global'}/${a.name}`, (a) => (a.status === 'RESERVED' && !(a.users ?? []).length ? { status: a.status } : undefined), 'No reserved internal IP addresses.');
    },
  }),
];
