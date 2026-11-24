import { defineCheck, evaluateEach, isFalse, isTrue, metadataValue, shortName } from '../engine/helpers.js';
import type { ScanContext } from '../engine/types.js';
import type { Instance } from '../gcp/types.js';

const NO_VMS = 'No VM instances in this project.';

/** GKE nodes are managed through GKE; their settings are checked by the GKE checks instead. */
function isGkeNode(vm: Instance): boolean {
  return !!vm.labels && ('goog-gke-node' in vm.labels || 'goog-k8s-cluster-name' in vm.labels);
}

async function vms(ctx: ScanContext): Promise<Instance[]> {
  return (await ctx.data('instances')).filter((vm) => !isGkeNode(vm));
}

const vmName = (vm: Instance) => `${shortName(vm.zone)}/${vm.name}`;
const isDefaultComputeSa = (email: string) => email.endsWith('-compute@developer.gserviceaccount.com');

export const computeChecks = [
  defineCheck({
    id: 'compute.vm.public-ip',
    title: 'VM instances do not have external IP addresses',
    service: 'compute',
    category: 'security',
    cis: ['4.9'],
    severity: { poc: 'info', test: 'medium', prod: 'high' },
    rationale: 'An external IP exposes the VM directly to the internet. Use Cloud NAT for egress and IAP TCP forwarding or a load balancer for ingress.',
    remediation: 'Remove the access config (gcloud compute instances delete-access-config VM --access-config-name="External NAT") and enforce the compute.vmExternalIpAccess org policy.',
    docs: 'https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address#disableexternalip',
    async run(ctx) {
      return evaluateEach(await vms(ctx), vmName, (vm) => {
        const ipv4 = (vm.networkInterfaces ?? []).flatMap((n) => n.accessConfigs ?? []).map((a) => a.natIP).filter(Boolean);
        const ipv6 = (vm.networkInterfaces ?? []).flatMap((n) => n.ipv6AccessConfigs ?? []).map((a) => a.externalIpv6).filter(Boolean);
        const hasExternal = (vm.networkInterfaces ?? []).some((n) => (n.accessConfigs ?? []).length > 0 || (n.ipv6AccessConfigs ?? []).length > 0);
        return hasExternal ? { externalIpv4: ipv4, externalIpv6: ipv6 } : undefined;
      }, NO_VMS);
    },
  }),
  defineCheck({
    id: 'compute.vm.default-service-account',
    title: 'VM instances do not use the default Compute Engine service account',
    service: 'compute',
    category: 'security',
    cis: ['4.1'],
    severity: { poc: 'low', test: 'medium', prod: 'high' },
    rationale: 'The default service account is shared by every VM and often holds Editor on the project.',
    remediation: 'Create a dedicated service account per workload with only the roles it needs and attach it to the VM.',
    docs: 'https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances',
    async run(ctx) {
      return evaluateEach(await vms(ctx), vmName, (vm) => {
        const sa = (vm.serviceAccounts ?? []).find((s) => isDefaultComputeSa(s.email));
        return sa ? { serviceAccount: sa.email } : undefined;
      }, NO_VMS);
    },
  }),
  defineCheck({
    id: 'compute.vm.default-sa-full-access',
    title: 'VM instances do not use the default service account with full Cloud API access',
    service: 'compute',
    category: 'security',
    cis: ['4.2'],
    severity: { poc: 'medium', test: 'high', prod: 'critical' },
    rationale: 'Default service account + cloud-platform scope means any process on the VM can use the Editor role over the whole project.',
    remediation: 'Attach a dedicated least-privilege service account; scopes then no longer limit you and IAM does the access control.',
    docs: 'https://cloud.google.com/compute/docs/access/service-accounts#scopes_best_practice',
    async run(ctx) {
      return evaluateEach(await vms(ctx), vmName, (vm) => {
        const sa = (vm.serviceAccounts ?? []).find(
          (s) => isDefaultComputeSa(s.email) && (s.scopes ?? []).includes('https://www.googleapis.com/auth/cloud-platform'),
        );
        return sa ? { serviceAccount: sa.email, scope: 'cloud-platform' } : undefined;
      }, NO_VMS);
    },
  }),
  defineCheck({
    id: 'compute.project.os-login',
    title: 'OS Login is enabled for the project and not disabled on any VM',
    service: 'compute',
    category: 'security',
    cis: ['4.4'],
    severity: { poc: 'low', test: 'medium', prod: 'high' },
    rationale: 'OS Login ties SSH access to IAM identities (with 2FA if required) instead of unmanaged SSH keys in metadata.',
    remediation: 'gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE, and remove enable-oslogin=FALSE from VMs. Enforce compute.requireOsLogin org policy.',
    docs: 'https://cloud.google.com/compute/docs/oslogin/set-up-oslogin',
    async run(ctx) {
      const project = await ctx.data('computeProject');
      const projectOn = isTrue(metadataValue(project.commonInstanceMetadata?.items, 'enable-oslogin'));
      const instances = await vms(ctx);
      const resources = [
        projectOn
          ? { resource: `projects/${ctx.projectId}`, status: 'PASS' as const }
          : { resource: `projects/${ctx.projectId}`, status: 'FAIL' as const, evidence: { projectMetadata: 'enable-oslogin is not TRUE' } },
        ...instances.map((vm) => {
          const v = metadataValue(vm.metadata?.items, 'enable-oslogin');
          const enabled = isTrue(v) || (projectOn && !isFalse(v));
          return enabled
            ? { resource: vmName(vm), status: 'PASS' as const }
            : { resource: vmName(vm), status: 'FAIL' as const, evidence: { instanceMetadata: v ?? '(inherits project)' } };
        }),
      ];
      return { kind: 'evaluated', resources };
    },
  }),
  defineCheck({
    id: 'compute.vm.block-project-ssh-keys',
    title: 'VMs block project-wide SSH keys (when OS Login is not used)',
    service: 'compute',
    category: 'security',
    cis: ['4.3'],
    severity: { poc: 'low', test: 'medium', prod: 'medium' },
    rationale: 'Project-wide SSH keys grant access to every VM in the project; one leaked key compromises all of them.',
    remediation: 'Set metadata block-project-ssh-keys=TRUE on the VM, or enable OS Login (which ignores metadata keys).',
    docs: 'https://cloud.google.com/compute/docs/connect/restrict-ssh-keys#block-keys',
    async run(ctx) {
      const project = await ctx.data('computeProject');
      const projectOsLogin = isTrue(metadataValue(project.commonInstanceMetadata?.items, 'enable-oslogin'));
      return evaluateEach(await vms(ctx), vmName, (vm) => {
        const osLoginValue = metadataValue(vm.metadata?.items, 'enable-oslogin');
        const osLogin = isTrue(osLoginValue) || (projectOsLogin && !isFalse(osLoginValue));
        if (osLogin) return undefined;
        return isTrue(metadataValue(vm.metadata?.items, 'block-project-ssh-keys')) ? undefined : { blockProjectSshKeys: false, osLogin: false };
      }, NO_VMS);
    },
  }),
  defineCheck({
    id: 'compute.vm.serial-port',
    title: 'Interactive serial console access is disabled',
    service: 'compute',
    category: 'security',
    cis: ['4.5'],
    severity: { poc: 'medium', test: 'high', prod: 'high' },
    rationale: 'The serial console accepts connections from any IP address and bypasses firewall rules.',
    remediation: 'Remove serial-port-enable from instance and project metadata; enforce the compute.disableSerialPortAccess org policy.',
    docs: 'https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console',
    async run(ctx) {
      const project = await ctx.data('computeProject');
      const projectOn = isTrue(metadataValue(project.commonInstanceMetadata?.items, 'serial-port-enable'));
      return evaluateEach(await vms(ctx), vmName, (vm) => {
        const v = metadataValue(vm.metadata?.items, 'serial-port-enable');
        const on = isTrue(v) || (projectOn && !isFalse(v));
        return on ? { serialPortEnable: v ?? 'inherited from project' } : undefined;
      }, NO_VMS);
    },
  }),
  defineCheck({
    id: 'compute.vm.ip-forwarding',
    title: 'IP forwarding is disabled on VM instances',
    service: 'compute',
    category: 'security',
    cis: ['4.6'],
    severity: { poc: 'low', test: 'medium', prod: 'medium' },
    rationale: 'IP forwarding lets a VM route packets that are not addressed to it. Only network appliances (NAT, firewall VMs) should need it.',
    remediation: 'Recreate the VM with --no-can-ip-forward, or add an exception for legitimate network appliances.',
    docs: 'https://cloud.google.com/vpc/docs/using-routes#canipforward',
    async run(ctx) {
      return evaluateEach(await vms(ctx), vmName, (vm) => (vm.canIpForward ? { canIpForward: true } : undefined), NO_VMS);
    },
  }),
  defineCheck({
    id: 'compute.vm.shielded-vm',
    title: 'Shielded VM vTPM and integrity monitoring are enabled',
    service: 'compute',
    category: 'security',
    cis: ['4.8'],
    severity: { poc: 'info', test: 'low', prod: 'medium' },
    rationale: 'vTPM and integrity monitoring detect boot-level and kernel-level tampering (rootkits, bootkits).',
    remediation: 'Stop the VM and enable vTPM and integrity monitoring (Shielded VM options). Requires a Shielded VM-compatible image.',
    docs: 'https://cloud.google.com/compute/shielded-vm/docs/shielded-vm',
    async run(ctx) {
      return evaluateEach(await vms(ctx), vmName, (vm) => {
        const s = vm.shieldedInstanceConfig ?? {};
        return s.enableVtpm && s.enableIntegrityMonitoring ? undefined : { vtpm: !!s.enableVtpm, integrityMonitoring: !!s.enableIntegrityMonitoring };
      }, NO_VMS);
    },
  }),
  defineCheck({
    id: 'compute.vm.secure-boot',
    title: 'Shielded VM Secure Boot is enabled',
    service: 'compute',
    category: 'security',
    severity: { poc: 'info', test: 'low', prod: 'medium' },
    rationale: 'Secure Boot ensures only signed boot components run.',
    remediation: 'Stop the VM and enable Secure Boot. Workloads using unsigned kernel modules (some GPU drivers) may need an exception.',
    docs: 'https://cloud.google.com/compute/shielded-vm/docs/modifying-shielded-vm',
    async run(ctx) {
      return evaluateEach(await vms(ctx), vmName, (vm) => (vm.shieldedInstanceConfig?.enableSecureBoot ? undefined : { secureBoot: false }), NO_VMS);
    },
  }),
  defineCheck({
    id: 'compute.vm.confidential-computing',
    title: 'Confidential Computing is enabled',
    service: 'compute',
    category: 'security',
    cis: ['4.11'],
    severity: { poc: 'off', test: 'off', prod: 'info' },
    rationale: 'Encrypts data in use. Only needed for workloads with explicit data-in-use protection requirements; limited to certain machine types.',
    remediation: 'Recreate the VM on a supported machine type (e.g. N2D/C3D) with Confidential VM enabled.',
    docs: 'https://cloud.google.com/confidential-computing/confidential-vm/docs/confidential-vm-overview',
    async run(ctx) {
      return evaluateEach(
        await vms(ctx),
        vmName,
        (vm) => (vm.confidentialInstanceConfig?.enableConfidentialCompute || vm.confidentialInstanceConfig?.confidentialInstanceType ? undefined : { confidentialCompute: false }),
        NO_VMS,
      );
    },
  }),
  defineCheck({
    id: 'compute.vm.approved-image',
    title: 'Boot disks are created from approved image projects',
    service: 'compute',
    category: 'security',
    severity: { poc: 'info', test: 'low', prod: 'medium' },
    rationale: 'Using images from known publishers or a hardened internal image project keeps the OS baseline under control.',
    remediation: 'Rebuild the VM from an approved image. Configure the list in config/inspector.yaml (compute.approvedImageProjects) and enforce compute.trustedImageProjects org policy.',
    docs: 'https://cloud.google.com/compute/docs/images/restricting-image-access',
    async run(ctx) {
      const approved = ctx.config.compute.approvedImageProjects;
      if (approved.length === 0) return { kind: 'not_applicable', reason: 'No approved image projects configured (compute.approvedImageProjects).' };
      const disks = new Map((await ctx.data('disks')).map((d) => [d.selfLink, d]));
      return evaluateEach(await vms(ctx), vmName, (vm) => {
        const boot = (vm.disks ?? []).find((d) => d.boot);
        const image = boot?.source ? disks.get(boot.source)?.sourceImage : undefined;
        if (!image) return { sourceImage: 'unknown (disk not created from an image)' };
        const imageProject = /projects\/([^/]+)\/global\/images/.exec(image)?.[1];
        return imageProject && approved.includes(imageProject) ? undefined : { sourceImage: image, imageProject };
      }, NO_VMS);
    },
  }),
  defineCheck({
    id: 'compute.vm.deletion-protection',
    title: 'Deletion protection is enabled on VM instances',
    service: 'compute',
    category: 'reliability',
    severity: { poc: 'off', test: 'low', prod: 'medium' },
    rationale: 'Prevents accidental deletion of long-lived VMs. Not useful for VMs in managed instance groups.',
    remediation: 'gcloud compute instances update VM --deletion-protection',
    docs: 'https://cloud.google.com/compute/docs/instances/preventing-accidental-vm-deletion',
    async run(ctx) {
      const instances = (await vms(ctx)).filter((vm) => !metadataValue(vm.metadata?.items, 'created-by')?.includes('instanceGroupManagers'));
      return evaluateEach(instances, vmName, (vm) => (vm.deletionProtection ? undefined : { deletionProtection: false }), 'No standalone VM instances (VMs in managed instance groups are excluded).');
    },
  }),
  defineCheck({
    id: 'compute.vm.live-migration',
    title: 'VMs live-migrate during host maintenance and restart automatically',
    service: 'compute',
    category: 'reliability',
    severity: { poc: 'off', test: 'info', prod: 'low' },
    rationale: 'MIGRATE + automatic restart keeps VMs running through host maintenance and failures. GPU and Spot VMs cannot migrate.',
    remediation: 'gcloud compute instances set-scheduling VM --maintenance-policy=MIGRATE --restart-on-failure',
    docs: 'https://cloud.google.com/compute/docs/instances/setting-vm-host-options',
    async run(ctx) {
      const regular = (await vms(ctx)).filter((vm) => !vm.scheduling?.preemptible && vm.scheduling?.provisioningModel !== 'SPOT');
      return evaluateEach(regular, vmName, (vm) => {
        const s = vm.scheduling ?? {};
        const ok = s.onHostMaintenance === 'MIGRATE' && s.automaticRestart !== false;
        return ok ? undefined : { onHostMaintenance: s.onHostMaintenance, automaticRestart: s.automaticRestart };
      }, 'No standard (non-Spot) VM instances.');
    },
  }),
  defineCheck({
    id: 'compute.vm.spot-preemptible',
    title: 'Long-lived VMs are not Spot / preemptible',
    service: 'compute',
    category: 'reliability',
    severity: { poc: 'off', test: 'off', prod: 'info' },
    rationale: 'Spot VMs can be stopped at any time. Fine for batch and POC workloads, risky for production services that are not fault tolerant.',
    remediation: 'Use standard provisioning for VMs that must stay up, or make the workload tolerate preemption (MIG + autoscaling).',
    docs: 'https://cloud.google.com/compute/docs/instances/spot',
    async run(ctx) {
      return evaluateEach(
        await vms(ctx),
        vmName,
        (vm) => (vm.scheduling?.preemptible || vm.scheduling?.provisioningModel === 'SPOT' ? { provisioningModel: vm.scheduling?.provisioningModel ?? 'PREEMPTIBLE' } : undefined),
        NO_VMS,
      );
    },
  }),
  defineCheck({
    id: 'compute.vm.multiple-nics',
    title: 'VM instances use a single network interface',
    service: 'compute',
    category: 'security',
    severity: { poc: 'off', test: 'info', prod: 'info' },
    rationale: 'A VM with interfaces in several VPCs can bridge networks that are meant to be isolated. Expected for network appliances.',
    remediation: 'Review whether the VM must sit in multiple VPCs; otherwise recreate it with one interface.',
    docs: 'https://cloud.google.com/vpc/docs/multiple-interfaces-concepts',
    async run(ctx) {
      return evaluateEach(
        await vms(ctx),
        vmName,
        (vm) => ((vm.networkInterfaces ?? []).length > 1 ? { networks: (vm.networkInterfaces ?? []).map((n) => shortName(n.network)) } : undefined),
        NO_VMS,
      );
    },
  }),
];
