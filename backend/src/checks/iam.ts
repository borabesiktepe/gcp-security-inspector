import { defineCheck, evaluateEach } from '../engine/helpers.js';
import type { IamBinding } from '../gcp/types.js';

const BASIC_ROLES = new Set(['roles/owner', 'roles/editor']);
const PUBLIC_MEMBERS = new Set(['allUsers', 'allAuthenticatedUsers']);
const SA_IMPERSONATION_ROLES = new Set(['roles/iam.serviceAccountUser', 'roles/iam.serviceAccountTokenCreator']);

/** One row per (member, role) so findings and exceptions can target a single grant. */
function grants(bindings: IamBinding[] | undefined, roleFilter: (role: string) => boolean, memberFilter: (m: string) => boolean) {
  const out: { member: string; role: string; conditional: boolean }[] = [];
  for (const b of bindings ?? []) {
    if (!roleFilter(b.role)) continue;
    for (const m of b.members ?? []) if (memberFilter(m)) out.push({ member: m, role: b.role, conditional: !!b.condition });
  }
  return out;
}

/** Checks that report one FAIL row per offending grant, or a single PASS row for the project. */
function grantsOutcome(projectId: string, rows: { member: string; role: string; conditional: boolean }[]) {
  if (rows.length === 0) return { kind: 'evaluated' as const, resources: [{ resource: `projects/${projectId}`, status: 'PASS' as const }] };
  return {
    kind: 'evaluated' as const,
    resources: rows.map((r) => ({ resource: r.member, status: 'FAIL' as const, evidence: { role: r.role, conditional: r.conditional } })),
  };
}

export const iamChecks = [
  defineCheck({
    id: 'iam.project.public-members',
    title: 'Project IAM policy does not grant roles to allUsers or allAuthenticatedUsers',
    service: 'iam',
    category: 'security',
    severity: { poc: 'critical', test: 'critical', prod: 'critical' },
    rationale: 'Granting project roles to allUsers/allAuthenticatedUsers lets anyone on the internet (or any Google account) act on the project.',
    remediation: 'Remove the binding: gcloud projects remove-iam-policy-binding PROJECT --member=allUsers --role=ROLE',
    docs: 'https://cloud.google.com/iam/docs/overview#allusers',
    async run(ctx) {
      const policy = await ctx.data('iamPolicy');
      return grantsOutcome(ctx.projectId, grants(policy.bindings, () => true, (m) => PUBLIC_MEMBERS.has(m)));
    },
  }),
  defineCheck({
    id: 'iam.project.basic-roles-service-accounts',
    title: 'Service accounts do not have Owner or Editor on the project',
    service: 'iam',
    category: 'security',
    cis: ['1.5'],
    severity: { poc: 'medium', test: 'high', prod: 'critical' },
    rationale: 'Owner/Editor give a workload thousands of permissions. A leaked token or compromised VM then controls the whole project. Note the default Compute Engine service account gets Editor automatically unless the iam.automaticIamGrantsForDefaultServiceAccounts org policy is enforced.',
    remediation: 'Replace Owner/Editor with predefined or custom roles that cover only what the workload uses (IAM Recommender shows unused permissions).',
    docs: 'https://cloud.google.com/iam/docs/best-practices-service-accounts#restrict-admin-privileges',
    async run(ctx) {
      const policy = await ctx.data('iamPolicy');
      return grantsOutcome(ctx.projectId, grants(policy.bindings, (r) => BASIC_ROLES.has(r), (m) => m.startsWith('serviceAccount:')));
    },
  }),
  defineCheck({
    id: 'iam.project.basic-roles-users',
    title: 'Users and groups do not have Owner or Editor on the project',
    service: 'iam',
    category: 'security',
    cis: ['1.1'],
    severity: { poc: 'low', test: 'medium', prod: 'high' },
    rationale: 'Basic roles are far broader than day-to-day work needs. In production, human access should use predefined roles and just-in-time elevation.',
    remediation: 'Grant predefined roles (e.g. roles/compute.admin, roles/viewer) instead; use Privileged Access Manager for temporary elevation.',
    docs: 'https://cloud.google.com/iam/docs/roles-overview#basic',
    async run(ctx) {
      const policy = await ctx.data('iamPolicy');
      return grantsOutcome(
        ctx.projectId,
        grants(policy.bindings, (r) => BASIC_ROLES.has(r), (m) => m.startsWith('user:') || m.startsWith('group:')),
      );
    },
  }),
  defineCheck({
    id: 'iam.project.service-account-impersonation',
    title: 'Service Account User / Token Creator are not granted at project level',
    service: 'iam',
    category: 'security',
    cis: ['1.6'],
    severity: { poc: 'low', test: 'medium', prod: 'high' },
    rationale: 'At project level these roles let the member impersonate every service account in the project, including highly privileged ones.',
    remediation: 'Grant roles/iam.serviceAccountUser or roles/iam.serviceAccountTokenCreator on the specific service account instead of the project.',
    docs: 'https://cloud.google.com/iam/docs/service-account-permissions',
    async run(ctx) {
      const policy = await ctx.data('iamPolicy');
      return grantsOutcome(ctx.projectId, grants(policy.bindings, (r) => SA_IMPERSONATION_ROLES.has(r), () => true));
    },
  }),
  defineCheck({
    id: 'iam.sa.user-managed-keys',
    title: 'Service accounts have no user-managed keys',
    service: 'iam',
    category: 'security',
    cis: ['1.4'],
    severity: { poc: 'low', test: 'high', prod: 'critical' },
    rationale: 'Downloaded JSON keys are long-lived bearer credentials and the most common cause of GCP credential leaks.',
    remediation: 'Use attached service accounts, Workload Identity Federation or impersonation instead. Delete keys: gcloud iam service-accounts keys delete KEY_ID --iam-account=SA. Enforce the iam.disableServiceAccountKeyCreation org policy.',
    docs: 'https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys',
    async run(ctx) {
      const keys = await ctx.data('serviceAccountKeys');
      const accounts = await ctx.data('serviceAccounts');
      return evaluateEach(
        accounts,
        (sa) => sa.email,
        (sa) => {
          const active = (keys[sa.email] ?? []).filter((k) => !k.disabled);
          return active.length ? { userManagedKeys: active.length } : undefined;
        },
        'No service accounts in this project.',
      );
    },
  }),
  defineCheck({
    id: 'iam.sa.key-rotation',
    title: 'User-managed service account keys are rotated',
    service: 'iam',
    category: 'security',
    cis: ['1.7'],
    severity: { poc: 'low', test: 'medium', prod: 'high' },
    rationale: 'If keys cannot be avoided, short lifetimes limit how long a leaked key stays useful.',
    remediation: 'Create a new key, roll it out, then delete the old key. Better: remove keys entirely.',
    docs: 'https://cloud.google.com/iam/docs/key-rotation',
    async run(ctx) {
      const maxDays = ctx.config.iam.serviceAccountKeyMaxAgeDays;
      const keysBySa = await ctx.data('serviceAccountKeys');
      const keys = Object.values(keysBySa).flat().filter((k) => !k.disabled);
      return evaluateEach(
        keys,
        (k) => k.name,
        (k) => {
          if (!k.validAfterTime) return undefined;
          const ageDays = Math.floor((ctx.now.getTime() - Date.parse(k.validAfterTime)) / 86_400_000);
          return ageDays > maxDays ? { ageDays, maxDays, createdAt: k.validAfterTime } : undefined;
        },
        'No user-managed service account keys.',
      );
    },
  }),
];
