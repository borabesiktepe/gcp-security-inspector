import { defineCheck } from '../engine/helpers.js';

export const loggingChecks = [
  defineCheck({
    id: 'logging.audit.data-access',
    title: 'Data Access audit logs are enabled for all services',
    service: 'logging',
    category: 'security',
    cis: ['2.1'],
    severity: { poc: 'off', test: 'low', prod: 'high' },
    rationale: 'Admin Activity logs are always on, but reads and data changes (DATA_READ / DATA_WRITE) are only logged when enabled. Without them you cannot investigate who read or modified data.',
    remediation: 'Enable DATA_READ and DATA_WRITE for allServices in the project (or at folder/org level): IAM & Admin > Audit Logs. Mind the log volume and cost.',
    docs: 'https://cloud.google.com/logging/docs/audit/configure-data-access',
    async run(ctx) {
      const policy = await ctx.data('iamPolicy');
      const all = policy.auditConfigs?.find((c) => c.service === 'allServices');
      const types = new Set((all?.auditLogConfigs ?? []).map((c) => c.logType));
      const exempted = (all?.auditLogConfigs ?? []).flatMap((c) => c.exemptedMembers ?? []);
      const missing = (['DATA_READ', 'DATA_WRITE'] as const).filter((t) => !types.has(t));
      const resource = `projects/${ctx.projectId}`;
      if (missing.length || exempted.length) {
        return {
          kind: 'evaluated',
          resources: [{ resource, status: 'FAIL', evidence: { missingLogTypes: missing, exemptedMembers: exempted, note: 'Folder/org level settings are not evaluated yet' } }],
        };
      }
      return { kind: 'evaluated', resources: [{ resource, status: 'PASS' }] };
    },
  }),
];
