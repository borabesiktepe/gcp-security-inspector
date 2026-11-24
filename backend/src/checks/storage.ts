import { defineCheck, evaluateEach } from '../engine/helpers.js';

const NO_BUCKETS = 'No Cloud Storage buckets in this project.';
const PUBLIC = new Set(['allUsers', 'allAuthenticatedUsers']);
const ADMIN_ROLES = new Set(['roles/storage.admin', 'roles/storage.legacyBucketOwner']);

export const storageChecks = [
  defineCheck({
    id: 'storage.bucket.public',
    title: 'Buckets are not publicly accessible',
    service: 'storage',
    category: 'security',
    cis: ['5.1'],
    severity: { poc: 'critical', test: 'critical', prod: 'critical' },
    rationale: 'allUsers / allAuthenticatedUsers bindings expose bucket data to the whole internet.',
    remediation: 'Remove the public bindings and enforce Public Access Prevention. For public websites serve through a load balancer + Cloud CDN, and add an exception.',
    docs: 'https://cloud.google.com/storage/docs/using-public-access-prevention',
    async run(ctx) {
      const [buckets, policies] = await Promise.all([ctx.data('buckets'), ctx.data('bucketPolicies')]);
      return evaluateEach(buckets, (b) => b.name, (b) => {
        const publicGrants = (policies[b.name]?.bindings ?? []).flatMap((bd) => (bd.members ?? []).filter((m) => PUBLIC.has(m)).map((m) => `${m} -> ${bd.role}`));
        return publicGrants.length ? { publicGrants } : undefined;
      }, NO_BUCKETS);
    },
  }),
  defineCheck({
    id: 'storage.bucket.public-access-prevention',
    title: 'Public Access Prevention is enforced on buckets',
    service: 'storage',
    category: 'security',
    severity: { poc: 'low', test: 'medium', prod: 'high' },
    rationale: 'Enforced PAP blocks any future public grant, even by mistake.',
    remediation: 'gcloud storage buckets update gs://BUCKET --public-access-prevention (or enforce storage.publicAccessPrevention org policy).',
    docs: 'https://cloud.google.com/storage/docs/public-access-prevention',
    async run(ctx) {
      return evaluateEach(await ctx.data('buckets'), (b) => b.name, (b) => {
        const pap = b.iamConfiguration?.publicAccessPrevention;
        return pap === 'enforced' ? undefined : { publicAccessPrevention: pap ?? 'unspecified' };
      }, NO_BUCKETS);
    },
  }),
  defineCheck({
    id: 'storage.bucket.uniform-access',
    title: 'Uniform bucket-level access is enabled',
    service: 'storage',
    category: 'security',
    cis: ['5.2'],
    severity: { poc: 'low', test: 'medium', prod: 'high' },
    rationale: 'Disables object ACLs so access is controlled only by IAM, which is auditable and consistent.',
    remediation: 'gcloud storage buckets update gs://BUCKET --uniform-bucket-level-access',
    docs: 'https://cloud.google.com/storage/docs/uniform-bucket-level-access',
    async run(ctx) {
      return evaluateEach(await ctx.data('buckets'), (b) => b.name, (b) => (b.iamConfiguration?.uniformBucketLevelAccess?.enabled ? undefined : { uniformBucketLevelAccess: false }), NO_BUCKETS);
    },
  }),
  defineCheck({
    id: 'storage.bucket.admin-grants',
    title: 'Bucket-level IAM does not grant storage admin roles',
    service: 'storage',
    category: 'security',
    severity: { poc: 'info', test: 'low', prod: 'medium' },
    rationale: 'Admin roles on a bucket let the member change its IAM policy and delete it. Admin access is easier to govern at project level through few, reviewed principals.',
    remediation: 'Replace roles/storage.admin on the bucket with objectViewer/objectUser/objectAdmin as needed.',
    docs: 'https://cloud.google.com/storage/docs/access-control/iam-roles',
    async run(ctx) {
      const [buckets, policies] = await Promise.all([ctx.data('buckets'), ctx.data('bucketPolicies')]);
      return evaluateEach(buckets, (b) => b.name, (b) => {
        const admins = (policies[b.name]?.bindings ?? [])
          .filter((bd) => ADMIN_ROLES.has(bd.role))
          // legacyBucketOwner is granted to projectOwner/projectEditor by default; only flag explicit principals.
          .flatMap((bd) => (bd.members ?? []).filter((m) => !m.startsWith('projectOwner:') && !m.startsWith('projectEditor:')).map((m) => `${m} -> ${bd.role}`));
        return admins.length ? { adminGrants: admins } : undefined;
      }, NO_BUCKETS);
    },
  }),
  defineCheck({
    id: 'storage.bucket.versioning',
    title: 'Object versioning or soft delete protects bucket data',
    service: 'storage',
    category: 'reliability',
    severity: { poc: 'off', test: 'info', prod: 'medium' },
    rationale: 'Versioning or soft delete lets you recover objects after accidental deletion, overwrite or ransomware.',
    remediation: 'gcloud storage buckets update gs://BUCKET --versioning (or keep the default 7-day soft delete policy).',
    docs: 'https://cloud.google.com/storage/docs/soft-delete',
    async run(ctx) {
      return evaluateEach(await ctx.data('buckets'), (b) => b.name, (b) => {
        const softDelete = Number(b.softDeletePolicy?.retentionDurationSeconds ?? 0);
        return b.versioning?.enabled || softDelete > 0 ? undefined : { versioning: false, softDeleteSeconds: softDelete };
      }, NO_BUCKETS);
    },
  }),
  defineCheck({
    id: 'storage.bucket.lifecycle',
    title: 'Buckets have lifecycle rules',
    service: 'storage',
    category: 'cost',
    severity: { poc: 'off', test: 'info', prod: 'low' },
    rationale: 'Lifecycle rules move cold data to cheaper classes and clean up old versions, keeping cost predictable.',
    remediation: 'Add lifecycle rules (e.g. delete noncurrent versions after N days, SetStorageClass for old objects).',
    docs: 'https://cloud.google.com/storage/docs/lifecycle',
    async run(ctx) {
      return evaluateEach(await ctx.data('buckets'), (b) => b.name, (b) => ((b.lifecycle?.rule ?? []).length ? undefined : { lifecycleRules: 0 }), NO_BUCKETS);
    },
  }),
  defineCheck({
    id: 'storage.bucket.usage-logs',
    title: 'Usage and storage logs are enabled',
    service: 'storage',
    category: 'operations',
    severity: { poc: 'off', test: 'off', prod: 'info' },
    rationale: 'Legacy usage logs record bucket access. For security auditing, Cloud Audit Logs (Data Access) are the recommended mechanism; see logging.audit.data-access.',
    remediation: 'gcloud storage buckets update gs://BUCKET --log-bucket=gs://LOG_BUCKET, or rely on Data Access audit logs.',
    docs: 'https://cloud.google.com/storage/docs/access-logs',
    async run(ctx) {
      return evaluateEach(await ctx.data('buckets'), (b) => b.name, (b) => (b.logging?.logBucket ? undefined : { usageLogs: false }), NO_BUCKETS);
    },
  }),
  defineCheck({
    id: 'storage.bucket.cors-wildcard',
    title: 'Bucket CORS does not allow any origin for write methods',
    service: 'storage',
    category: 'security',
    severity: { poc: 'info', test: 'low', prod: 'medium' },
    rationale: 'origin "*" combined with PUT/POST/DELETE lets any website issue writes using a signed URL or user credentials.',
    remediation: 'List explicit origins in the CORS configuration.',
    docs: 'https://cloud.google.com/storage/docs/cross-origin',
    async run(ctx) {
      const withCors = (await ctx.data('buckets')).filter((b) => (b.cors ?? []).length > 0);
      return evaluateEach(withCors, (b) => b.name, (b) => {
        const risky = (b.cors ?? []).filter((c) => (c.origin ?? []).includes('*') && (c.method ?? []).some((m) => !['GET', 'HEAD', 'OPTIONS'].includes(m.toUpperCase())));
        return risky.length ? { cors: risky } : undefined;
      }, 'No buckets with a CORS configuration.');
    },
  }),
  defineCheck({
    id: 'storage.bucket.website-config',
    title: 'Website buckets define an index page and an error page',
    service: 'storage',
    category: 'operations',
    severity: { poc: 'off', test: 'off', prod: 'info' },
    rationale: 'Without a custom 404 page, missing objects return a generic XML error.',
    remediation: 'gcloud storage buckets update gs://BUCKET --web-main-page-suffix=index.html --web-error-page=404.html',
    docs: 'https://cloud.google.com/storage/docs/hosting-static-website',
    async run(ctx) {
      const sites = (await ctx.data('buckets')).filter((b) => b.website && (b.website.mainPageSuffix || b.website.notFoundPage));
      return evaluateEach(sites, (b) => b.name, (b) => (b.website?.mainPageSuffix && b.website?.notFoundPage ? undefined : { website: b.website }), 'No buckets are configured as websites.');
    },
  }),
];
