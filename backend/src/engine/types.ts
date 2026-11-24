import type { Collectors } from '../gcp/types.js';

export const ENVIRONMENTS = ['poc', 'test', 'prod'] as const;
export type Environment = (typeof ENVIRONMENTS)[number];

/** `off` means the check is not run or reported in that environment. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'off'] as const;
export type Severity = (typeof SEVERITIES)[number];

export type ServiceId = 'iam' | 'logging' | 'compute' | 'vpc' | 'storage' | 'gke';
export type Category = 'security' | 'reliability' | 'cost' | 'operations';

export interface InspectorConfig {
  environment: {
    labelKeys: string[];
    aliases: Record<string, Environment>;
    folders: Record<string, Environment>;
    default: Environment;
  };
  compute: { approvedImageProjects: string[] };
  iam: { serviceAccountKeyMaxAgeDays: number };
}

/** What a check sees: lazily fetched, memoised GCP data for one project. */
export interface ScanContext {
  projectId: string;
  config: InspectorConfig;
  now: Date;
  data<K extends keyof Collectors>(key: K): Promise<Collectors[K]>;
}

export interface ResourceResult {
  resource: string;
  status: 'PASS' | 'FAIL';
  evidence?: Record<string, unknown>;
}

export type CheckOutcome =
  | { kind: 'evaluated'; resources: ResourceResult[] }
  | { kind: 'not_applicable'; reason: string };

export interface CheckDefinition {
  id: string;
  title: string;
  service: ServiceId;
  category: Category;
  /** CIS Google Cloud Platform Foundation Benchmark references, e.g. "4.9". */
  cis?: string[];
  severity: Record<Environment, Severity>;
  rationale: string;
  remediation: string;
  docs?: string;
  run(ctx: ScanContext): Promise<CheckOutcome>;
}

export type CheckStatus = 'PASS' | 'FAIL' | 'ERROR' | 'NOT_APPLICABLE' | 'SKIPPED';

export interface AppliedException {
  reason: string;
  owner: string;
  expires: string;
}

export interface Finding extends ResourceResult {
  excepted?: AppliedException;
}

export interface CheckResult {
  id: string;
  title: string;
  service: ServiceId;
  category: Category;
  cis: string[];
  severity: Severity;
  status: CheckStatus;
  message?: string;
  rationale: string;
  remediation: string;
  docs?: string;
  resources: { total: number; passed: number; failed: number; excepted: number };
  findings: Finding[];
}

export type GateStatus = 'PASS' | 'WARN' | 'BLOCKED' | 'INCOMPLETE';

export interface ScanReport {
  id: string;
  projectId: string;
  projectName?: string;
  environment: Environment;
  environmentSource: { source: 'request' | 'label' | 'folder' | 'default'; detail: string };
  profile: string;
  startedAt: string;
  finishedAt: string;
  score: number;
  gate: { status: GateStatus; reasons: string[] };
  summary: {
    byStatus: Record<CheckStatus, number>;
    failedBySeverity: Record<Exclude<Severity, 'off'>, number>;
    services: { id: ServiceId; score: number; checks: number; failed: number }[];
  };
  warnings: string[];
  checks: CheckResult[];
}
