import type { CheckDefinition } from '../engine/types.js';
import { computeChecks } from './compute.js';
import { gkeChecks } from './gke.js';
import { iamChecks } from './iam.js';
import { loggingChecks } from './logging.js';
import { storageChecks } from './storage.js';
import { vpcChecks } from './vpc.js';

export const ALL_CHECKS: CheckDefinition[] = [...iamChecks, ...loggingChecks, ...vpcChecks, ...computeChecks, ...storageChecks, ...gkeChecks];

const ids = new Set<string>();
for (const c of ALL_CHECKS) {
  if (ids.has(c.id)) throw new Error(`Duplicate check id ${c.id}`);
  ids.add(c.id);
}
