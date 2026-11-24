import type { Project } from '../gcp/types.js';
import { ENVIRONMENTS, type Environment, type InspectorConfig, type ScanReport } from './types.js';

export function isEnvironment(v: unknown): v is Environment {
  return typeof v === 'string' && (ENVIRONMENTS as readonly string[]).includes(v);
}

/** Maps a label value such as "production" or "staging" to an environment tier. */
export function normaliseEnvironment(value: string | undefined, config: InspectorConfig): Environment | undefined {
  if (!value) return undefined;
  const v = value.trim().toLowerCase();
  if (isEnvironment(v)) return v;
  return config.environment.aliases[v];
}

/**
 * Order of precedence: explicit request > project label > parent folder mapping > configured default.
 * The default is `prod` out of the box so an unlabelled project is reviewed strictly.
 */
export function resolveEnvironment(
  requested: string | undefined,
  project: Project | undefined,
  config: InspectorConfig,
): { environment: Environment; source: ScanReport['environmentSource'] } {
  if (requested) {
    if (!isEnvironment(requested)) throw new Error(`Unknown environment "${requested}". Use one of: ${ENVIRONMENTS.join(', ')}`);
    return { environment: requested, source: { source: 'request', detail: 'Selected by the user' } };
  }
  for (const key of config.environment.labelKeys) {
    const value = project?.labels?.[key];
    const env = normaliseEnvironment(value, config);
    if (env) return { environment: env, source: { source: 'label', detail: `Project label ${key}=${value}` } };
  }
  const parent = project?.parent;
  if (parent && config.environment.folders[parent]) {
    return { environment: config.environment.folders[parent], source: { source: 'folder', detail: `Parent ${parent}` } };
  }
  return {
    environment: config.environment.default,
    source: { source: 'default', detail: `No environment label or folder mapping found; using default "${config.environment.default}"` },
  };
}
