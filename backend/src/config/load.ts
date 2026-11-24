import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse } from 'yaml';
import { validateExceptions, type ExceptionRule } from '../engine/exceptions.js';
import { isEnvironment } from '../engine/environment.js';
import { validateProfile, type Profile } from '../engine/profiles.js';
import { ENVIRONMENTS, type Environment, type InspectorConfig } from '../engine/types.js';

export interface LoadedConfig {
  config: InspectorConfig;
  profiles: Record<Environment, Profile>;
  exceptions: ExceptionRule[];
}

async function readYaml(file: string, optional = false): Promise<unknown> {
  try {
    return parse(await readFile(file, 'utf8')) ?? {};
  } catch (err) {
    if (optional && (err as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw new Error(`Cannot read ${file}: ${(err as Error).message}`);
  }
}

export function validateConfig(raw: unknown): InspectorConfig {
  const c = (raw ?? {}) as Partial<InspectorConfig> & { environment?: Partial<InspectorConfig['environment']> };
  const env: Partial<InspectorConfig['environment']> = c.environment ?? {};
  const aliases: Record<string, Environment> = {};
  for (const [k, v] of Object.entries(env.aliases ?? {})) {
    if (!isEnvironment(v)) throw new Error(`inspector.yaml: alias "${k}" maps to unknown environment "${v}"`);
    aliases[k.toLowerCase()] = v;
  }
  const folders: Record<string, Environment> = {};
  for (const [k, v] of Object.entries(env.folders ?? {})) {
    if (!isEnvironment(v)) throw new Error(`inspector.yaml: folder "${k}" maps to unknown environment "${v}"`);
    folders[k.startsWith('folders/') ? k : `folders/${k}`] = v;
  }
  const def = env.default ?? 'prod';
  if (!isEnvironment(def)) throw new Error(`inspector.yaml: default environment "${def}" is unknown`);
  return {
    environment: { labelKeys: env.labelKeys ?? ['environment', 'env'], aliases, folders, default: def },
    compute: { approvedImageProjects: c.compute?.approvedImageProjects ?? [] },
    iam: { serviceAccountKeyMaxAgeDays: c.iam?.serviceAccountKeyMaxAgeDays ?? 90 },
  };
}

export async function loadConfig(dir: string, knownCheckIds: Set<string>): Promise<LoadedConfig> {
  const config = validateConfig(await readYaml(path.join(dir, 'inspector.yaml')));
  const profiles = {} as Record<Environment, Profile>;
  for (const env of ENVIRONMENTS) {
    const file = path.join(dir, 'profiles', `${env}.yaml`);
    const profile = validateProfile(await readYaml(file), file, knownCheckIds);
    if (profile.environment !== env) throw new Error(`${file}: environment must be "${env}"`);
    profiles[env] = profile;
  }
  const exFile = path.join(dir, 'exceptions.yaml');
  const exceptions = validateExceptions(await readYaml(exFile, true), exFile);
  for (const e of exceptions) {
    if (!knownCheckIds.has(e.check)) throw new Error(`${exFile}: exception refers to unknown check "${e.check}"`);
  }
  return { config, profiles, exceptions };
}
