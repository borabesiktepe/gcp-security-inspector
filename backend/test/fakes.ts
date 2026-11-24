import type { Collectors } from '../src/gcp/types.js';
import type { InspectorConfig, ScanContext } from '../src/engine/types.js';
import { validateConfig } from '../src/config/load.js';

export const config: InspectorConfig = validateConfig({
  environment: { aliases: { production: 'prod', staging: 'test' }, folders: { '42': 'test' } },
  compute: { approvedImageProjects: ['debian-cloud'] },
});

/** Context that serves fixture data; a key that maps to an Error rejects with it. */
export function fakeContext(data: Partial<{ [K in keyof Collectors]: Collectors[K] | Error }>, now = new Date('2026-11-24T00:00:00Z')): ScanContext {
  return {
    projectId: 'demo-project',
    config,
    now,
    async data(key) {
      const v = data[key];
      if (v instanceof Error) throw v;
      if (v === undefined) throw new Error(`fixture "${key}" not provided`);
      return v as never;
    },
  };
}
