import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from './app.js';
import { ALL_CHECKS } from './checks/index.js';
import { loadConfig } from './config/load.js';
import { GcpClient } from './gcp/client.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const configDir = process.env.INSPECTOR_CONFIG_DIR ?? path.join(root, 'config');
const staticDir = process.env.INSPECTOR_STATIC_DIR ?? path.resolve(root, '..', 'inspector', 'dist');
const port = Number(process.env.PORT ?? 8080);
// Local tool without its own login: listen on loopback unless told otherwise (e.g. Cloud Run behind IAP sets HOST=0.0.0.0).
const host = process.env.HOST ?? '127.0.0.1';

const loaded = await loadConfig(configDir, new Set(ALL_CHECKS.map((c) => c.id)));
const gcp = new GcpClient();
const app = createApp({ loaded, gcp, staticDir });

app.listen(port, host, () => {
  console.log(`Google Cloud Inspector API on http://${host}:${port} (${ALL_CHECKS.length} checks, config: ${configDir})`);
  gcp.identity().then(
    (id) =>
      id.principal || id.projectId
        ? console.log(`Scanning as ${id.principal ?? 'Application Default Credentials'}`)
        : console.warn('No Application Default Credentials found yet. Run: gcloud auth application-default login'),
    () => console.warn('No Application Default Credentials found yet. Run: gcloud auth application-default login'),
  );
});
