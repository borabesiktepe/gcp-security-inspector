import express, { type NextFunction, type Request, type Response } from 'express';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { ALL_CHECKS } from './checks/index.js';
import type { LoadedConfig } from './config/load.js';
import { resolveEnvironment } from './engine/environment.js';
import { resolveSeverity } from './engine/profiles.js';
import { runScan } from './engine/runner.js';
import { ENVIRONMENTS, type CheckDefinition, type ScanReport } from './engine/types.js';
import { GcpApiError, GcpClient } from './gcp/client.js';
import { GcpScanContext } from './gcp/context.js';
import type { Project } from './gcp/types.js';

// GCP project ids: 6-30 chars, lowercase letters, digits, hyphens; starts with a letter.
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const MAX_STORED_REPORTS = 50;

export interface AppOptions {
  loaded: LoadedConfig;
  gcp: GcpClient;
  checks?: CheckDefinition[];
  staticDir?: string;
}

export function createApp({ loaded, gcp, checks = ALL_CHECKS, staticDir }: AppOptions) {
  const app = express();
  const reports = new Map<string, ScanReport>();
  app.use(express.json({ limit: '100kb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.get('/api/identity', async (_req, res) => {
    res.json(await gcp.identity());
  });

  app.get('/api/projects', async (req, res) => {
    const filter = typeof req.query.q === 'string' && req.query.q.trim() ? `state:ACTIVE ${req.query.q.trim()}` : 'state:ACTIVE';
    const projects = await gcp.listAll<Project>('https://cloudresourcemanager.googleapis.com/v3/projects:search', 'projects', { query: filter });
    res.json(
      projects.map((p) => {
        const env = resolveEnvironment(undefined, p, loaded.config);
        return { projectId: p.projectId, displayName: p.displayName, parent: p.parent, labels: p.labels ?? {}, environment: env.environment, environmentSource: env.source };
      }),
    );
  });

  app.get('/api/catalog', (_req, res) => {
    res.json({
      environments: ENVIRONMENTS,
      profiles: Object.values(loaded.profiles).map((p) => ({ name: p.name, environment: p.environment, description: p.description, gate: p.gate })),
      checks: checks.map((c) => ({
        id: c.id,
        title: c.title,
        service: c.service,
        category: c.category,
        cis: c.cis ?? [],
        rationale: c.rationale,
        remediation: c.remediation,
        docs: c.docs,
        severity: Object.fromEntries(ENVIRONMENTS.map((e) => [e, resolveSeverity(c, loaded.profiles[e])])),
      })),
    });
  });

  app.post('/api/scans', async (req, res) => {
    const { projectId, environment } = (req.body ?? {}) as { projectId?: unknown; environment?: unknown };
    if (typeof projectId !== 'string' || !PROJECT_ID.test(projectId)) {
      res.status(400).json({ error: 'projectId must be a valid GCP project id' });
      return;
    }
    if (environment !== undefined && environment !== null && environment !== '' && !ENVIRONMENTS.includes(environment as never)) {
      res.status(400).json({ error: `environment must be one of ${ENVIRONMENTS.join(', ')}` });
      return;
    }
    const ctx = new GcpScanContext(gcp, projectId, loaded.config);
    // Project metadata (labels/parent) drives environment detection. Lack of access here is fatal: nothing else would work either.
    const project = await ctx.data('project');
    const env = resolveEnvironment((environment as string) || undefined, project, loaded.config);
    const report = await runScan(ctx, checks, {
      profile: loaded.profiles[env.environment],
      environmentSource: env.source,
      exceptions: loaded.exceptions,
      project,
    });
    reports.set(report.id, report);
    while (reports.size > MAX_STORED_REPORTS) reports.delete(reports.keys().next().value!);
    res.status(201).json(report);
  });

  app.get('/api/scans', (_req, res) => {
    res.json(
      [...reports.values()].reverse().map((r) => ({
        id: r.id, projectId: r.projectId, environment: r.environment, score: r.score, gate: r.gate.status, finishedAt: r.finishedAt,
      })),
    );
  });

  app.get('/api/scans/:id', (req, res) => {
    const report = reports.get(req.params.id);
    if (!report) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
    res.json(report);
  });

  if (staticDir && existsSync(staticDir)) {
    app.use(express.static(staticDir));
    app.get(/^\/(?!api\/).*/, (_req, res) => res.sendFile(path.join(staticDir, 'index.html')));
  }

  // Express 5 forwards rejected promises from async handlers here.
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof GcpApiError) {
      const status = err.kind === 'PERMISSION_DENIED' ? 403 : err.kind === 'NOT_FOUND' ? 404 : err.kind === 'UNAUTHENTICATED' ? 401 : 502;
      res.status(status).json({ error: err.message, kind: err.kind });
      return;
    }
    const message = err instanceof Error ? err.message : String(err);
    if (/Could not load the default credentials/i.test(message)) {
      res.status(401).json({ error: 'No Application Default Credentials found. Run: gcloud auth application-default login', kind: 'UNAUTHENTICATED' });
      return;
    }
    console.error(err);
    res.status(500).json({ error: message });
  });

  return app;
}
