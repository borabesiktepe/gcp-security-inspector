# Google Cloud Inspector – backend (v2)

Read-only security review API for Google Cloud projects, with **POC / Test / Prod** profiles.

- No service account keys: uses Application Default Credentials (ADC)
- 64 checks across IAM, Logging, VPC/Firewall, Compute Engine, Cloud Storage and GKE, mapped to the CIS Google Cloud benchmarks where applicable
- Every check has a severity per environment; profiles and exceptions are plain YAML in `config/`
- Missing permissions are reported as `ERROR`, never as a pass

## Run locally

Requirements: Node.js 20+ and the gcloud CLI.

```bash
# 1. Credentials (recommended: impersonate a read-only scanner service account)
gcloud auth application-default login --impersonate-service-account=inspector@SCANNER_PROJECT.iam.gserviceaccount.com
#    or simply your own user (needs the roles below on the scanned projects)
gcloud auth application-default login

# 2. Start the API
cd backend
npm install
npm run dev          # http://127.0.0.1:8080
```

Production build: `npm run build && npm start`. If `../inspector/dist` exists, the built web UI is served from the same port.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | HTTP port |
| `HOST` | `127.0.0.1` | Bind address. The API has no login of its own; only expose it behind IAP or similar |
| `INSPECTOR_CONFIG_DIR` | `./config` | Config, profiles and exceptions |
| `INSPECTOR_STATIC_DIR` | `../inspector/dist` | Built frontend |

## Scanner identity: roles

Grant on each scanned project (or on a folder / the organization):

| Role | Why |
|---|---|
| `roles/iam.securityReviewer` | Read IAM policies of all resources (projects, buckets, …) |
| `roles/viewer` | Read resource configuration (Compute, GKE, Storage metadata, IAM service accounts) |
| `roles/browser` | List projects (only needed at folder/org level) |

To impersonate a scanner service account, the human user needs `roles/iam.serviceAccountTokenCreator` **on that service account only**, not on the project. The scanner itself never needs write roles (the old setup guide's Storage Admin is not required).

## API

| Method | Path | |
|---|---|---|
| GET | `/api/identity` | Identity ADC resolves to |
| GET | `/api/projects?q=` | Projects visible to the scanner, with detected environment |
| GET | `/api/catalog` | All checks with their severity per environment, profiles |
| POST | `/api/scans` | Body `{ "projectId": "...", "environment": "poc" \| "test" \| "prod" (optional) }` |
| GET | `/api/scans`, `/api/scans/:id` | Recent scans (kept in memory) |

## Environments

The tier is picked in this order:
1. `environment` in the scan request
2. Project label `environment` / `env` / `stage` (values like `production`, `staging`, `sandbox` are mapped via `config/inspector.yaml`)
3. Parent folder mapping in `config/inspector.yaml`
4. Default: **prod** (strict), with a warning in the report

## Severities, score and gate

Severities: `critical`, `high`, `medium`, `low`, `info`, `off` (`off` = not run in that environment).

- **Score** (0–100): weighted by severity (critical 10, high 5, medium 3, low 1, info 0) and by the share of passing resources.
- **Gate** (from `config/profiles/<env>.yaml`):
  - `BLOCKED`: a check with a `failOn` severity failed
  - `INCOMPLETE`: a `failOn` check could not be evaluated (usually permissions)
  - `WARN`: a check with a `warnOn` severity failed
  - `PASS`

Change a check's severity for one environment in its profile:

```yaml
# config/profiles/prod.yaml
overrides:
  compute.vm.confidential-computing: medium
```

## Exceptions (accepted risk)

`config/exceptions.yaml` – each entry needs a check id, resource (glob), reason, owner and expiry date. Expired exceptions stop applying and show up as warnings.

## Development

```bash
npm test          # vitest, uses fixtures – no GCP access needed
npm run typecheck
```

A check is one `defineCheck({...})` entry in `src/checks/<service>.ts`; data comes from `ctx.data('<collector>')` (see `src/gcp/context.ts`).
