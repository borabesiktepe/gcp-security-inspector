import { GoogleAuth } from 'google-auth-library';

export type GcpErrorKind = 'PERMISSION_DENIED' | 'API_DISABLED' | 'NOT_FOUND' | 'UNAUTHENTICATED' | 'OTHER';

export class GcpApiError extends Error {
  constructor(
    public readonly kind: GcpErrorKind,
    public readonly status: number | undefined,
    message: string,
    public readonly url: string,
  ) {
    super(message);
    this.name = 'GcpApiError';
  }
}

interface GoogleErrorBody {
  error?: {
    code?: number;
    message?: string;
    status?: string;
    errors?: { reason?: string }[];
    details?: { reason?: string }[];
  };
}

export function toGcpApiError(err: unknown, url: string): GcpApiError {
  const e = err as { response?: { status?: number; data?: GoogleErrorBody }; message?: string };
  const status = e.response?.status;
  const body = e.response?.data?.error;
  const message = body?.message ?? e.message ?? 'Unknown GCP API error';
  const reasons = [...(body?.details ?? []), ...(body?.errors ?? [])].map((d) => d.reason);
  let kind: GcpErrorKind = 'OTHER';
  if (reasons.includes('SERVICE_DISABLED') || reasons.includes('accessNotConfigured') || /has not been used in project|is disabled/i.test(message)) {
    kind = 'API_DISABLED';
  } else if (status === 401) {
    kind = 'UNAUTHENTICATED';
  } else if (status === 403) {
    kind = 'PERMISSION_DENIED';
  } else if (status === 404) {
    kind = 'NOT_FOUND';
  }
  return new GcpApiError(kind, status, message, url);
}

/**
 * Thin REST client on top of Application Default Credentials.
 * Works with `gcloud auth application-default login`, with
 * `--impersonate-service-account`, and with attached service accounts (Cloud Run, GCE).
 * No key files are ever handled by this application.
 */
export class GcpClient {
  private readonly auth: GoogleAuth;

  constructor(auth?: GoogleAuth) {
    this.auth = auth ?? new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/cloud-platform'] });
  }

  async request<T>(url: string, opts: { method?: 'GET' | 'POST'; body?: unknown; params?: Record<string, string> } = {}): Promise<T> {
    const client = await this.auth.getClient();
    try {
      const res = await client.request<T>({
        url,
        method: opts.method ?? 'GET',
        data: opts.body,
        params: opts.params,
        retry: true,
      });
      return res.data;
    } catch (err) {
      throw toGcpApiError(err, url);
    }
  }

  /** Follows `nextPageToken` and concatenates `itemsKey` arrays. */
  async listAll<T>(url: string, itemsKey: string, params: Record<string, string> = {}): Promise<T[]> {
    const out: T[] = [];
    let pageToken: string | undefined;
    do {
      const page = await this.request<Record<string, unknown>>(url, {
        params: { ...params, ...(pageToken ? { pageToken } : {}) },
      });
      out.push(...((page[itemsKey] as T[] | undefined) ?? []));
      pageToken = page.nextPageToken as string | undefined;
    } while (pageToken);
    return out;
  }

  /** Compute Engine `aggregated/*` lists: `{ items: { "zones/x": { <itemsKey>: [...] } } }`. */
  async listAggregated<T>(url: string, itemsKey: string): Promise<T[]> {
    const out: T[] = [];
    let pageToken: string | undefined;
    do {
      const page = await this.request<{ items?: Record<string, Record<string, unknown>>; nextPageToken?: string }>(url, {
        params: { returnPartialSuccess: 'true', ...(pageToken ? { pageToken } : {}) },
      });
      for (const scoped of Object.values(page.items ?? {})) {
        out.push(...((scoped[itemsKey] as T[] | undefined) ?? []));
      }
      pageToken = page.nextPageToken;
    } while (pageToken);
    return out;
  }

  /** Best-effort description of the identity ADC resolves to. */
  async identity(): Promise<{ principal?: string; projectId?: string }> {
    const projectId = await this.auth.getProjectId().catch(() => undefined);
    try {
      const creds = await this.auth.getCredentials();
      if (creds.client_email) return { principal: creds.client_email, projectId };
    } catch {
      /* fall through to tokeninfo */
    }
    try {
      const client = await this.auth.getClient();
      const { token } = await client.getAccessToken();
      if (token) {
        const info = await fetch(`https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(token)}`);
        if (info.ok) {
          const body = (await info.json()) as { email?: string };
          return { principal: body.email, projectId };
        }
      }
    } catch {
      /* identity is informational only */
    }
    return { projectId };
  }
}

/** Runs `fn` over `items` with at most `limit` in flight. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}
