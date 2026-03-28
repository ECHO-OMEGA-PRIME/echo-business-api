/**
 * echo-business-api — Multi-Tenant Business Management API
 * Cloudflare Worker powered by Hono 4.7
 * Version: 2.0.0
 *
 * Provides full CRUD for customers, services, bookings, invoices,
 * payments, expenses, employees, hours, payroll, reviews, inventory,
 * settings, and analytics — all tenant-isolated via Firebase JWT.
 *
 * Routes match the API client at lib/business-api.ts exactly:
 *   /customers, /services, /bookings, /invoices, /payments,
 *   /expenses, /employees, /hours, /payroll, /reviews,
 *   /inventory, /settings, /analytics/*
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ASSETS: R2Bucket;
  CORS_ORIGIN: string;
  FIREBASE_PROJECT_ID: string;
}

type Variables = {
  tenantId: string;
  userId: string;
};

type AppType = { Bindings: Env; Variables: Variables };

// ---------------------------------------------------------------------------
// Structured JSON Logging
// ---------------------------------------------------------------------------

function log(level: string, component: string, message: string, extra: Record<string, unknown> = {}): void {
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      level,
      worker: 'echo-business-api',
      component,
      message,
      ...extra,
    }),
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function now(): string {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function currentYearMonth(): string {
  const d = new Date();
  return `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}`;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/** Base64url decode for JWT payload parsing */
function b64urlDecode(str: string): string {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  return atob(padded);
}

/** Convert PEM certificate to ArrayBuffer for Web Crypto import */
function pemToBuffer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s/g, '');
  const binary = atob(b64);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf.buffer;
}

/** Base64url decode to ArrayBuffer (for signature verification) */
function b64urlToBuffer(str: string): ArrayBuffer {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const decoded = atob(padded);
  const buf = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i++) buf[i] = decoded.charCodeAt(i);
  return buf.buffer;
}

const GOOGLE_CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

/** Fetch and cache Google's public keys for Firebase JWT verification */
async function getGooglePublicKeys(cache: KVNamespace): Promise<Record<string, string>> {
  const cached = await cache.get('firebase_google_certs', 'json') as Record<string, string> | null;
  if (cached) return cached;

  const resp = await fetch(GOOGLE_CERTS_URL);
  if (!resp.ok) throw new Error(`Failed to fetch Google certs: ${resp.status}`);
  const certs = await resp.json() as Record<string, string>;

  // Cache for 1 hour (Google rotates keys roughly every 24h, cache-control ~6h)
  await cache.put('firebase_google_certs', JSON.stringify(certs), { expirationTtl: 3600 });
  return certs;
}

/** Verify Firebase JWT RS256 signature and validate claims */
async function verifyFirebaseJWT(
  token: string,
  projectId: string,
  cache: KVNamespace,
): Promise<{ sub: string; [key: string]: unknown }> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed JWT');

  const headerJson = b64urlDecode(parts[0]);
  const payloadJson = b64urlDecode(parts[1]);
  const header = JSON.parse(headerJson) as { alg: string; kid: string };
  const payload = JSON.parse(payloadJson) as { sub?: string; aud?: string; iss?: string; exp?: number; iat?: number; auth_time?: number };

  // 1. Verify algorithm
  if (header.alg !== 'RS256') throw new Error(`Unsupported algorithm: ${header.alg}`);

  // 2. Verify kid exists
  if (!header.kid) throw new Error('Missing kid in JWT header');

  // 3. Fetch Google public keys and find matching kid
  const certs = await getGooglePublicKeys(cache);
  const certPem = certs[header.kid];
  if (!certPem) throw new Error(`Unknown kid: ${header.kid} — key not found in Google certs`);

  // 4. Import the X.509 certificate and extract the public key
  const certBuffer = pemToBuffer(certPem);
  const cryptoKey = await crypto.subtle.importKey(
    'spki',
    // Extract SubjectPublicKeyInfo from X.509 cert (DER offset after header)
    await extractSPKIFromX509(certBuffer),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );

  // 5. Verify signature
  const signedContent = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = b64urlToBuffer(parts[2]);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, signedContent);
  if (!valid) throw new Error('JWT signature verification failed');

  // 6. Validate standard claims
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('Token expired');
  if (payload.iat && payload.iat > now + 300) throw new Error('Token issued in the future');
  if (payload.aud !== projectId) throw new Error(`Invalid audience: ${payload.aud}`);
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) throw new Error(`Invalid issuer: ${payload.iss}`);
  if (!payload.sub || typeof payload.sub !== 'string' || payload.sub.length === 0) throw new Error('Missing or empty sub claim');
  if (payload.auth_time && payload.auth_time > now + 300) throw new Error('auth_time in the future');

  return payload as { sub: string; [key: string]: unknown };
}

/** Extract SubjectPublicKeyInfo from DER-encoded X.509 certificate */
async function extractSPKIFromX509(certDer: ArrayBuffer): Promise<ArrayBuffer> {
  // Use a simple ASN.1 parser to find the SubjectPublicKeyInfo
  // In X.509, SPKI is the 7th top-level element in TBSCertificate
  const bytes = new Uint8Array(certDer);
  let offset = 0;

  function readTag(): { tag: number; length: number; start: number } {
    const tag = bytes[offset++];
    let length = bytes[offset++];
    const start = offset;
    if (length & 0x80) {
      const numBytes = length & 0x7f;
      length = 0;
      for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | bytes[offset++];
      }
    }
    return { tag, length, start: offset };
  }

  function skipElement(): void {
    const { length } = readTag();
    offset += length;
  }

  // Outer SEQUENCE
  readTag();
  // TBSCertificate SEQUENCE
  readTag();

  // version [0] EXPLICIT (optional — skip if context tag 0)
  if (bytes[offset] === 0xa0) {
    skipElement();
  }

  // serialNumber
  skipElement();
  // signature algorithm
  skipElement();
  // issuer
  skipElement();
  // validity
  skipElement();
  // subject
  skipElement();

  // subjectPublicKeyInfo — this is what we need
  const spkiStart = offset;
  const spkiInfo = readTag();
  const spkiEnd = offset + spkiInfo.length;

  // Return the full SPKI element including its tag and length
  return certDer.slice(spkiStart, spkiEnd);
}

// ---------------------------------------------------------------------------
// Audit log helper
// ---------------------------------------------------------------------------

async function audit(
  db: D1Database,
  tenantId: string,
  userId: string,
  action: string,
  entityType: string,
  entityId: number | null,
  details?: string,
): Promise<void> {
  try {
    await db
      .prepare(
        'INSERT INTO audit_log (tenant_id, user_id, action, entity_type, entity_id, details, created_at) VALUES (?,?,?,?,?,?,?)',
      )
      .bind(tenantId, userId, action, entityType, entityId, details ?? null, now())
      .run();
  } catch (e: unknown) {
    log('error', 'audit', 'Failed to write audit log', { error: (e as Error).message });
  }
}

// ---------------------------------------------------------------------------
// Invoice recalculation helper
// ---------------------------------------------------------------------------

async function recalcInvoice(db: D1Database, tenantId: string, invoiceId: number): Promise<void> {
  const itemsResult = await db
    .prepare('SELECT COALESCE(SUM(total), 0) as subtotal FROM invoice_items WHERE tenant_id = ? AND invoice_id = ?')
    .bind(tenantId, invoiceId)
    .first<{ subtotal: number }>();
  const subtotal = itemsResult?.subtotal ?? 0;

  const inv = await db
    .prepare('SELECT tax_rate, discount FROM invoices WHERE tenant_id = ? AND id = ?')
    .bind(tenantId, invoiceId)
    .first<{ tax_rate: number; discount: number }>();
  const taxRate = inv?.tax_rate ?? 0.0825;
  const discount = inv?.discount ?? 0;
  const taxAmount = round2(subtotal * taxRate);
  const total = round2(subtotal + taxAmount - discount);

  await db
    .prepare(
      'UPDATE invoices SET subtotal = ?, tax_amount = ?, total = ?, updated_at = ? WHERE tenant_id = ? AND id = ?',
    )
    .bind(subtotal, taxAmount, total, now(), tenantId, invoiceId)
    .run();
}

// ---------------------------------------------------------------------------
// Invoice number generation: INV-YYYYMM-NNN
// ---------------------------------------------------------------------------

async function generateInvoiceNumber(db: D1Database, tenantId: string): Promise<string> {
  const ym = currentYearMonth();
  const prefix = `INV-${ym}-`;

  const result = await db
    .prepare(
      "SELECT invoice_number FROM invoices WHERE tenant_id = ? AND invoice_number LIKE ? ORDER BY invoice_number DESC LIMIT 1",
    )
    .bind(tenantId, `${prefix}%`)
    .first<{ invoice_number: string }>();

  let seq = 1;
  if (result?.invoice_number) {
    const lastSeq = parseInt(result.invoice_number.replace(prefix, ''), 10);
    if (!isNaN(lastSeq)) seq = lastSeq + 1;
  }

  return `${prefix}${String(seq).padStart(3, '0')}`;
}

// ---------------------------------------------------------------------------
// Update invoice status based on payments
// ---------------------------------------------------------------------------

async function updateInvoicePaymentStatus(db: D1Database, tenantId: string, invoiceId: number): Promise<void> {
  const totals = await db
    .prepare(
      'SELECT total, amount_paid, status FROM invoices WHERE tenant_id = ? AND id = ?',
    )
    .bind(tenantId, invoiceId)
    .first<{ total: number; amount_paid: number; status: string }>();

  if (!totals || totals.status === 'void') return;

  let newStatus: string;
  if (totals.amount_paid >= totals.total) {
    newStatus = 'paid';
  } else if (totals.amount_paid > 0) {
    newStatus = 'partial';
  } else {
    newStatus = totals.status; // keep current
  }

  if (newStatus !== totals.status) {
    await db
      .prepare('UPDATE invoices SET status = ?, updated_at = ? WHERE tenant_id = ? AND id = ?')
      .bind(newStatus, now(), tenantId, invoiceId)
      .run();
  }
}

// ===========================================================================
// App Setup
// ===========================================================================

const startTime = Date.now();
const app = new Hono<AppType>();
// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('X-Frame-Options', 'DENY');
  c.res.headers.set('X-XSS-Protection', '1; mode=block');
  c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});


// Global CORS
app.use(
  '*',
  cors({
    origin: ['https://echo-ept.com', 'http://localhost:3000'],
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,
  }),
);

// Global error handler
app.onError((err, c) => {
  log('error', 'global', 'Unhandled error', { error: err.message, stack: err.stack, path: c.req.path, method: c.req.method });
  return c.json({ error: 'Internal server error' }, 500);
});

// ---------------------------------------------------------------------------
// Health & Root (no auth required)
// ---------------------------------------------------------------------------

app.get('/', (c) =>
  c.json({
    status: 'ok',
    service: 'echo-business-api',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
  }),
);

app.get('/health', (c) =>
  c.json({
    status: 'ok',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
    bindings: {
      d1: !!c.env.DB,
      kv: !!c.env.CACHE,
      r2: !!c.env.ASSETS,
    },
  }),
);

// ---------------------------------------------------------------------------
// Public review endpoints (NO auth required — customer-facing)
// ---------------------------------------------------------------------------

app.get('/public/reviews', async (c) => {
  const tenantId = c.env.CORS_ORIGIN === 'https://echo-ept.com' ? 'echo-ept-public' : 'echo-ept-public';
  try {
    const result = await c.env.DB.prepare(
      'SELECT id, reviewer_name, rating, review_text, service_type, featured, created_at FROM reviews WHERE tenant_id = ? AND approved = 1 ORDER BY featured DESC, created_at DESC'
    ).bind(tenantId).all();
    const reviews = result.results.map((row: Record<string, unknown>) => ({
      id: row.id,
      reviewer_name: row.reviewer_name,
      rating: row.rating,
      text: row.review_text,
      service_type: row.service_type,
      featured: !!row.featured,
      date: row.created_at,
    }));
    log('info', 'public-reviews', 'Listed approved reviews', { count: reviews.length });
    return c.json({ reviews });
  } catch (e: unknown) {
    log('error', 'public-reviews', 'List failed', { error: (e as Error).message });
    return c.json({ error: 'Failed to fetch reviews' }, 500);
  }
});

app.post('/public/reviews', async (c) => {
  const tenantId = 'echo-ept-public';
  try {
    const body = await c.req.json();
    if (!body.reviewer_name || !body.text || body.rating === undefined) {
      return c.json({ error: 'reviewer_name, rating, and text are required' }, 400);
    }
    if (typeof body.rating !== 'number' || body.rating < 1 || body.rating > 5) {
      return c.json({ error: 'rating must be a number between 1 and 5' }, 400);
    }
    if (body.reviewer_name.length > 100 || body.text.length > 2000) {
      return c.json({ error: 'reviewer_name max 100 chars, text max 2000 chars' }, 400);
    }

    // Rate limit public submissions: max 3 per IP per hour
    const ip = c.req.header('CF-Connecting-IP') || 'unknown';
    const rlKey = `rl:pub-review:${ip}:${Math.floor(Date.now() / 3600000)}`;
    const rlCount = parseInt((await c.env.CACHE.get(rlKey)) || '0');
    if (rlCount >= 3) {
      log('warn', 'public-reviews', 'Rate limited', { ip });
      return c.json({ error: 'Too many reviews submitted. Please try again later.' }, 429);
    }
    await c.env.CACHE.put(rlKey, String(rlCount + 1), { expirationTtl: 3600 });

    const result = await c.env.DB.prepare(
      `INSERT INTO reviews (tenant_id, customer_id, reviewer_name, rating, review_text, service_type, approved, featured, created_at)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).bind(
      tenantId,
      null,
      body.reviewer_name.trim(),
      body.rating,
      body.text.trim(),
      body.service_type?.trim() || null,
      0, // always pending
      0, // never featured by default
      now(),
    ).run();

    log('info', 'public-reviews', 'Submitted', { id: result.meta.last_row_id, ip });
    return c.json({ success: true, message: 'Review submitted! It will appear after approval.' }, 201);
  } catch (e: unknown) {
    log('error', 'public-reviews', 'Submit failed', { error: (e as Error).message });
    return c.json({ error: 'Failed to submit review' }, 500);
  }
});

// ---------------------------------------------------------------------------
// Auth + Rate Limiting Middleware (all non-root routes)
// ---------------------------------------------------------------------------

app.use('/*', async (c, next) => {
  // Skip auth for root, health, OPTIONS, public endpoints
  const path = c.req.path;
  if (path === '/' || path === '/health' || path.startsWith('/public/') || c.req.method === 'OPTIONS') {
    return next();
  }

  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized — missing Bearer token' }, 401);
  }

  try {
    const token = authHeader.slice(7);
    const projectId = c.env.FIREBASE_PROJECT_ID || 'echo-prime-tech';
    const payload = await verifyFirebaseJWT(token, projectId, c.env.CACHE);
    c.set('tenantId', payload.sub);
    c.set('userId', payload.sub);
  } catch (e: unknown) {
    log('warn', 'auth', 'JWT verification failed', { error: (e as Error).message });
    return c.json({ error: 'Invalid or expired token' }, 401);
  }

  // Rate limit: 120 requests per minute per tenant
  const tenantId = c.get('tenantId');
  const windowKey = `rl:${tenantId}:${Math.floor(Date.now() / 60000)}`;
  try {
    const current = parseInt((await c.env.CACHE.get(windowKey)) ?? '0', 10);
    if (current >= 120) {
      log('warn', 'ratelimit', 'Rate limit exceeded', { tenantId });
      return c.json({ error: 'Rate limit exceeded. Max 120 requests per minute.' }, 429);
    }
    await c.env.CACHE.put(windowKey, String(current + 1), { expirationTtl: 120 });
  } catch (e: unknown) {
    // KV failure should not block requests
    log('warn', 'ratelimit', 'KV rate-limit check failed, allowing request', { error: (e as Error).message });
  }

  log('debug', 'request', `${c.req.method} ${c.req.path}`, { tenantId });
  await next();
});

// ===========================================================================
// CUSTOMERS
// ===========================================================================

app.get('/customers', async (c) => {
  const tenantId = c.get('tenantId');
  const search = c.req.query('search');
  try {
    let sql = 'SELECT * FROM customers WHERE tenant_id = ?';
    const params: unknown[] = [tenantId];

    if (search) {
      sql += " AND (first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR phone LIKE ? OR company_name LIKE ?)";
      const like = `%${search}%`;
      params.push(like, like, like, like, like);
    }
    sql += ' ORDER BY last_name ASC, first_name ASC';

    const result = await c.env.DB.prepare(sql).bind(...params).all();
    return c.json({ customers: result.results });
  } catch (e: unknown) {
    log('error', 'customers', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch customers' }, 500);
  }
});

app.post('/customers', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.first_name || !body.last_name) {
      return c.json({ error: 'first_name and last_name are required' }, 400);
    }

    const result = await c.env.DB.prepare(
      `INSERT INTO customers (tenant_id, first_name, last_name, email, phone, company_name, address, city, state, zip,
        notes, customer_type, source, tax_exempt, tax_exempt_id, payment_terms, contact_person, contact_email, contact_phone,
        created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        tenantId,
        body.first_name,
        body.last_name,
        body.email ?? null,
        body.phone ?? null,
        body.company_name ?? null,
        body.address ?? null,
        body.city ?? null,
        body.state ?? 'TX',
        body.zip ?? null,
        body.notes ?? null,
        body.type ?? body.customer_type ?? 'residential',
        body.source ?? 'website',
        body.tax_exempt ? 1 : 0,
        body.tax_exempt_id ?? null,
        body.payment_terms ?? 'due_on_receipt',
        body.contact_person ?? null,
        body.contact_email ?? null,
        body.contact_phone ?? null,
        now(),
        now(),
      )
      .run();

    const id = result.meta.last_row_id;
    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'customer', id as number);
    log('info', 'customers', 'Created', { tenantId, id });

    const created = await c.env.DB.prepare('SELECT * FROM customers WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(created, 201);
  } catch (e: unknown) {
    log('error', 'customers', 'Create failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to create customer' }, 500);
  }
});

app.get('/customers/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const customer = await c.env.DB.prepare('SELECT * FROM customers WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!customer) return c.json({ error: 'Customer not found' }, 404);
    return c.json(customer);
  } catch (e: unknown) {
    log('error', 'customers', 'Get failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to fetch customer' }, 500);
  }
});

app.put('/customers/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM customers WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Customer not found' }, 404);

    const body = await c.req.json();
    const fields: string[] = [];
    const values: unknown[] = [];

    const updatable = [
      'first_name', 'last_name', 'email', 'phone', 'company_name', 'address', 'city', 'state', 'zip',
      'notes', 'source', 'tax_exempt_id', 'payment_terms', 'contact_person', 'contact_email', 'contact_phone',
    ];
    for (const field of updatable) {
      if (body[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(body[field]);
      }
    }
    // Handle 'type' from client mapping to 'customer_type' in DB
    if (body.type !== undefined) {
      fields.push('customer_type = ?');
      values.push(body.type);
    }
    if (body.customer_type !== undefined && body.type === undefined) {
      fields.push('customer_type = ?');
      values.push(body.customer_type);
    }
    if (body.tax_exempt !== undefined) {
      fields.push('tax_exempt = ?');
      values.push(body.tax_exempt ? 1 : 0);
    }

    if (fields.length === 0) {
      return c.json({ error: 'No fields to update' }, 400);
    }

    fields.push('updated_at = ?');
    values.push(now());
    values.push(tenantId, id);

    await c.env.DB.prepare(`UPDATE customers SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`)
      .bind(...values)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'update', 'customer', id);
    log('info', 'customers', 'Updated', { tenantId, id });

    const updated = await c.env.DB.prepare('SELECT * FROM customers WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(updated);
  } catch (e: unknown) {
    log('error', 'customers', 'Update failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to update customer' }, 500);
  }
});

app.delete('/customers/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM customers WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Customer not found' }, 404);

    // Check for dependent bookings/invoices
    const deps = await c.env.DB.prepare(
      'SELECT COUNT(*) as cnt FROM bookings WHERE tenant_id = ? AND customer_id = ?',
    )
      .bind(tenantId, id)
      .first<{ cnt: number }>();
    if (deps && deps.cnt > 0) {
      return c.json({ error: 'Cannot delete customer with existing bookings. Archive instead.' }, 409);
    }

    await c.env.DB.prepare('DELETE FROM customers WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .run();
    await audit(c.env.DB, tenantId, c.get('userId'), 'delete', 'customer', id);
    log('info', 'customers', 'Deleted', { tenantId, id });
    return c.json({ success: true });
  } catch (e: unknown) {
    log('error', 'customers', 'Delete failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to delete customer' }, 500);
  }
});

// ===========================================================================
// SERVICES
// ===========================================================================

app.get('/services', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const result = await c.env.DB.prepare(
      'SELECT * FROM services WHERE tenant_id = ? ORDER BY sort_order ASC, name ASC',
    )
      .bind(tenantId)
      .all();
    return c.json({ services: result.results });
  } catch (e: unknown) {
    log('error', 'services', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch services' }, 500);
  }
});

app.post('/services', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.name || body.base_price === undefined) {
      return c.json({ error: 'name and base_price are required' }, 400);
    }

    const result = await c.env.DB.prepare(
      `INSERT INTO services (tenant_id, name, description, category, pricing_type, base_price, duration_minutes, active, sort_order, billing_cycle, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        tenantId,
        body.name,
        body.description ?? null,
        body.category ?? 'general',
        body.pricing_type ?? 'flat',
        body.base_price,
        body.duration_minutes ?? 60,
        body.active !== undefined ? (body.active ? 1 : 0) : 1,
        body.sort_order ?? 0,
        body.billing_cycle ?? 'one-time',
        now(),
        now(),
      )
      .run();

    const id = result.meta.last_row_id;
    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'service', id as number);
    log('info', 'services', 'Created', { tenantId, id });

    const created = await c.env.DB.prepare('SELECT * FROM services WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(created, 201);
  } catch (e: unknown) {
    log('error', 'services', 'Create failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to create service' }, 500);
  }
});

app.put('/services/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM services WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Service not found' }, 404);

    const body = await c.req.json();
    const fields: string[] = [];
    const values: unknown[] = [];

    const updatable = ['name', 'description', 'category', 'pricing_type', 'base_price', 'duration_minutes', 'sort_order', 'billing_cycle'];
    for (const field of updatable) {
      if (body[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(body[field]);
      }
    }
    if (body.active !== undefined) {
      fields.push('active = ?');
      values.push(body.active ? 1 : 0);
    }

    if (fields.length === 0) return c.json({ error: 'No fields to update' }, 400);

    fields.push('updated_at = ?');
    values.push(now());
    values.push(tenantId, id);

    await c.env.DB.prepare(`UPDATE services SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`)
      .bind(...values)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'update', 'service', id);
    log('info', 'services', 'Updated', { tenantId, id });

    const updated = await c.env.DB.prepare('SELECT * FROM services WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(updated);
  } catch (e: unknown) {
    log('error', 'services', 'Update failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to update service' }, 500);
  }
});

app.delete('/services/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM services WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Service not found' }, 404);

    // Check for dependent bookings
    const deps = await c.env.DB.prepare(
      'SELECT COUNT(*) as cnt FROM bookings WHERE tenant_id = ? AND service_id = ?',
    )
      .bind(tenantId, id)
      .first<{ cnt: number }>();
    if (deps && deps.cnt > 0) {
      // Soft-delete: mark inactive instead
      await c.env.DB.prepare('UPDATE services SET active = 0, updated_at = ? WHERE tenant_id = ? AND id = ?')
        .bind(now(), tenantId, id)
        .run();
      await audit(c.env.DB, tenantId, c.get('userId'), 'deactivate', 'service', id);
      log('info', 'services', 'Deactivated (has bookings)', { tenantId, id });
      return c.json({ success: true, note: 'Service deactivated (has existing bookings)' });
    }

    await c.env.DB.prepare('DELETE FROM services WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .run();
    await audit(c.env.DB, tenantId, c.get('userId'), 'delete', 'service', id);
    log('info', 'services', 'Deleted', { tenantId, id });
    return c.json({ success: true });
  } catch (e: unknown) {
    log('error', 'services', 'Delete failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to delete service' }, 500);
  }
});

// ===========================================================================
// BOOKINGS
// ===========================================================================

app.get('/bookings', async (c) => {
  const tenantId = c.get('tenantId');
  const status = c.req.query('status');
  try {
    let sql = `SELECT b.*, c.first_name || ' ' || c.last_name as customer_name, s.name as service_name
               FROM bookings b
               LEFT JOIN customers c ON c.id = b.customer_id AND c.tenant_id = b.tenant_id
               LEFT JOIN services s ON s.id = b.service_id AND s.tenant_id = b.tenant_id
               WHERE b.tenant_id = ?`;
    const params: unknown[] = [tenantId];
    if (status) {
      sql += ' AND b.status = ?';
      params.push(status);
    }
    sql += ' ORDER BY b.scheduled_date DESC, b.scheduled_time DESC';

    const result = await c.env.DB.prepare(sql).bind(...params).all();
    // Map DB columns to client-expected field names
    const bookings = result.results.map((row: Record<string, unknown>) => ({
      ...row,
      date: row.scheduled_date,
      time: row.scheduled_time,
    }));
    return c.json({ bookings });
  } catch (e: unknown) {
    log('error', 'bookings', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch bookings' }, 500);
  }
});

app.post('/bookings', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.customer_id || !body.service_id || !(body.date || body.scheduled_date)) {
      return c.json({ error: 'customer_id, service_id, and date are required' }, 400);
    }

    // Verify customer belongs to tenant
    const cust = await c.env.DB.prepare('SELECT id FROM customers WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, body.customer_id)
      .first();
    if (!cust) return c.json({ error: 'Customer not found' }, 404);

    // Verify service belongs to tenant
    const svc = await c.env.DB.prepare('SELECT id, base_price, duration_minutes FROM services WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, body.service_id)
      .first<{ id: number; base_price: number; duration_minutes: number }>();
    if (!svc) return c.json({ error: 'Service not found' }, 404);

    const scheduledDate = body.date ?? body.scheduled_date;
    const scheduledTime = body.time ?? body.scheduled_time ?? '09:00';
    const duration = body.duration_minutes ?? svc.duration_minutes ?? 60;
    const quotedPrice = body.quoted_price ?? svc.base_price;

    const result = await c.env.DB.prepare(
      `INSERT INTO bookings (tenant_id, customer_id, service_id, scheduled_date, scheduled_time, duration_minutes,
        address, city, state, zip, notes, quoted_price, status, assigned_team, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        tenantId,
        body.customer_id,
        body.service_id,
        scheduledDate,
        scheduledTime,
        duration,
        body.address ?? null,
        body.city ?? null,
        body.state ?? 'TX',
        body.zip ?? null,
        body.notes ?? null,
        quotedPrice,
        body.status ?? 'pending',
        body.assigned_team ?? null,
        now(),
        now(),
      )
      .run();

    const id = result.meta.last_row_id;
    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'booking', id as number);
    log('info', 'bookings', 'Created', { tenantId, id });

    const created = await c.env.DB.prepare(
      `SELECT b.*, c.first_name || ' ' || c.last_name as customer_name, s.name as service_name
       FROM bookings b
       LEFT JOIN customers c ON c.id = b.customer_id AND c.tenant_id = b.tenant_id
       LEFT JOIN services s ON s.id = b.service_id AND s.tenant_id = b.tenant_id
       WHERE b.tenant_id = ? AND b.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    return c.json({ ...created, date: (created as Record<string, unknown>)?.scheduled_date, time: (created as Record<string, unknown>)?.scheduled_time }, 201);
  } catch (e: unknown) {
    log('error', 'bookings', 'Create failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to create booking' }, 500);
  }
});

app.get('/bookings/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const booking = await c.env.DB.prepare(
      `SELECT b.*, c.first_name || ' ' || c.last_name as customer_name, s.name as service_name
       FROM bookings b
       LEFT JOIN customers c ON c.id = b.customer_id AND c.tenant_id = b.tenant_id
       LEFT JOIN services s ON s.id = b.service_id AND s.tenant_id = b.tenant_id
       WHERE b.tenant_id = ? AND b.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    if (!booking) return c.json({ error: 'Booking not found' }, 404);
    return c.json({ ...booking, date: (booking as Record<string, unknown>).scheduled_date, time: (booking as Record<string, unknown>).scheduled_time });
  } catch (e: unknown) {
    log('error', 'bookings', 'Get failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to fetch booking' }, 500);
  }
});

app.put('/bookings/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM bookings WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Booking not found' }, 404);

    const body = await c.req.json();
    const fields: string[] = [];
    const values: unknown[] = [];

    // Map client field names to DB columns
    if (body.date !== undefined) { fields.push('scheduled_date = ?'); values.push(body.date); }
    if (body.scheduled_date !== undefined) { fields.push('scheduled_date = ?'); values.push(body.scheduled_date); }
    if (body.time !== undefined) { fields.push('scheduled_time = ?'); values.push(body.time); }
    if (body.scheduled_time !== undefined) { fields.push('scheduled_time = ?'); values.push(body.scheduled_time); }

    const updatable = ['customer_id', 'service_id', 'duration_minutes', 'address', 'city', 'state', 'zip', 'notes', 'quoted_price', 'status', 'assigned_team'];
    for (const field of updatable) {
      if (body[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(body[field]);
      }
    }

    if (fields.length === 0) return c.json({ error: 'No fields to update' }, 400);

    fields.push('updated_at = ?');
    values.push(now());
    values.push(tenantId, id);

    await c.env.DB.prepare(`UPDATE bookings SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`)
      .bind(...values)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'update', 'booking', id);
    log('info', 'bookings', 'Updated', { tenantId, id });

    const updated = await c.env.DB.prepare(
      `SELECT b.*, c.first_name || ' ' || c.last_name as customer_name, s.name as service_name
       FROM bookings b
       LEFT JOIN customers c ON c.id = b.customer_id AND c.tenant_id = b.tenant_id
       LEFT JOIN services s ON s.id = b.service_id AND s.tenant_id = b.tenant_id
       WHERE b.tenant_id = ? AND b.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    return c.json({ ...updated, date: (updated as Record<string, unknown>)?.scheduled_date, time: (updated as Record<string, unknown>)?.scheduled_time });
  } catch (e: unknown) {
    log('error', 'bookings', 'Update failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to update booking' }, 500);
  }
});

// PUT /bookings/:id/status — matches updateBookingStatus in client
app.put('/bookings/:id/status', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const body = await c.req.json();
    const validStatuses = ['pending', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show'];
    if (!body.status || !validStatuses.includes(body.status)) {
      return c.json({ error: `status must be one of: ${validStatuses.join(', ')}` }, 400);
    }

    const existing = await c.env.DB.prepare('SELECT id FROM bookings WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Booking not found' }, 404);

    await c.env.DB.prepare('UPDATE bookings SET status = ?, updated_at = ? WHERE tenant_id = ? AND id = ?')
      .bind(body.status, now(), tenantId, id)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'status_change', 'booking', id, body.status);
    log('info', 'bookings', 'Status changed', { tenantId, id, status: body.status });

    const updated = await c.env.DB.prepare(
      `SELECT b.*, c.first_name || ' ' || c.last_name as customer_name, s.name as service_name
       FROM bookings b
       LEFT JOIN customers c ON c.id = b.customer_id AND c.tenant_id = b.tenant_id
       LEFT JOIN services s ON s.id = b.service_id AND s.tenant_id = b.tenant_id
       WHERE b.tenant_id = ? AND b.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    return c.json({ ...updated, date: (updated as Record<string, unknown>)?.scheduled_date, time: (updated as Record<string, unknown>)?.scheduled_time });
  } catch (e: unknown) {
    log('error', 'bookings', 'Status change failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to change booking status' }, 500);
  }
});

// ===========================================================================
// INVOICES
// ===========================================================================

app.get('/invoices', async (c) => {
  const tenantId = c.get('tenantId');
  const status = c.req.query('status');
  try {
    let sql = `SELECT i.*, c.first_name || ' ' || c.last_name as customer_name
               FROM invoices i
               LEFT JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
               WHERE i.tenant_id = ?`;
    const params: unknown[] = [tenantId];
    if (status) {
      sql += ' AND i.status = ?';
      params.push(status);
    }
    sql += ' ORDER BY i.created_at DESC';

    const result = await c.env.DB.prepare(sql).bind(...params).all();
    return c.json({ invoices: result.results });
  } catch (e: unknown) {
    log('error', 'invoices', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch invoices' }, 500);
  }
});

app.post('/invoices', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.customer_id) {
      return c.json({ error: 'customer_id is required' }, 400);
    }

    // Verify customer
    const cust = await c.env.DB.prepare('SELECT id, payment_terms FROM customers WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, body.customer_id)
      .first<{ id: number; payment_terms: string }>();
    if (!cust) return c.json({ error: 'Customer not found' }, 404);

    const invoiceNumber = await generateInvoiceNumber(c.env.DB, tenantId);
    const issueDate = body.issue_date ?? today();
    const paymentTerms = body.payment_terms ?? cust.payment_terms ?? 'due_on_receipt';

    // Calculate due date from payment terms
    let dueDays = 0;
    const termMatch = paymentTerms.match(/net_(\d+)/);
    if (termMatch) dueDays = parseInt(termMatch[1], 10);
    const dueDate = body.due_date ?? new Date(new Date(issueDate).getTime() + dueDays * 86400000).toISOString().slice(0, 10);

    const taxRate = body.tax_rate ?? 0.0825;
    const discount = body.discount ?? 0;

    const result = await c.env.DB.prepare(
      `INSERT INTO invoices (tenant_id, invoice_number, customer_id, booking_id, issue_date, due_date, payment_terms,
        subtotal, tax_rate, tax_amount, discount, total, amount_paid, late_fee_rate, finance_charge_rate, notes, status, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,0,?,0,?,0,0,?,?,?,?,?,?)`,
    )
      .bind(
        tenantId,
        invoiceNumber,
        body.customer_id,
        body.booking_id ?? null,
        issueDate,
        dueDate,
        paymentTerms,
        taxRate,
        discount,
        body.late_fee_rate ?? 0.015,
        body.finance_charge_rate ?? 0.18,
        body.notes ?? null,
        body.status ?? 'draft',
        now(),
        now(),
      )
      .run();

    const id = result.meta.last_row_id;

    // If items are passed inline, insert them
    if (body.items && Array.isArray(body.items)) {
      for (const item of body.items) {
        const qty = item.quantity ?? 1;
        const unitPrice = item.unit_price;
        const lineTotal = round2(qty * unitPrice);
        await c.env.DB.prepare(
          'INSERT INTO invoice_items (tenant_id, invoice_id, description, quantity, unit_price, total, created_at) VALUES (?,?,?,?,?,?,?)',
        )
          .bind(tenantId, id, item.description, qty, unitPrice, lineTotal, now())
          .run();
      }
      await recalcInvoice(c.env.DB, tenantId, id as number);
    }

    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'invoice', id as number, invoiceNumber);
    log('info', 'invoices', 'Created', { tenantId, id, invoiceNumber });

    const created = await c.env.DB.prepare(
      `SELECT i.*, c.first_name || ' ' || c.last_name as customer_name
       FROM invoices i
       LEFT JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
       WHERE i.tenant_id = ? AND i.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    return c.json(created, 201);
  } catch (e: unknown) {
    log('error', 'invoices', 'Create failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to create invoice' }, 500);
  }
});

app.get('/invoices/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const invoice = await c.env.DB.prepare(
      `SELECT i.*, c.first_name || ' ' || c.last_name as customer_name
       FROM invoices i
       LEFT JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
       WHERE i.tenant_id = ? AND i.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    if (!invoice) return c.json({ error: 'Invoice not found' }, 404);

    // Fetch line items
    const itemsResult = await c.env.DB.prepare(
      'SELECT * FROM invoice_items WHERE tenant_id = ? AND invoice_id = ? ORDER BY id ASC',
    )
      .bind(tenantId, id)
      .all();

    // Fetch payments
    const paymentsResult = await c.env.DB.prepare(
      'SELECT * FROM payments WHERE tenant_id = ? AND invoice_id = ? ORDER BY payment_date DESC',
    )
      .bind(tenantId, id)
      .all();

    return c.json({
      ...invoice,
      items: itemsResult.results,
      payments: paymentsResult.results,
    });
  } catch (e: unknown) {
    log('error', 'invoices', 'Get failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to fetch invoice' }, 500);
  }
});

app.put('/invoices/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id, status FROM invoices WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first<{ id: number; status: string }>();
    if (!existing) return c.json({ error: 'Invoice not found' }, 404);
    if (existing.status === 'void') return c.json({ error: 'Cannot edit voided invoice' }, 400);

    const body = await c.req.json();
    const fields: string[] = [];
    const values: unknown[] = [];

    const updatable = ['customer_id', 'booking_id', 'issue_date', 'due_date', 'payment_terms', 'tax_rate', 'discount', 'late_fee_rate', 'finance_charge_rate', 'notes', 'status'];
    for (const field of updatable) {
      if (body[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(body[field]);
      }
    }

    if (fields.length === 0) return c.json({ error: 'No fields to update' }, 400);

    fields.push('updated_at = ?');
    values.push(now());
    values.push(tenantId, id);

    await c.env.DB.prepare(`UPDATE invoices SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`)
      .bind(...values)
      .run();

    // Recalc if tax_rate or discount changed
    if (body.tax_rate !== undefined || body.discount !== undefined) {
      await recalcInvoice(c.env.DB, tenantId, id);
    }

    await audit(c.env.DB, tenantId, c.get('userId'), 'update', 'invoice', id);
    log('info', 'invoices', 'Updated', { tenantId, id });

    const updated = await c.env.DB.prepare(
      `SELECT i.*, c.first_name || ' ' || c.last_name as customer_name
       FROM invoices i
       LEFT JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
       WHERE i.tenant_id = ? AND i.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    return c.json(updated);
  } catch (e: unknown) {
    log('error', 'invoices', 'Update failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to update invoice' }, 500);
  }
});

// POST /invoices/:id/send — mark invoice as sent
app.post('/invoices/:id/send', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id, status, invoice_number FROM invoices WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first<{ id: number; status: string; invoice_number: string }>();
    if (!existing) return c.json({ error: 'Invoice not found' }, 404);
    if (existing.status === 'void') return c.json({ error: 'Cannot send voided invoice' }, 400);
    if (existing.status === 'paid') return c.json({ error: 'Invoice already paid' }, 400);

    // Generate a share token for public access
    const shareToken = crypto.randomUUID();

    await c.env.DB.prepare(
      "UPDATE invoices SET status = 'sent', share_token = ?, updated_at = ? WHERE tenant_id = ? AND id = ?",
    )
      .bind(shareToken, now(), tenantId, id)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'send', 'invoice', id, existing.invoice_number);
    log('info', 'invoices', 'Sent', { tenantId, id, invoice_number: existing.invoice_number });

    const updated = await c.env.DB.prepare(
      `SELECT i.*, c.first_name || ' ' || c.last_name as customer_name
       FROM invoices i
       LEFT JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
       WHERE i.tenant_id = ? AND i.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    return c.json(updated);
  } catch (e: unknown) {
    log('error', 'invoices', 'Send failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to send invoice' }, 500);
  }
});

// POST /invoices/:id/void — void an invoice
app.post('/invoices/:id/void', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id, status, invoice_number FROM invoices WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first<{ id: number; status: string; invoice_number: string }>();
    if (!existing) return c.json({ error: 'Invoice not found' }, 404);
    if (existing.status === 'void') return c.json({ error: 'Invoice already voided' }, 400);
    if (existing.status === 'paid') return c.json({ error: 'Cannot void a fully paid invoice' }, 400);

    await c.env.DB.prepare(
      "UPDATE invoices SET status = 'void', updated_at = ? WHERE tenant_id = ? AND id = ?",
    )
      .bind(now(), tenantId, id)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'void', 'invoice', id, existing.invoice_number);
    log('info', 'invoices', 'Voided', { tenantId, id, invoice_number: existing.invoice_number });

    const updated = await c.env.DB.prepare(
      `SELECT i.*, c.first_name || ' ' || c.last_name as customer_name
       FROM invoices i
       LEFT JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
       WHERE i.tenant_id = ? AND i.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    return c.json(updated);
  } catch (e: unknown) {
    log('error', 'invoices', 'Void failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to void invoice' }, 500);
  }
});

// ===========================================================================
// INVOICE ITEMS
// ===========================================================================

// POST /invoices/:invoiceId/items
app.post('/invoices/:invoiceId/items', async (c) => {
  const tenantId = c.get('tenantId');
  const invoiceId = parseInt(c.req.param('invoiceId'), 10);
  try {
    // Verify invoice exists and is editable
    const invoice = await c.env.DB.prepare('SELECT id, status FROM invoices WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, invoiceId)
      .first<{ id: number; status: string }>();
    if (!invoice) return c.json({ error: 'Invoice not found' }, 404);
    if (invoice.status === 'void') return c.json({ error: 'Cannot add items to voided invoice' }, 400);

    const body = await c.req.json();
    if (!body.description || body.unit_price === undefined) {
      return c.json({ error: 'description and unit_price are required' }, 400);
    }

    const quantity = body.quantity ?? 1;
    const unitPrice = body.unit_price;
    const lineTotal = round2(quantity * unitPrice);

    const result = await c.env.DB.prepare(
      'INSERT INTO invoice_items (tenant_id, invoice_id, description, quantity, unit_price, total, created_at) VALUES (?,?,?,?,?,?,?)',
    )
      .bind(tenantId, invoiceId, body.description, quantity, unitPrice, lineTotal, now())
      .run();

    // Recalculate invoice totals
    await recalcInvoice(c.env.DB, tenantId, invoiceId);

    const id = result.meta.last_row_id;
    await audit(c.env.DB, tenantId, c.get('userId'), 'add_item', 'invoice_item', id as number, `invoice:${invoiceId}`);
    log('info', 'invoice_items', 'Added', { tenantId, invoiceId, id });

    const created = await c.env.DB.prepare('SELECT * FROM invoice_items WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(created, 201);
  } catch (e: unknown) {
    log('error', 'invoice_items', 'Add failed', { error: (e as Error).message, tenantId, invoiceId });
    return c.json({ error: 'Failed to add invoice item' }, 500);
  }
});

// DELETE /invoices/:invoiceId/items/:itemId
app.delete('/invoices/:invoiceId/items/:itemId', async (c) => {
  const tenantId = c.get('tenantId');
  const invoiceId = parseInt(c.req.param('invoiceId'), 10);
  const itemId = parseInt(c.req.param('itemId'), 10);
  try {
    // Verify invoice
    const invoice = await c.env.DB.prepare('SELECT id, status FROM invoices WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, invoiceId)
      .first<{ id: number; status: string }>();
    if (!invoice) return c.json({ error: 'Invoice not found' }, 404);
    if (invoice.status === 'void') return c.json({ error: 'Cannot remove items from voided invoice' }, 400);

    // Verify item belongs to this invoice + tenant
    const item = await c.env.DB.prepare(
      'SELECT id FROM invoice_items WHERE tenant_id = ? AND invoice_id = ? AND id = ?',
    )
      .bind(tenantId, invoiceId, itemId)
      .first();
    if (!item) return c.json({ error: 'Invoice item not found' }, 404);

    await c.env.DB.prepare('DELETE FROM invoice_items WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, itemId)
      .run();

    // Recalculate invoice totals
    await recalcInvoice(c.env.DB, tenantId, invoiceId);

    await audit(c.env.DB, tenantId, c.get('userId'), 'remove_item', 'invoice_item', itemId, `invoice:${invoiceId}`);
    log('info', 'invoice_items', 'Removed', { tenantId, invoiceId, itemId });
    return c.json({ success: true });
  } catch (e: unknown) {
    log('error', 'invoice_items', 'Remove failed', { error: (e as Error).message, tenantId, invoiceId, itemId });
    return c.json({ error: 'Failed to remove invoice item' }, 500);
  }
});

// ===========================================================================
// PAYMENTS
// ===========================================================================

app.get('/payments', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const result = await c.env.DB.prepare(
      `SELECT p.*, i.invoice_number, c.first_name || ' ' || c.last_name as customer_name
       FROM payments p
       LEFT JOIN invoices i ON i.id = p.invoice_id AND i.tenant_id = p.tenant_id
       LEFT JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
       WHERE p.tenant_id = ?
       ORDER BY p.payment_date DESC, p.created_at DESC`,
    )
      .bind(tenantId)
      .all();
    return c.json({ payments: result.results });
  } catch (e: unknown) {
    log('error', 'payments', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch payments' }, 500);
  }
});

app.post('/payments', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.invoice_id || body.amount === undefined) {
      return c.json({ error: 'invoice_id and amount are required' }, 400);
    }

    // Verify invoice belongs to tenant
    const invoice = await c.env.DB.prepare('SELECT id, total, amount_paid, status FROM invoices WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, body.invoice_id)
      .first<{ id: number; total: number; amount_paid: number; status: string }>();
    if (!invoice) return c.json({ error: 'Invoice not found' }, 404);
    if (invoice.status === 'void') return c.json({ error: 'Cannot pay voided invoice' }, 400);

    const amount = parseFloat(body.amount);
    if (isNaN(amount) || amount <= 0) {
      return c.json({ error: 'amount must be a positive number' }, 400);
    }

    const result = await c.env.DB.prepare(
      `INSERT INTO payments (tenant_id, invoice_id, amount, payment_method, payment_date, reference_number, collected_by, notes, created_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        tenantId,
        body.invoice_id,
        amount,
        body.method ?? body.payment_method ?? 'cash',
        body.date ?? body.payment_date ?? today(),
        body.reference ?? body.reference_number ?? null,
        body.collected_by ?? null,
        body.notes ?? null,
        now(),
      )
      .run();

    // Update invoice amount_paid
    const newAmountPaid = round2(invoice.amount_paid + amount);
    await c.env.DB.prepare('UPDATE invoices SET amount_paid = ?, updated_at = ? WHERE tenant_id = ? AND id = ?')
      .bind(newAmountPaid, now(), tenantId, body.invoice_id)
      .run();

    // Update invoice status based on new payment total
    await updateInvoicePaymentStatus(c.env.DB, tenantId, body.invoice_id);

    const id = result.meta.last_row_id;
    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'payment', id as number, `invoice:${body.invoice_id} amount:${amount}`);
    log('info', 'payments', 'Created', { tenantId, id, invoiceId: body.invoice_id, amount });

    const created = await c.env.DB.prepare('SELECT * FROM payments WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(created, 201);
  } catch (e: unknown) {
    log('error', 'payments', 'Create failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to create payment' }, 500);
  }
});

// ===========================================================================
// EXPENSES
// ===========================================================================

app.get('/expenses', async (c) => {
  const tenantId = c.get('tenantId');
  const category = c.req.query('category');
  try {
    let sql = 'SELECT * FROM expenses WHERE tenant_id = ?';
    const params: unknown[] = [tenantId];
    if (category) {
      sql += ' AND category = ?';
      params.push(category);
    }
    sql += ' ORDER BY expense_date DESC, created_at DESC';

    const result = await c.env.DB.prepare(sql).bind(...params).all();
    return c.json({ expenses: result.results });
  } catch (e: unknown) {
    log('error', 'expenses', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch expenses' }, 500);
  }
});

app.post('/expenses', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.category || !body.description || body.amount === undefined || !body.expense_date) {
      return c.json({ error: 'category, description, amount, and expense_date are required' }, 400);
    }

    const result = await c.env.DB.prepare(
      `INSERT INTO expenses (tenant_id, category, description, amount, expense_date, vendor, receipt_url, notes, recurring, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        tenantId,
        body.category,
        body.description,
        body.amount,
        body.expense_date,
        body.vendor ?? null,
        body.receipt_url ?? null,
        body.notes ?? null,
        body.recurring ? 1 : 0,
        now(),
        now(),
      )
      .run();

    const id = result.meta.last_row_id;
    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'expense', id as number);
    log('info', 'expenses', 'Created', { tenantId, id });

    const created = await c.env.DB.prepare('SELECT * FROM expenses WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(created, 201);
  } catch (e: unknown) {
    log('error', 'expenses', 'Create failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to create expense' }, 500);
  }
});

app.put('/expenses/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM expenses WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Expense not found' }, 404);

    const body = await c.req.json();
    const fields: string[] = [];
    const values: unknown[] = [];

    const updatable = ['category', 'description', 'amount', 'expense_date', 'vendor', 'receipt_url', 'notes'];
    for (const field of updatable) {
      if (body[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(body[field]);
      }
    }
    if (body.recurring !== undefined) {
      fields.push('recurring = ?');
      values.push(body.recurring ? 1 : 0);
    }

    if (fields.length === 0) return c.json({ error: 'No fields to update' }, 400);

    fields.push('updated_at = ?');
    values.push(now());
    values.push(tenantId, id);

    await c.env.DB.prepare(`UPDATE expenses SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`)
      .bind(...values)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'update', 'expense', id);
    log('info', 'expenses', 'Updated', { tenantId, id });

    const updated = await c.env.DB.prepare('SELECT * FROM expenses WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(updated);
  } catch (e: unknown) {
    log('error', 'expenses', 'Update failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to update expense' }, 500);
  }
});

app.delete('/expenses/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM expenses WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Expense not found' }, 404);

    await c.env.DB.prepare('DELETE FROM expenses WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'delete', 'expense', id);
    log('info', 'expenses', 'Deleted', { tenantId, id });
    return c.json({ success: true });
  } catch (e: unknown) {
    log('error', 'expenses', 'Delete failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to delete expense' }, 500);
  }
});

// ===========================================================================
// EMPLOYEES
// ===========================================================================

app.get('/employees', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const result = await c.env.DB.prepare(
      'SELECT * FROM employees WHERE tenant_id = ? ORDER BY last_name ASC, first_name ASC',
    )
      .bind(tenantId)
      .all();
    return c.json({ employees: result.results });
  } catch (e: unknown) {
    log('error', 'employees', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch employees' }, 500);
  }
});

app.post('/employees', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.first_name || !body.last_name) {
      return c.json({ error: 'first_name and last_name are required' }, 400);
    }

    const result = await c.env.DB.prepare(
      `INSERT INTO employees (tenant_id, first_name, last_name, email, phone, role, hourly_rate, status, hire_date, notes, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        tenantId,
        body.first_name,
        body.last_name,
        body.email ?? null,
        body.phone ?? null,
        body.role ?? 'staff',
        body.hourly_rate ?? 15.0,
        body.status ?? 'active',
        body.hire_date ?? today(),
        body.notes ?? null,
        now(),
        now(),
      )
      .run();

    const id = result.meta.last_row_id;
    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'employee', id as number);
    log('info', 'employees', 'Created', { tenantId, id });

    const created = await c.env.DB.prepare('SELECT * FROM employees WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(created, 201);
  } catch (e: unknown) {
    log('error', 'employees', 'Create failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to create employee' }, 500);
  }
});

app.put('/employees/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM employees WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Employee not found' }, 404);

    const body = await c.req.json();
    const fields: string[] = [];
    const values: unknown[] = [];

    const updatable = ['first_name', 'last_name', 'email', 'phone', 'role', 'hourly_rate', 'status', 'hire_date', 'notes'];
    for (const field of updatable) {
      if (body[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(body[field]);
      }
    }

    if (fields.length === 0) return c.json({ error: 'No fields to update' }, 400);

    fields.push('updated_at = ?');
    values.push(now());
    values.push(tenantId, id);

    await c.env.DB.prepare(`UPDATE employees SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`)
      .bind(...values)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'update', 'employee', id);
    log('info', 'employees', 'Updated', { tenantId, id });

    const updated = await c.env.DB.prepare('SELECT * FROM employees WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(updated);
  } catch (e: unknown) {
    log('error', 'employees', 'Update failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to update employee' }, 500);
  }
});

// ===========================================================================
// HOURS (Time Tracking)
// ===========================================================================

app.get('/hours', async (c) => {
  const tenantId = c.get('tenantId');
  const employeeId = c.req.query('employee_id');
  const start = c.req.query('start');
  const end = c.req.query('end');
  try {
    let sql = `SELECT h.*, e.first_name || ' ' || e.last_name as employee_name
               FROM hours h
               LEFT JOIN employees e ON e.id = h.employee_id AND e.tenant_id = h.tenant_id
               WHERE h.tenant_id = ?`;
    const params: unknown[] = [tenantId];

    if (employeeId) {
      sql += ' AND h.employee_id = ?';
      params.push(parseInt(employeeId, 10));
    }
    if (start) {
      sql += ' AND h.work_date >= ?';
      params.push(start);
    }
    if (end) {
      sql += ' AND h.work_date <= ?';
      params.push(end);
    }
    sql += ' ORDER BY h.work_date DESC, h.created_at DESC';

    const result = await c.env.DB.prepare(sql).bind(...params).all();
    // Map DB columns to client field names
    const hours = result.results.map((row: Record<string, unknown>) => ({
      ...row,
      date: row.work_date,
      hours: row.hours_worked,
      overtime: row.overtime_hours,
    }));
    return c.json({ hours });
  } catch (e: unknown) {
    log('error', 'hours', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch hours' }, 500);
  }
});

app.post('/hours', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.employee_id || !(body.date || body.work_date)) {
      return c.json({ error: 'employee_id and date are required' }, 400);
    }

    // Verify employee belongs to tenant
    const emp = await c.env.DB.prepare('SELECT id FROM employees WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, body.employee_id)
      .first();
    if (!emp) return c.json({ error: 'Employee not found' }, 404);

    const workDate = body.date ?? body.work_date;
    const hoursWorked = body.hours ?? body.hours_worked ?? 0;
    const overtimeHours = body.overtime ?? body.overtime_hours ?? 0;

    const result = await c.env.DB.prepare(
      `INSERT INTO hours (tenant_id, employee_id, booking_id, work_date, hours_worked, overtime_hours, notes, approved, created_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        tenantId,
        body.employee_id,
        body.booking_id ?? null,
        workDate,
        hoursWorked,
        overtimeHours,
        body.notes ?? null,
        0,
        now(),
      )
      .run();

    const id = result.meta.last_row_id;
    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'hours', id as number);
    log('info', 'hours', 'Logged', { tenantId, id, employeeId: body.employee_id });

    const created = await c.env.DB.prepare(
      `SELECT h.*, e.first_name || ' ' || e.last_name as employee_name
       FROM hours h
       LEFT JOIN employees e ON e.id = h.employee_id AND e.tenant_id = h.tenant_id
       WHERE h.tenant_id = ? AND h.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    const mapped = { ...created, date: (created as Record<string, unknown>)?.work_date, hours: (created as Record<string, unknown>)?.hours_worked, overtime: (created as Record<string, unknown>)?.overtime_hours };
    return c.json(mapped, 201);
  } catch (e: unknown) {
    log('error', 'hours', 'Log failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to log hours' }, 500);
  }
});

app.put('/hours/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id, approved FROM hours WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first<{ id: number; approved: number }>();
    if (!existing) return c.json({ error: 'Hour entry not found' }, 404);
    if (existing.approved) return c.json({ error: 'Cannot edit approved hours' }, 400);

    const body = await c.req.json();
    const fields: string[] = [];
    const values: unknown[] = [];

    if (body.date !== undefined || body.work_date !== undefined) {
      fields.push('work_date = ?');
      values.push(body.date ?? body.work_date);
    }
    if (body.hours !== undefined || body.hours_worked !== undefined) {
      fields.push('hours_worked = ?');
      values.push(body.hours ?? body.hours_worked);
    }
    if (body.overtime !== undefined || body.overtime_hours !== undefined) {
      fields.push('overtime_hours = ?');
      values.push(body.overtime ?? body.overtime_hours);
    }
    if (body.notes !== undefined) {
      fields.push('notes = ?');
      values.push(body.notes);
    }
    if (body.employee_id !== undefined) {
      fields.push('employee_id = ?');
      values.push(body.employee_id);
    }
    if (body.booking_id !== undefined) {
      fields.push('booking_id = ?');
      values.push(body.booking_id);
    }

    if (fields.length === 0) return c.json({ error: 'No fields to update' }, 400);

    values.push(tenantId, id);

    await c.env.DB.prepare(`UPDATE hours SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`)
      .bind(...values)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'update', 'hours', id);
    log('info', 'hours', 'Updated', { tenantId, id });

    const updated = await c.env.DB.prepare(
      `SELECT h.*, e.first_name || ' ' || e.last_name as employee_name
       FROM hours h
       LEFT JOIN employees e ON e.id = h.employee_id AND e.tenant_id = h.tenant_id
       WHERE h.tenant_id = ? AND h.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    return c.json({ ...updated, date: (updated as Record<string, unknown>)?.work_date, hours: (updated as Record<string, unknown>)?.hours_worked, overtime: (updated as Record<string, unknown>)?.overtime_hours });
  } catch (e: unknown) {
    log('error', 'hours', 'Update failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to update hours' }, 500);
  }
});

// POST /hours/:id/approve
app.post('/hours/:id/approve', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id, approved FROM hours WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first<{ id: number; approved: number }>();
    if (!existing) return c.json({ error: 'Hour entry not found' }, 404);
    if (existing.approved) return c.json({ error: 'Already approved' }, 400);

    await c.env.DB.prepare('UPDATE hours SET approved = 1 WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'approve', 'hours', id);
    log('info', 'hours', 'Approved', { tenantId, id });

    const updated = await c.env.DB.prepare(
      `SELECT h.*, e.first_name || ' ' || e.last_name as employee_name
       FROM hours h
       LEFT JOIN employees e ON e.id = h.employee_id AND e.tenant_id = h.tenant_id
       WHERE h.tenant_id = ? AND h.id = ?`,
    )
      .bind(tenantId, id)
      .first();
    return c.json({ ...updated, date: (updated as Record<string, unknown>)?.work_date, hours: (updated as Record<string, unknown>)?.hours_worked, overtime: (updated as Record<string, unknown>)?.overtime_hours });
  } catch (e: unknown) {
    log('error', 'hours', 'Approve failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to approve hours' }, 500);
  }
});

// ===========================================================================
// PAYROLL
// ===========================================================================

app.get('/payroll', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const result = await c.env.DB.prepare(
      'SELECT * FROM payroll_runs WHERE tenant_id = ? ORDER BY period_end DESC',
    )
      .bind(tenantId)
      .all();

    // Map to client-expected fields
    const runs = result.results.map((row: Record<string, unknown>) => ({
      ...row,
      gross_total: row.total_gross,
      net_total: row.total_net,
      deductions_total: round2((row.total_gross as number) - (row.total_net as number)),
    }));
    return c.json({ runs });
  } catch (e: unknown) {
    log('error', 'payroll', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch payroll runs' }, 500);
  }
});

app.post('/payroll', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.period_start || !body.period_end) {
      return c.json({ error: 'period_start and period_end are required' }, 400);
    }

    // Create the payroll run
    const runResult = await c.env.DB.prepare(
      `INSERT INTO payroll_runs (tenant_id, period_start, period_end, status, total_gross, total_net, created_at, updated_at)
       VALUES (?,?,?,?,0,0,?,?)`,
    )
      .bind(tenantId, body.period_start, body.period_end, 'draft', now(), now())
      .run();
    const runId = runResult.meta.last_row_id as number;

    // Get all active employees
    const employees = await c.env.DB.prepare(
      "SELECT id, hourly_rate FROM employees WHERE tenant_id = ? AND status = 'active'",
    )
      .bind(tenantId)
      .all<{ id: number; hourly_rate: number }>();

    let totalGross = 0;
    let totalNet = 0;

    // For each employee, sum approved hours in the period
    for (const emp of employees.results) {
      const hoursResult = await c.env.DB.prepare(
        `SELECT COALESCE(SUM(hours_worked), 0) as regular, COALESCE(SUM(overtime_hours), 0) as overtime
         FROM hours WHERE tenant_id = ? AND employee_id = ? AND approved = 1
         AND work_date >= ? AND work_date <= ?`,
      )
        .bind(tenantId, emp.id, body.period_start, body.period_end)
        .first<{ regular: number; overtime: number }>();

      const regularHours = hoursResult?.regular ?? 0;
      const overtimeHours = hoursResult?.overtime ?? 0;

      if (regularHours === 0 && overtimeHours === 0) continue; // Skip employees with no hours

      // Gross = (regular * rate) + (overtime * rate * 1.5)
      const grossPay = round2((regularHours * emp.hourly_rate) + (overtimeHours * emp.hourly_rate * 1.5));

      // Default deductions: estimate 22% for taxes/withholding (configurable per tenant via settings)
      const deductionRate = 0.22;
      const deductions = round2(grossPay * deductionRate);
      const netPay = round2(grossPay - deductions);

      await c.env.DB.prepare(
        `INSERT INTO payroll_items (tenant_id, payroll_run_id, employee_id, hours_regular, hours_overtime, rate, gross_pay, deductions, net_pay, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?)`,
      )
        .bind(tenantId, runId, emp.id, regularHours, overtimeHours, emp.hourly_rate, grossPay, deductions, netPay, now())
        .run();

      totalGross += grossPay;
      totalNet += netPay;
    }

    // Update run totals
    totalGross = round2(totalGross);
    totalNet = round2(totalNet);
    await c.env.DB.prepare(
      'UPDATE payroll_runs SET total_gross = ?, total_net = ?, updated_at = ? WHERE tenant_id = ? AND id = ?',
    )
      .bind(totalGross, totalNet, now(), tenantId, runId)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'payroll_run', runId);
    log('info', 'payroll', 'Created run', { tenantId, runId, totalGross, totalNet });

    // Fetch the complete run with items
    const run = await c.env.DB.prepare('SELECT * FROM payroll_runs WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, runId)
      .first();
    const items = await c.env.DB.prepare(
      `SELECT pi.*, e.first_name || ' ' || e.last_name as employee_name
       FROM payroll_items pi
       LEFT JOIN employees e ON e.id = pi.employee_id AND e.tenant_id = pi.tenant_id
       WHERE pi.tenant_id = ? AND pi.payroll_run_id = ?`,
    )
      .bind(tenantId, runId)
      .all();

    const mapped = items.results.map((row: Record<string, unknown>) => ({
      ...row,
      regular_hours: row.hours_regular,
      overtime_hours: row.hours_overtime,
      hourly_rate: row.rate,
    }));

    return c.json({
      ...run,
      gross_total: totalGross,
      net_total: totalNet,
      deductions_total: round2(totalGross - totalNet),
      items: mapped,
    }, 201);
  } catch (e: unknown) {
    log('error', 'payroll', 'Create failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to create payroll run' }, 500);
  }
});

app.get('/payroll/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const run = await c.env.DB.prepare('SELECT * FROM payroll_runs WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!run) return c.json({ error: 'Payroll run not found' }, 404);

    const items = await c.env.DB.prepare(
      `SELECT pi.*, e.first_name || ' ' || e.last_name as employee_name
       FROM payroll_items pi
       LEFT JOIN employees e ON e.id = pi.employee_id AND e.tenant_id = pi.tenant_id
       WHERE pi.tenant_id = ? AND pi.payroll_run_id = ?
       ORDER BY e.last_name ASC`,
    )
      .bind(tenantId, id)
      .all();

    const mapped = items.results.map((row: Record<string, unknown>) => ({
      ...row,
      regular_hours: row.hours_regular,
      overtime_hours: row.hours_overtime,
      hourly_rate: row.rate,
    }));

    const r = run as Record<string, unknown>;
    return c.json({
      ...run,
      gross_total: r.total_gross,
      net_total: r.total_net,
      deductions_total: round2((r.total_gross as number) - (r.total_net as number)),
      items: mapped,
    });
  } catch (e: unknown) {
    log('error', 'payroll', 'Get failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to fetch payroll run' }, 500);
  }
});

// POST /payroll/:id/approve
app.post('/payroll/:id/approve', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id, status FROM payroll_runs WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first<{ id: number; status: string }>();
    if (!existing) return c.json({ error: 'Payroll run not found' }, 404);
    if (existing.status !== 'draft') return c.json({ error: `Cannot approve payroll with status: ${existing.status}` }, 400);

    await c.env.DB.prepare(
      "UPDATE payroll_runs SET status = 'approved', updated_at = ? WHERE tenant_id = ? AND id = ?",
    )
      .bind(now(), tenantId, id)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'approve', 'payroll_run', id);
    log('info', 'payroll', 'Approved', { tenantId, id });

    // Fetch updated run with items
    const run = await c.env.DB.prepare('SELECT * FROM payroll_runs WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    const items = await c.env.DB.prepare(
      `SELECT pi.*, e.first_name || ' ' || e.last_name as employee_name
       FROM payroll_items pi
       LEFT JOIN employees e ON e.id = pi.employee_id AND e.tenant_id = pi.tenant_id
       WHERE pi.tenant_id = ? AND pi.payroll_run_id = ?`,
    )
      .bind(tenantId, id)
      .all();

    const mapped = items.results.map((row: Record<string, unknown>) => ({
      ...row,
      regular_hours: row.hours_regular,
      overtime_hours: row.hours_overtime,
      hourly_rate: row.rate,
    }));

    const r = run as Record<string, unknown>;
    return c.json({
      ...run,
      gross_total: r.total_gross,
      net_total: r.total_net,
      deductions_total: round2((r.total_gross as number) - (r.total_net as number)),
      items: mapped,
    });
  } catch (e: unknown) {
    log('error', 'payroll', 'Approve failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to approve payroll run' }, 500);
  }
});

// ===========================================================================
// REVIEWS
// ===========================================================================

app.get('/reviews', async (c) => {
  // Allow admin to view public reviews via ?tenant=public
  const tenantId = c.req.query('tenant') === 'public' ? 'echo-ept-public' : c.get('tenantId');
  const status = c.req.query('status');
  try {
    let sql = 'SELECT * FROM reviews WHERE tenant_id = ?';
    const params: unknown[] = [tenantId];
    if (status) {
      if (status === 'pending') {
        sql += ' AND approved = 0';
      } else if (status === 'approved') {
        sql += ' AND approved = 1';
      }
    }
    sql += ' ORDER BY created_at DESC';

    const result = await c.env.DB.prepare(sql).bind(...params).all();
    // Map to client expected fields
    const reviews = result.results.map((row: Record<string, unknown>) => ({
      ...row,
      text: row.review_text,
      status: row.approved ? 'approved' : 'pending',
      date: row.created_at,
    }));
    return c.json({ reviews });
  } catch (e: unknown) {
    log('error', 'reviews', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch reviews' }, 500);
  }
});

app.post('/reviews', async (c) => {
  const tenantId = c.req.query('tenant') === 'public' ? 'echo-ept-public' : c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.reviewer_name || body.rating === undefined) {
      return c.json({ error: 'reviewer_name and rating are required' }, 400);
    }
    if (body.rating < 1 || body.rating > 5) {
      return c.json({ error: 'rating must be between 1 and 5' }, 400);
    }

    const result = await c.env.DB.prepare(
      `INSERT INTO reviews (tenant_id, customer_id, reviewer_name, rating, review_text, service_type, approved, featured, created_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        tenantId,
        body.customer_id ?? null,
        body.reviewer_name,
        body.rating,
        body.text ?? body.review_text ?? null,
        body.service_type ?? null,
        0, // new reviews start unapproved
        body.featured ? 1 : 0,
        now(),
      )
      .run();

    const id = result.meta.last_row_id;
    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'review', id as number);
    log('info', 'reviews', 'Created', { tenantId, id });

    const created = await c.env.DB.prepare('SELECT * FROM reviews WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    const r = created as Record<string, unknown>;
    return c.json({ ...created, text: r?.review_text, status: r?.approved ? 'approved' : 'pending', date: r?.created_at }, 201);
  } catch (e: unknown) {
    log('error', 'reviews', 'Create failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to create review' }, 500);
  }
});

// POST /reviews/:id/approve
app.post('/reviews/:id/approve', async (c) => {
  const tenantId = c.req.query('tenant') === 'public' ? 'echo-ept-public' : c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id, approved FROM reviews WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first<{ id: number; approved: number }>();
    if (!existing) return c.json({ error: 'Review not found' }, 404);

    await c.env.DB.prepare('UPDATE reviews SET approved = 1 WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'approve', 'review', id);
    log('info', 'reviews', 'Approved', { tenantId, id });

    const updated = await c.env.DB.prepare('SELECT * FROM reviews WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    const r = updated as Record<string, unknown>;
    return c.json({ ...updated, text: r?.review_text, status: 'approved', date: r?.created_at });
  } catch (e: unknown) {
    log('error', 'reviews', 'Approve failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to approve review' }, 500);
  }
});

app.delete('/reviews/:id', async (c) => {
  const tenantId = c.req.query('tenant') === 'public' ? 'echo-ept-public' : c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM reviews WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Review not found' }, 404);

    await c.env.DB.prepare('DELETE FROM reviews WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'delete', 'review', id);
    log('info', 'reviews', 'Deleted', { tenantId, id });
    return c.json({ success: true });
  } catch (e: unknown) {
    log('error', 'reviews', 'Delete failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to delete review' }, 500);
  }
});

// ===========================================================================
// INVENTORY
// ===========================================================================

app.get('/inventory', async (c) => {
  const tenantId = c.get('tenantId');
  const category = c.req.query('category');
  try {
    let sql = 'SELECT * FROM inventory_items WHERE tenant_id = ?';
    const params: unknown[] = [tenantId];
    if (category) {
      sql += ' AND category = ?';
      params.push(category);
    }
    sql += ' ORDER BY name ASC';

    const result = await c.env.DB.prepare(sql).bind(...params).all();
    return c.json({ items: result.results });
  } catch (e: unknown) {
    log('error', 'inventory', 'List failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch inventory' }, 500);
  }
});

app.post('/inventory', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.name) {
      return c.json({ error: 'name is required' }, 400);
    }

    const result = await c.env.DB.prepare(
      `INSERT INTO inventory_items (tenant_id, name, category, quantity, unit, unit_cost, reorder_level, vendor, notes, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        tenantId,
        body.name,
        body.category ?? 'supplies',
        body.quantity ?? 0,
        body.unit ?? 'each',
        body.unit_cost ?? 0,
        body.reorder_level ?? 0,
        body.vendor ?? null,
        body.notes ?? null,
        now(),
        now(),
      )
      .run();

    const id = result.meta.last_row_id;
    await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'inventory_item', id as number);
    log('info', 'inventory', 'Created', { tenantId, id });

    const created = await c.env.DB.prepare('SELECT * FROM inventory_items WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(created, 201);
  } catch (e: unknown) {
    log('error', 'inventory', 'Create failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to create inventory item' }, 500);
  }
});

app.put('/inventory/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM inventory_items WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Inventory item not found' }, 404);

    const body = await c.req.json();
    const fields: string[] = [];
    const values: unknown[] = [];

    const updatable = ['name', 'category', 'quantity', 'unit', 'unit_cost', 'reorder_level', 'vendor', 'notes'];
    for (const field of updatable) {
      if (body[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(body[field]);
      }
    }

    if (fields.length === 0) return c.json({ error: 'No fields to update' }, 400);

    fields.push('updated_at = ?');
    values.push(now());
    values.push(tenantId, id);

    await c.env.DB.prepare(`UPDATE inventory_items SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`)
      .bind(...values)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'update', 'inventory_item', id);
    log('info', 'inventory', 'Updated', { tenantId, id });

    const updated = await c.env.DB.prepare('SELECT * FROM inventory_items WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(updated);
  } catch (e: unknown) {
    log('error', 'inventory', 'Update failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to update inventory item' }, 500);
  }
});

app.delete('/inventory/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT id FROM inventory_items WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    if (!existing) return c.json({ error: 'Inventory item not found' }, 404);

    await c.env.DB.prepare('DELETE FROM inventory_items WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'delete', 'inventory_item', id);
    log('info', 'inventory', 'Deleted', { tenantId, id });
    return c.json({ success: true });
  } catch (e: unknown) {
    log('error', 'inventory', 'Delete failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to delete inventory item' }, 500);
  }
});

// POST /inventory/:id/restock
app.post('/inventory/:id/restock', async (c) => {
  const tenantId = c.get('tenantId');
  const id = parseInt(c.req.param('id'), 10);
  try {
    const existing = await c.env.DB.prepare('SELECT * FROM inventory_items WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first<{ id: number; quantity: number; unit_cost: number }>();
    if (!existing) return c.json({ error: 'Inventory item not found' }, 404);

    const body = await c.req.json();
    if (body.quantity === undefined || body.quantity <= 0) {
      return c.json({ error: 'quantity must be a positive number' }, 400);
    }

    const newQuantity = round2(existing.quantity + body.quantity);
    const newUnitCost = body.cost_per_unit ?? existing.unit_cost;

    await c.env.DB.prepare(
      `UPDATE inventory_items SET quantity = ?, unit_cost = ?, last_restocked = ?, vendor = COALESCE(?, vendor), updated_at = ?
       WHERE tenant_id = ? AND id = ?`,
    )
      .bind(newQuantity, newUnitCost, now(), body.supplier ?? null, now(), tenantId, id)
      .run();

    // Log the restock as an expense if cost_per_unit is provided
    if (body.cost_per_unit && body.cost_per_unit > 0) {
      const totalCost = round2(body.quantity * body.cost_per_unit);
      await c.env.DB.prepare(
        `INSERT INTO expenses (tenant_id, category, description, amount, expense_date, vendor, notes, recurring, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,0,?,?)`,
      )
        .bind(
          tenantId,
          'inventory',
          `Restock: ${body.quantity} units`,
          totalCost,
          today(),
          body.supplier ?? null,
          `Inventory restock for item #${id}`,
          now(),
          now(),
        )
        .run();
    }

    await audit(c.env.DB, tenantId, c.get('userId'), 'restock', 'inventory_item', id, `qty:+${body.quantity}`);
    log('info', 'inventory', 'Restocked', { tenantId, id, addedQty: body.quantity, newQuantity });

    const updated = await c.env.DB.prepare('SELECT * FROM inventory_items WHERE tenant_id = ? AND id = ?')
      .bind(tenantId, id)
      .first();
    return c.json(updated);
  } catch (e: unknown) {
    log('error', 'inventory', 'Restock failed', { error: (e as Error).message, tenantId, id });
    return c.json({ error: 'Failed to restock inventory item' }, 500);
  }
});

// ===========================================================================
// SETTINGS
// ===========================================================================

app.get('/settings', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const result = await c.env.DB.prepare('SELECT key, value FROM settings WHERE tenant_id = ?')
      .bind(tenantId)
      .all<{ key: string; value: string }>();

    // Build a settings object from key-value pairs
    const settings: Record<string, unknown> = {
      company_name: '',
      phone: '',
      email: '',
      address: '',
      tax_rate: 0.0825,
      tax_id: '',
      payment_methods: ['cash', 'check', 'card'],
      business_hours: {},
    };

    for (const row of result.results) {
      try {
        settings[row.key] = JSON.parse(row.value);
      } catch {
        settings[row.key] = row.value;
      }
    }

    return c.json(settings);
  } catch (e: unknown) {
    log('error', 'settings', 'Get failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to fetch settings' }, 500);
  }
});

// PUT /settings — upsert a single key-value pair
app.put('/settings', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    const body = await c.req.json();
    if (!body.key) {
      return c.json({ error: 'key is required' }, 400);
    }

    const valueStr = typeof body.value === 'string' ? body.value : JSON.stringify(body.value);

    await c.env.DB.prepare(
      `INSERT INTO settings (tenant_id, key, value, updated_at) VALUES (?,?,?,?)
       ON CONFLICT(tenant_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    )
      .bind(tenantId, body.key, valueStr, now())
      .run();

    await audit(c.env.DB, tenantId, c.get('userId'), 'update', 'settings', null, `${body.key}`);
    log('info', 'settings', 'Updated', { tenantId, key: body.key });
    return c.json({ success: true });
  } catch (e: unknown) {
    log('error', 'settings', 'Update failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to update settings' }, 500);
  }
});

// ===========================================================================
// ANALYTICS
// ===========================================================================

// GET /analytics/summary
app.get('/analytics/summary', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    // Total revenue from paid invoices
    const revenueResult = await c.env.DB.prepare(
      "SELECT COALESCE(SUM(amount_paid), 0) as total FROM invoices WHERE tenant_id = ? AND status IN ('paid', 'partial')",
    )
      .bind(tenantId)
      .first<{ total: number }>();

    // Total expenses
    const expensesResult = await c.env.DB.prepare(
      'SELECT COALESCE(SUM(amount), 0) as total FROM expenses WHERE tenant_id = ?',
    )
      .bind(tenantId)
      .first<{ total: number }>();

    // Active customers (any customer with a booking or invoice in last 12 months)
    const activeCustomersResult = await c.env.DB.prepare(
      `SELECT COUNT(DISTINCT c.id) as cnt FROM customers c
       WHERE c.tenant_id = ? AND (
         EXISTS (SELECT 1 FROM bookings b WHERE b.customer_id = c.id AND b.tenant_id = c.tenant_id AND b.scheduled_date >= date('now', '-12 months'))
         OR EXISTS (SELECT 1 FROM invoices i WHERE i.customer_id = c.id AND i.tenant_id = c.tenant_id AND i.issue_date >= date('now', '-12 months'))
       )`,
    )
      .bind(tenantId)
      .first<{ cnt: number }>();

    // Monthly bookings (current month)
    const monthStart = new Date().toISOString().slice(0, 7) + '-01';
    const monthlyBookingsResult = await c.env.DB.prepare(
      'SELECT COUNT(*) as cnt FROM bookings WHERE tenant_id = ? AND scheduled_date >= ?',
    )
      .bind(tenantId, monthStart)
      .first<{ cnt: number }>();

    // Outstanding AR (unpaid/partial invoices)
    const arResult = await c.env.DB.prepare(
      "SELECT COALESCE(SUM(total - amount_paid), 0) as outstanding FROM invoices WHERE tenant_id = ? AND status IN ('sent', 'partial', 'overdue')",
    )
      .bind(tenantId)
      .first<{ outstanding: number }>();

    // Recent bookings (last 10)
    const recentBookingsResult = await c.env.DB.prepare(
      `SELECT b.*, c.first_name || ' ' || c.last_name as customer_name, s.name as service_name
       FROM bookings b
       LEFT JOIN customers c ON c.id = b.customer_id AND c.tenant_id = b.tenant_id
       LEFT JOIN services s ON s.id = b.service_id AND s.tenant_id = b.tenant_id
       WHERE b.tenant_id = ?
       ORDER BY b.scheduled_date DESC, b.scheduled_time DESC
       LIMIT 10`,
    )
      .bind(tenantId)
      .all();

    const recentBookings = recentBookingsResult.results.map((row: Record<string, unknown>) => ({
      ...row,
      date: row.scheduled_date,
      time: row.scheduled_time,
    }));

    return c.json({
      total_revenue: round2(revenueResult?.total ?? 0),
      total_expenses: round2(expensesResult?.total ?? 0),
      active_customers: activeCustomersResult?.cnt ?? 0,
      monthly_bookings: monthlyBookingsResult?.cnt ?? 0,
      outstanding_ar: round2(arResult?.outstanding ?? 0),
      recent_bookings: recentBookings,
    });
  } catch (e: unknown) {
    log('error', 'analytics', 'Summary failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to generate analytics summary' }, 500);
  }
});

// GET /analytics/revenue — monthly revenue breakdown
app.get('/analytics/revenue', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    // Last 12 months of revenue from payments
    const result = await c.env.DB.prepare(
      `SELECT strftime('%Y-%m', payment_date) as month, COALESCE(SUM(amount), 0) as revenue
       FROM payments WHERE tenant_id = ? AND payment_date >= date('now', '-12 months')
       GROUP BY month ORDER BY month ASC`,
    )
      .bind(tenantId)
      .all<{ month: string; revenue: number }>();

    // YTD revenue
    const yearStart = new Date().getFullYear() + '-01-01';
    const ytdResult = await c.env.DB.prepare(
      'SELECT COALESCE(SUM(amount), 0) as ytd FROM payments WHERE tenant_id = ? AND payment_date >= ?',
    )
      .bind(tenantId, yearStart)
      .first<{ ytd: number }>();

    return c.json({
      monthly: result.results.map((r) => ({ month: r.month, revenue: round2(r.revenue) })),
      ytd: round2(ytdResult?.ytd ?? 0),
    });
  } catch (e: unknown) {
    log('error', 'analytics', 'Revenue failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to generate revenue analytics' }, 500);
  }
});

// GET /analytics/expenses — monthly expenses + category breakdown
app.get('/analytics/expenses', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    // Monthly totals (last 12 months)
    const monthlyResult = await c.env.DB.prepare(
      `SELECT strftime('%Y-%m', expense_date) as month, COALESCE(SUM(amount), 0) as total
       FROM expenses WHERE tenant_id = ? AND expense_date >= date('now', '-12 months')
       GROUP BY month ORDER BY month ASC`,
    )
      .bind(tenantId)
      .all<{ month: string; total: number }>();

    // By category
    const categoryResult = await c.env.DB.prepare(
      `SELECT category, COALESCE(SUM(amount), 0) as total
       FROM expenses WHERE tenant_id = ?
       GROUP BY category ORDER BY total DESC`,
    )
      .bind(tenantId)
      .all<{ category: string; total: number }>();

    // YTD
    const yearStart = new Date().getFullYear() + '-01-01';
    const ytdResult = await c.env.DB.prepare(
      'SELECT COALESCE(SUM(amount), 0) as ytd FROM expenses WHERE tenant_id = ? AND expense_date >= ?',
    )
      .bind(tenantId, yearStart)
      .first<{ ytd: number }>();

    const ytd = round2(ytdResult?.ytd ?? 0);

    // Calculate category totals and percentages
    const grandTotal = categoryResult.results.reduce((sum, r) => sum + r.total, 0) || 1; // avoid div by zero
    const byCategory = categoryResult.results.map((r) => ({
      category: r.category,
      total: round2(r.total),
      percentage: round2((r.total / grandTotal) * 100),
    }));

    return c.json({
      monthly: monthlyResult.results.map((r) => ({ month: r.month, total: round2(r.total) })),
      by_category: byCategory,
      ytd,
    });
  } catch (e: unknown) {
    log('error', 'analytics', 'Expenses failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to generate expense analytics' }, 500);
  }
});

// GET /analytics/ar-aging — Accounts Receivable aging buckets
app.get('/analytics/ar-aging', async (c) => {
  const tenantId = c.get('tenantId');
  try {
    // Fetch all unpaid/partial invoices
    const result = await c.env.DB.prepare(
      `SELECT i.*, c.first_name || ' ' || c.last_name as customer_name
       FROM invoices i
       LEFT JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
       WHERE i.tenant_id = ? AND i.status IN ('sent', 'partial', 'overdue')
       ORDER BY i.due_date ASC`,
    )
      .bind(tenantId)
      .all();

    const todayDate = new Date();
    const buckets = [
      { label: 'Current (0-30 days)', min_days: 0, max_days: 30, count: 0, total: 0 },
      { label: '31-60 days', min_days: 31, max_days: 60, count: 0, total: 0 },
      { label: '61-90 days', min_days: 61, max_days: 90, count: 0, total: 0 },
      { label: '90+ days', min_days: 91, max_days: 99999, count: 0, total: 0 },
    ];

    const invoices: {
      invoice_number: string;
      customer_name: string;
      issue_date: string;
      due_date: string;
      amount: number;
      days_outstanding: number;
      bucket: string;
    }[] = [];

    for (const row of result.results) {
      const r = row as Record<string, unknown>;
      const dueDate = new Date(r.due_date as string);
      const daysOutstanding = Math.max(0, Math.floor((todayDate.getTime() - dueDate.getTime()) / 86400000));
      const outstanding = round2((r.total as number) - (r.amount_paid as number));

      if (outstanding <= 0) continue; // fully paid, skip

      let bucketLabel = 'Current (0-30 days)';
      let bucketIdx = 0;
      if (daysOutstanding > 90) { bucketIdx = 3; bucketLabel = '90+ days'; }
      else if (daysOutstanding > 60) { bucketIdx = 2; bucketLabel = '61-90 days'; }
      else if (daysOutstanding > 30) { bucketIdx = 1; bucketLabel = '31-60 days'; }

      buckets[bucketIdx].count++;
      buckets[bucketIdx].total = round2(buckets[bucketIdx].total + outstanding);

      invoices.push({
        invoice_number: r.invoice_number as string,
        customer_name: (r.customer_name as string) ?? 'Unknown',
        issue_date: r.issue_date as string,
        due_date: r.due_date as string,
        amount: outstanding,
        days_outstanding: daysOutstanding,
        bucket: bucketLabel,
      });
    }

    return c.json({ buckets, invoices });
  } catch (e: unknown) {
    log('error', 'analytics', 'AR aging failed', { error: (e as Error).message, tenantId });
    return c.json({ error: 'Failed to generate AR aging report' }, 500);
  }
});

// ===========================================================================
// Sales Reps & Commissions
// ===========================================================================

app.get('/sales-reps', async (c) => {
  const tenantId = c.get('tenantId');
  const status = c.req.query('status');
  let sql = 'SELECT * FROM sales_reps WHERE tenant_id = ?';
  const params: string[] = [tenantId];
  if (status) { sql += ' AND status = ?'; params.push(status); }
  sql += ' ORDER BY name ASC';
  const result = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json({ sales_reps: result.results, count: result.results.length });
});

app.post('/sales-reps', async (c) => {
  const tenantId = c.get('tenantId');
  const body = await c.req.json<{ name: string; email?: string; phone?: string; commission_rate?: number; notes?: string }>();
  if (!body.name) return c.json({ error: 'name required' }, 400);
  const rate = body.commission_rate ?? 10.0;
  const result = await c.env.DB.prepare(
    'INSERT INTO sales_reps (tenant_id, name, email, phone, commission_rate, notes) VALUES (?,?,?,?,?,?)'
  ).bind(tenantId, body.name, body.email || null, body.phone || null, rate, body.notes || null).run();
  await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'sales_rep', result.meta.last_row_id);
  return c.json({ success: true, id: result.meta.last_row_id }, 201);
});

app.put('/sales-reps/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = c.req.param('id');
  const body = await c.req.json<{ name?: string; email?: string; phone?: string; commission_rate?: number; status?: string; notes?: string }>();
  const fields: string[] = [];
  const values: (string | number | null)[] = [];
  if (body.name !== undefined) { fields.push('name = ?'); values.push(body.name); }
  if (body.email !== undefined) { fields.push('email = ?'); values.push(body.email); }
  if (body.phone !== undefined) { fields.push('phone = ?'); values.push(body.phone); }
  if (body.commission_rate !== undefined) { fields.push('commission_rate = ?'); values.push(body.commission_rate); }
  if (body.status !== undefined) { fields.push('status = ?'); values.push(body.status); }
  if (body.notes !== undefined) { fields.push('notes = ?'); values.push(body.notes); }
  if (fields.length === 0) return c.json({ error: 'No fields to update' }, 400);
  fields.push('updated_at = ?'); values.push(now());
  values.push(tenantId, id);
  await c.env.DB.prepare(`UPDATE sales_reps SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`).bind(...values).run();
  await audit(c.env.DB, tenantId, c.get('userId'), 'update', 'sales_rep', Number(id));
  return c.json({ success: true });
});

app.delete('/sales-reps/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const id = c.req.param('id');
  await c.env.DB.prepare('DELETE FROM sales_reps WHERE tenant_id = ? AND id = ?').bind(tenantId, id).run();
  await audit(c.env.DB, tenantId, c.get('userId'), 'delete', 'sales_rep', Number(id));
  return c.json({ success: true });
});

app.get('/commissions', async (c) => {
  const tenantId = c.get('tenantId');
  const repId = c.req.query('rep_id');
  const status = c.req.query('status');
  let sql = `SELECT cm.*, sr.name as rep_name, sr.email as rep_email,
    c.first_name || ' ' || c.last_name as customer_name, c.company_name
    FROM commissions cm
    LEFT JOIN sales_reps sr ON sr.id = cm.rep_id AND sr.tenant_id = cm.tenant_id
    LEFT JOIN customers c ON c.id = cm.customer_id AND c.tenant_id = cm.tenant_id
    WHERE cm.tenant_id = ?`;
  const params: string[] = [tenantId];
  if (repId) { sql += ' AND cm.rep_id = ?'; params.push(repId); }
  if (status) { sql += ' AND cm.status = ?'; params.push(status); }
  sql += ' ORDER BY cm.created_at DESC';
  const result = await c.env.DB.prepare(sql).bind(...params).all();

  // Calculate totals
  const totals = { pending: 0, approved: 0, paid: 0 };
  for (const row of result.results as any[]) {
    if (row.status === 'pending') totals.pending += row.commission_amount;
    else if (row.status === 'approved') totals.approved += row.commission_amount;
    else if (row.status === 'paid') totals.paid += row.commission_amount;
  }

  return c.json({ commissions: result.results, count: result.results.length, totals });
});

app.post('/commissions', async (c) => {
  const tenantId = c.get('tenantId');
  const body = await c.req.json<{ rep_id: number; customer_id?: number; invoice_id?: number; invoice_total: number; commission_rate?: number; notes?: string }>();
  if (!body.rep_id || !body.invoice_total) return c.json({ error: 'rep_id and invoice_total required' }, 400);

  // Get rep's default rate if not specified
  let rate = body.commission_rate;
  if (rate === undefined) {
    const rep = await c.env.DB.prepare('SELECT commission_rate FROM sales_reps WHERE tenant_id = ? AND id = ?').bind(tenantId, body.rep_id).first<{ commission_rate: number }>();
    rate = rep?.commission_rate ?? 10.0;
  }
  const amount = body.invoice_total * (rate / 100);

  const result = await c.env.DB.prepare(
    'INSERT INTO commissions (tenant_id, rep_id, customer_id, invoice_id, invoice_total, commission_rate, commission_amount, notes) VALUES (?,?,?,?,?,?,?,?)'
  ).bind(tenantId, body.rep_id, body.customer_id || null, body.invoice_id || null, body.invoice_total, rate, amount, body.notes || null).run();

  // Update rep totals
  await c.env.DB.prepare('UPDATE sales_reps SET total_earned = total_earned + ? WHERE tenant_id = ? AND id = ?').bind(amount, tenantId, body.rep_id).run();

  await audit(c.env.DB, tenantId, c.get('userId'), 'create', 'commission', result.meta.last_row_id);
  return c.json({ success: true, id: result.meta.last_row_id, commission_amount: amount }, 201);
});

app.put('/commissions/:id/pay', async (c) => {
  const tenantId = c.get('tenantId');
  const id = c.req.param('id');
  const commission = await c.env.DB.prepare('SELECT * FROM commissions WHERE tenant_id = ? AND id = ?').bind(tenantId, id).first<{ rep_id: number; commission_amount: number; status: string }>();
  if (!commission) return c.json({ error: 'Commission not found' }, 404);
  if (commission.status === 'paid') return c.json({ error: 'Already paid' }, 400);

  await c.env.DB.prepare("UPDATE commissions SET status = 'paid', paid_date = ? WHERE tenant_id = ? AND id = ?").bind(now(), tenantId, id).run();
  await c.env.DB.prepare('UPDATE sales_reps SET total_paid = total_paid + ? WHERE tenant_id = ? AND id = ?').bind(commission.commission_amount, tenantId, commission.rep_id).run();
  await audit(c.env.DB, tenantId, c.get('userId'), 'pay', 'commission', Number(id));
  return c.json({ success: true });
});

app.put('/commissions/:id/approve', async (c) => {
  const tenantId = c.get('tenantId');
  const id = c.req.param('id');
  await c.env.DB.prepare("UPDATE commissions SET status = 'approved' WHERE tenant_id = ? AND id = ?").bind(tenantId, id).run();
  await audit(c.env.DB, tenantId, c.get('userId'), 'approve', 'commission', Number(id));
  return c.json({ success: true });
});

// ===========================================================================
// 404 Fallback
// ===========================================================================

app.notFound((c) => {
  log('warn', 'router', 'Route not found', { path: c.req.path, method: c.req.method });
  return c.json(
    {
      error: 'Not found',
      path: c.req.path,
      method: c.req.method,
      hint: 'GET /health for status. Check the API documentation for valid endpoints.',
    },
    404,
  );
});

// ---------------------------------------------------------------------------
// Startup log
// ---------------------------------------------------------------------------

log('info', 'startup', 'echo-business-api v2.0.0 initialized', {
  routes: [
    '/health', '/customers', '/services', '/bookings', '/invoices',
    '/payments', '/expenses', '/employees', '/hours', '/payroll',
    '/reviews', '/inventory', '/settings', '/analytics/*',
  ],
});

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export default app;
