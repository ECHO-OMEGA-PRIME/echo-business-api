# Echo Business API

**Multi-Tenant Business Management API v2.0.0**

Cloudflare Worker providing a comprehensive REST API for small business operations. Supports multi-tenant isolation via Firebase JWT authentication, covering customers, services, bookings, invoicing, payments, expenses, employees, payroll, reviews, inventory, settings, and analytics.

## Features

- **Multi-Tenant Isolation** -- Firebase JWT-based tenant separation; every query is scoped to the authenticated tenant
- **Customer Management** -- Full CRUD for customer records with contact details and notes
- **Service Catalog** -- Define services with pricing, duration, and categories
- **Booking System** -- Schedule and manage appointments with status tracking
- **Invoicing** -- Auto-generated invoice numbers (`INV-YYYYMM-NNN`), line items, tax calculation (configurable rate), discounts, and payment status tracking
- **Payment Processing** -- Record payments against invoices with automatic status updates (paid, partial, pending)
- **Expense Tracking** -- Categorize and track business expenses with vendor information
- **Employee Management** -- Employee records, roles, and scheduling
- **Time/Hours Tracking** -- Log employee hours with clock-in/clock-out
- **Payroll** -- Calculate payroll based on logged hours and pay rates
- **Review System** -- Customer reviews with ratings, approval workflow, and public display endpoint
- **Inventory Management** -- Track stock levels, reorder points, and item categories
- **Business Settings** -- Per-tenant configuration (name, address, tax rates, branding)
- **Analytics Dashboard** -- Revenue summaries, booking trends, customer metrics
- **Audit Logging** -- All mutations are logged to an audit table with user, action, and timestamp
- **Public Reviews Endpoint** -- Unauthenticated endpoint for displaying approved customer reviews on websites

## API Endpoints

All authenticated endpoints require a valid Firebase JWT in the `Authorization: Bearer <token>` header.

### Public (No Auth)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Service info and version |
| `GET` | `/health` | Health check with binding status |
| `GET` | `/public/reviews` | Approved customer reviews |

### Customers

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/customers` | List customers |
| `POST` | `/api/customers` | Create customer |
| `PUT` | `/api/customers/:id` | Update customer |
| `DELETE` | `/api/customers/:id` | Delete customer |

### Services, Bookings, Invoices, Payments, Expenses, Employees, Hours, Payroll, Reviews, Inventory, Settings, Analytics

Each resource follows the same CRUD pattern under `/api/<resource>`.

## Configuration

### wrangler.toml

```toml
name = "echo-business-api"
compatibility_date = "2024-09-23"
```

### Bindings

| Type | Binding | Resource |
|------|---------|----------|
| D1 | `DB` | `echo-business-db` |
| KV | `CACHE` | KV namespace for hot cache |
| R2 | `ASSETS` | `echo-business-assets` bucket |

### Environment Variables

| Name | Description |
|------|-------------|
| `CORS_ORIGIN` | Allowed CORS origin (default: `https://echo-ept.com`) |

## Deployment

```bash
cd WORKERS/echo-business-api
npx wrangler deploy
```

## Tech Stack

- **Runtime**: Cloudflare Workers
- **Framework**: Hono 4.7
- **Language**: TypeScript
- **Database**: Cloudflare D1 (SQLite)
- **Cache**: Cloudflare KV
- **Storage**: Cloudflare R2
- **Auth**: Firebase JWT verification
- **Source**: `src/index.ts` (2,683 lines)
