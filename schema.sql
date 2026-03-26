-- Schema for echo-business-api (multi-tenant)
-- D1 Database: echo-business-db
-- Every table includes tenant_id for multi-tenancy isolation
-- Run: npx wrangler d1 execute echo-business-db --remote --file=./schema.sql

DROP TABLE IF EXISTS payroll_items;
DROP TABLE IF EXISTS payroll_runs;
DROP TABLE IF EXISTS hours;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS invoice_items;
DROP TABLE IF EXISTS invoices;
DROP TABLE IF EXISTS bookings;
DROP TABLE IF EXISTS expenses;
DROP TABLE IF EXISTS employees;
DROP TABLE IF EXISTS reviews;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS customers;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS inventory_items;

CREATE TABLE customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  company_name TEXT,
  address TEXT,
  city TEXT,
  state TEXT DEFAULT 'TX',
  zip TEXT,
  notes TEXT,
  customer_type TEXT DEFAULT 'residential' CHECK(customer_type IN ('residential', 'commercial')),
  source TEXT DEFAULT 'website',
  tax_exempt INTEGER DEFAULT 0,
  tax_exempt_id TEXT,
  payment_terms TEXT DEFAULT 'due_on_receipt' CHECK(payment_terms IN ('due_on_receipt', 'net_10', 'net_15', 'net_20', 'net_30', 'net_45', 'net_60')),
  contact_person TEXT,
  contact_email TEXT,
  contact_phone TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  category TEXT DEFAULT 'general',
  pricing_type TEXT DEFAULT 'flat' CHECK(pricing_type IN ('flat', 'hourly', 'sqft', 'unit')),
  base_price REAL NOT NULL,
  duration_minutes INTEGER DEFAULT 60,
  active INTEGER DEFAULT 1,
  sort_order INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE bookings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  customer_id INTEGER REFERENCES customers(id),
  service_id INTEGER REFERENCES services(id),
  scheduled_date TEXT NOT NULL,
  scheduled_time TEXT DEFAULT '09:00',
  duration_minutes INTEGER DEFAULT 60,
  address TEXT,
  city TEXT,
  state TEXT DEFAULT 'TX',
  zip TEXT,
  notes TEXT,
  quoted_price REAL,
  status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show')),
  assigned_team TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  invoice_number TEXT NOT NULL,
  customer_id INTEGER REFERENCES customers(id),
  booking_id INTEGER REFERENCES bookings(id),
  issue_date TEXT NOT NULL,
  due_date TEXT NOT NULL,
  payment_terms TEXT DEFAULT 'due_on_receipt' CHECK(payment_terms IN ('due_on_receipt', 'net_10', 'net_15', 'net_20', 'net_30', 'net_45', 'net_60')),
  subtotal REAL DEFAULT 0,
  tax_rate REAL DEFAULT 0.0825,
  tax_amount REAL DEFAULT 0,
  discount REAL DEFAULT 0,
  total REAL DEFAULT 0,
  amount_paid REAL DEFAULT 0,
  late_fee_rate REAL DEFAULT 0.015,
  finance_charge_rate REAL DEFAULT 0.18,
  notes TEXT,
  share_token TEXT,
  status TEXT DEFAULT 'draft' CHECK(status IN ('draft', 'sent', 'paid', 'overdue', 'void', 'partial')),
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  UNIQUE(tenant_id, invoice_number)
);

CREATE TABLE invoice_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  description TEXT NOT NULL,
  quantity REAL DEFAULT 1,
  unit_price REAL NOT NULL,
  total REAL NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  invoice_id INTEGER NOT NULL REFERENCES invoices(id),
  amount REAL NOT NULL,
  payment_method TEXT DEFAULT 'cash' CHECK(payment_method IN ('cash', 'check', 'card', 'zelle', 'venmo', 'paypal', 'ach', 'other')),
  payment_date TEXT NOT NULL,
  reference_number TEXT,
  collected_by TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('supplies', 'equipment', 'vehicle', 'insurance', 'marketing', 'rent', 'utilities', 'payroll_tax', 'software', 'inventory', 'other')),
  description TEXT NOT NULL,
  amount REAL NOT NULL,
  expense_date TEXT NOT NULL,
  vendor TEXT,
  receipt_url TEXT,
  notes TEXT,
  recurring INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  role TEXT DEFAULT 'staff',
  hourly_rate REAL DEFAULT 15.00,
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'terminated')),
  hire_date TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE hours (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  booking_id INTEGER REFERENCES bookings(id),
  work_date TEXT NOT NULL,
  hours_worked REAL DEFAULT 0,
  overtime_hours REAL DEFAULT 0,
  notes TEXT,
  approved INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE payroll_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  status TEXT DEFAULT 'draft' CHECK(status IN ('draft', 'approved', 'paid')),
  total_gross REAL DEFAULT 0,
  total_net REAL DEFAULT 0,
  paid_date TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE payroll_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  payroll_run_id INTEGER NOT NULL REFERENCES payroll_runs(id) ON DELETE CASCADE,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  hours_regular REAL DEFAULT 0,
  hours_overtime REAL DEFAULT 0,
  rate REAL NOT NULL,
  gross_pay REAL NOT NULL,
  deductions REAL DEFAULT 0,
  net_pay REAL NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  customer_id INTEGER REFERENCES customers(id),
  reviewer_name TEXT NOT NULL,
  rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
  review_text TEXT,
  service_type TEXT,
  approved INTEGER DEFAULT 0,
  featured INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE settings (
  tenant_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (tenant_id, key)
);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  user_id TEXT,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id INTEGER,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE inventory_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'supplies',
  quantity REAL DEFAULT 0,
  unit TEXT DEFAULT 'each',
  unit_cost REAL DEFAULT 0,
  reorder_level REAL DEFAULT 0,
  vendor TEXT,
  notes TEXT,
  last_restocked TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Indexes for tenant_id on every table
CREATE INDEX idx_customers_tenant ON customers(tenant_id);
CREATE INDEX idx_services_tenant ON services(tenant_id);
CREATE INDEX idx_bookings_tenant ON bookings(tenant_id);
CREATE INDEX idx_invoices_tenant ON invoices(tenant_id);
CREATE INDEX idx_invoice_items_tenant ON invoice_items(tenant_id);
CREATE INDEX idx_payments_tenant ON payments(tenant_id);
CREATE INDEX idx_expenses_tenant ON expenses(tenant_id);
CREATE INDEX idx_employees_tenant ON employees(tenant_id);
CREATE INDEX idx_hours_tenant ON hours(tenant_id);
CREATE INDEX idx_payroll_runs_tenant ON payroll_runs(tenant_id);
CREATE INDEX idx_payroll_items_tenant ON payroll_items(tenant_id);
CREATE INDEX idx_reviews_tenant ON reviews(tenant_id);
CREATE INDEX idx_audit_log_tenant ON audit_log(tenant_id);
CREATE INDEX idx_inventory_tenant ON inventory_items(tenant_id);

-- Additional useful indexes
CREATE INDEX idx_customers_email ON customers(tenant_id, email);
CREATE INDEX idx_customers_phone ON customers(tenant_id, phone);
CREATE INDEX idx_bookings_customer ON bookings(tenant_id, customer_id);
CREATE INDEX idx_bookings_service ON bookings(tenant_id, service_id);
CREATE INDEX idx_bookings_status ON bookings(tenant_id, status);
CREATE INDEX idx_bookings_date ON bookings(tenant_id, scheduled_date);
CREATE INDEX idx_invoices_customer ON invoices(tenant_id, customer_id);
CREATE INDEX idx_invoices_status ON invoices(tenant_id, status);
CREATE INDEX idx_invoice_items_invoice ON invoice_items(tenant_id, invoice_id);
CREATE INDEX idx_payments_invoice ON payments(tenant_id, invoice_id);
CREATE INDEX idx_hours_employee ON hours(tenant_id, employee_id);
CREATE INDEX idx_hours_date ON hours(tenant_id, work_date);
CREATE INDEX idx_hours_approved ON hours(tenant_id, approved);
CREATE INDEX idx_expenses_category ON expenses(tenant_id, category);
CREATE INDEX idx_expenses_date ON expenses(tenant_id, expense_date);
CREATE INDEX idx_payroll_items_run ON payroll_items(tenant_id, payroll_run_id);
CREATE INDEX idx_reviews_approved ON reviews(tenant_id, approved);
CREATE INDEX idx_inventory_category ON inventory_items(tenant_id, category);
CREATE INDEX idx_audit_log_entity ON audit_log(tenant_id, entity_type, entity_id);
