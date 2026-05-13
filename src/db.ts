import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import path from "path";
import fs from "fs";

const dbPath = process.env.DB_PATH ?? "./data/prices.db";
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS categories (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL UNIQUE,
    color TEXT NOT NULL DEFAULT '#6b7280'
  );

  CREATE TABLE IF NOT EXISTS items (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    category_id   INTEGER REFERENCES categories(id) ON DELETE SET NULL,
    diamond_price REAL,
    notes         TEXT,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id               INTEGER REFERENCES items(id) ON DELETE SET NULL,
    item_name             TEXT NOT NULL,
    suggested_price       REAL,
    suggested_category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
    reasoning             TEXT,
    submitter_username    TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'pending',
    admin_notes           TEXT,
    created_at            DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id       INTEGER,
    admin_username TEXT NOT NULL,
    action         TEXT NOT NULL,
    target_type    TEXT NOT NULL,
    target_id      INTEGER,
    target_name    TEXT,
    details        TEXT,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_items_category ON items(category_id);
  CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
  CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
`);

// ── Migrations ────────────────────────────────────────────────────────────────

// Drop legacy per-format price columns
const itemCols = (db.prepare("PRAGMA table_info(items)").all() as { name: string }[]).map(
  (c) => c.name
);
for (const old of ["units_per_diamond", "shulker_price", "diamond_block_price"]) {
  if (itemCols.includes(old)) db.exec(`ALTER TABLE items DROP COLUMN ${old}`);
}

// Add stack_size to items if missing
if (!itemCols.includes("stack_size")) {
  db.exec("ALTER TABLE items ADD COLUMN stack_size INTEGER NOT NULL DEFAULT 64");
}

// Add suggested_category_id to submissions if missing
const subCols = (db.prepare("PRAGMA table_info(submissions)").all() as { name: string }[]).map(
  (c) => c.name
);
if (!subCols.includes("suggested_category_id")) {
  db.exec(
    "ALTER TABLE submissions ADD COLUMN suggested_category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL"
  );
}

// Add role column to admins if missing
const adminCols = (db.prepare("PRAGMA table_info(admins)").all() as { name: string }[]).map(
  (c) => c.name
);
if (!adminCols.includes("role")) {
  db.exec("ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'staff'");
  // Promote the earliest admin to owner if no owner exists
  db.exec(
    "UPDATE admins SET role = 'owner' WHERE id = (SELECT MIN(id) FROM admins)"
  );
}

// ── Seed initial admin from env vars if the table is empty ───────────────────
const adminCount = (db.prepare("SELECT COUNT(*) as n FROM admins").get() as { n: number }).n;
if (adminCount === 0) {
  const username = process.env.ADMIN_USERNAME;
  const hash = process.env.ADMIN_PASSWORD_HASH;
  if (username && hash) {
    db.prepare("INSERT INTO admins (username, password_hash, role) VALUES (?, ?, 'owner')").run(username, hash);
    console.log(`[db] Seeded initial admin "${username}" from env vars.`);
  } else if (username && process.env.ADMIN_PASSWORD) {
    // Plain-text fallback (dev only)
    const autoHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
    db.prepare("INSERT INTO admins (username, password_hash, role) VALUES (?, ?, 'owner')").run(username, autoHash);
    console.log(`[db] Seeded initial admin "${username}" (plain-text password - set ADMIN_PASSWORD_HASH in production).`);
  } else {
    console.warn("[db] WARNING: No admins in DB and no ADMIN_USERNAME/ADMIN_PASSWORD_HASH env vars set. Set them to create the first admin.");
  }
}

export default db;
