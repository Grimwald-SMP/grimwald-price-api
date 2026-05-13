import { Router } from "express";
import { z } from "zod";
import db from "../db";
import { requireAdmin } from "../middleware/auth";

const router = Router();

const ItemSchema = z.object({
  name: z.string().min(1).max(100),
  category_id: z.number().int().nullable().optional(),
  diamond_price: z.number().positive().nullable().optional(),
  notes: z.string().max(500).nullable().optional(),
});

const CategorySchema = z.object({
  name: z.string().min(1).max(50),
  color: z.string().regex(/^#[0-9a-fA-F]{6}$/),
});

// Public: get all items with their category
router.get("/", (_req, res) => {
  const items = db
    .prepare(
      `SELECT i.*, c.name AS category_name, c.color AS category_color
       FROM items i
       LEFT JOIN categories c ON i.category_id = c.id
       ORDER BY i.name ASC`
    )
    .all();
  res.json(items);
});

// Public: get all categories
router.get("/categories", (_req, res) => {
  const categories = db.prepare("SELECT * FROM categories ORDER BY name ASC").all();
  res.json(categories);
});

// Admin: add item
router.post("/", requireAdmin, (req, res) => {
  const parsed = ItemSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const d = parsed.data;
  const result = db
    .prepare("INSERT INTO items (name, category_id, diamond_price, notes) VALUES (?, ?, ?, ?)")
    .run(d.name, d.category_id ?? null, d.diamond_price ?? null, d.notes ?? null);
  const item = db.prepare("SELECT * FROM items WHERE id = ?").get(result.lastInsertRowid);
  res.status(201).json(item);
});

// Admin: update item
router.put("/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const parsed = ItemSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const d = parsed.data;
  db.prepare(
    "UPDATE items SET name=?, category_id=?, diamond_price=?, notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?"
  ).run(d.name, d.category_id ?? null, d.diamond_price ?? null, d.notes ?? null, id);
  const item = db.prepare("SELECT * FROM items WHERE id = ?").get(id);
  if (!item) {
    res.status(404).json({ error: "Item not found" });
    return;
  }
  res.json(item);
});

// Admin: delete item
router.delete("/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare("DELETE FROM items WHERE id = ?").run(id);
  if (info.changes === 0) {
    res.status(404).json({ error: "Item not found" });
    return;
  }
  res.json({ ok: true });
});

// Admin: add category
router.post("/categories", requireAdmin, (req, res) => {
  const parsed = CategorySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const result = db
    .prepare("INSERT INTO categories (name, color) VALUES (?, ?)")
    .run(parsed.data.name, parsed.data.color);
  const cat = db.prepare("SELECT * FROM categories WHERE id = ?").get(result.lastInsertRowid);
  res.status(201).json(cat);
});

// Admin: update category
router.put("/categories/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const parsed = CategorySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  db.prepare("UPDATE categories SET name=?, color=? WHERE id=?").run(
    parsed.data.name,
    parsed.data.color,
    id
  );
  const cat = db.prepare("SELECT * FROM categories WHERE id = ?").get(id);
  if (!cat) {
    res.status(404).json({ error: "Category not found" });
    return;
  }
  res.json(cat);
});

// Admin: delete category
router.delete("/categories/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare("DELETE FROM categories WHERE id = ?").run(id);
  if (info.changes === 0) {
    res.status(404).json({ error: "Category not found" });
    return;
  }
  res.json({ ok: true });
});

// Admin: bulk import
router.post("/bulk", requireAdmin, (req, res) => {
  const rows = z.array(ItemSchema).safeParse(req.body);
  if (!rows.success) {
    res.status(400).json({ error: rows.error.flatten() });
    return;
  }
  const insert = db.prepare(
    "INSERT INTO items (name, category_id, diamond_price, notes) VALUES (?, ?, ?, ?)"
  );
  const insertMany = db.transaction((items: typeof rows.data) => {
    for (const d of items) {
      insert.run(d.name, d.category_id ?? null, d.diamond_price ?? null, d.notes ?? null);
    }
  });
  insertMany(rows.data);
  res.json({ inserted: rows.data.length });
});

export default router;
