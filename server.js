
import express from "express";
import pg from "pg";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const { Pool } = pg;
const PORT = Number(process.env.PORT || 8080);

const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(express.json({ limit: "100kb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

const categories = {
  rifles: [
    "AK-47", "M4A4", "M4A1-S", "AWP",
    "AUG", "FAMAS", "Galil AR", "SG 553",
    "SSG 08", "SCAR-20", "G3SG1"
  ],
  pistols: [
    "Glock-18", "USP-S", "P2000",
    "Desert Eagle", "P250", "Five-SeveN",
    "Tec-9", "CZ75-Auto", "Dual Berettas",
    "R8 Revolver"
  ],
  smg: [
    "MP9", "MAC-10", "MP7", "MP5-SD",
    "UMP-45", "P90", "PP-Bizon"
  ],
  heavy: [
    "Nova", "XM1014", "MAG-7",
    "Sawed-Off", "M249", "Negev"
  ],
  knives: [
    "Karambit", "Bayonet", "M9 Bayonet",
    "Butterfly Knife", "Flip Knife",
    "Gut Knife", "Huntsman Knife",
    "Falchion Knife", "Bowie Knife",
    "Shadow Daggers", "Navaja Knife",
    "Stiletto Knife", "Ursus Knife",
    "Talon Knife", "Classic Knife",
    "Paracord Knife", "Survival Knife",
    "Nomad Knife", "Skeleton Knife",
    "Kukri Knife"
  ],
  gloves: [
    "Sport Gloves", "Driver Gloves",
    "Hand Wraps", "Moto Gloves",
    "Specialist Gloves", "Hydra Gloves",
    "Bloodhound Gloves", "Broken Fang Gloves"
  ]
};

function getCategory(weapon) {
  for (const [category, weapons] of Object.entries(categories)) {
    if (weapons.includes(weapon)) return category;
  }
  return null;
}

function verifyTelegram(initData) {
  const token = process.env.BOT_TOKEN;
  if (!token || !initData || typeof initData !== "string") {
    return null;
  }

  try {
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) return null;

    params.delete("hash");
    params.delete("signature");

    const authDate = Number(params.get("auth_date"));
    const now = Math.floor(Date.now() / 1000);

    if (!authDate || authDate > now + 60 || now - authDate > 3600) {
      return null;
    }

    const dataCheck = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secret = crypto
      .createHmac("sha256", "WebAppData")
      .update(token)
      .digest();

    const expected = crypto
      .createHmac("sha256", secret)
      .update(dataCheck)
      .digest();

    const received = Buffer.from(hash, "hex");

    if (
      received.length !== expected.length ||
      !crypto.timingSafeEqual(received, expected)
    ) {
      return null;
    }

    const user = JSON.parse(params.get("user") || "null");
    return user && Number.isSafeInteger(user.id) ? user : null;
  } catch {
    return null;
  }
}

function requireAdmin(req, res, next) {
  const user = verifyTelegram(req.get("X-Telegram-Init-Data"));
  const adminId = Number(process.env.ADMIN_TELEGRAM_ID);

  if (!user) {
    return res.status(401).json({ error: "Требуется авторизация Telegram" });
  }

  if (!adminId || user.id !== adminId) {
    return res.status(403).json({ error: "Нет прав администратора" });
  }

  req.admin = user;
  next();
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id BIGSERIAL PRIMARY KEY,
      weapon TEXT NOT NULL,
      skin TEXT NOT NULL,
      category TEXT NOT NULL,
      condition TEXT NOT NULL,
      price INTEGER NOT NULL CHECK (price > 0),
      quantity INTEGER NOT NULL DEFAULT 1 CHECK (quantity >= 0),
      image_url TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

app.get("/api/categories", (req, res) => {
  res.json(categories);
});

app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM products ORDER BY created_at DESC, id DESC"
    );
    res.json(result.rows);
  } catch {
    res.status(500).json({ error: "Ошибка загрузки товаров" });
  }
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({
    admin: true,
    id: req.admin.id
  });
});

app.post("/api/products", requireAdmin, async (req, res) => {
  try {
    const { weapon, skin, condition, price, quantity, image_url } = req.body;

    const category = getCategory(weapon);
    const validConditions = [
      "Factory New", "Minimal Wear", "Field-Tested",
      "Well-Worn", "Battle-Scarred", "Not Painted"
    ];

    if (
      !category ||
      typeof skin !== "string" ||
      !skin.trim() ||
      skin.length > 150 ||
      !validConditions.includes(condition) ||
      !Number.isSafeInteger(price) ||
      price <= 0 ||
      !Number.isSafeInteger(quantity) ||
      quantity < 0 ||
      typeof image_url !== "string" ||
      image_url.length > 2000
    ) {
      return res.status(400).json({ error: "Неверные данные товара" });
    }

    if (image_url) {
      const url = new URL(image_url);
      if (url.protocol !== "https:") {
        return res.status(400).json({ error: "Изображение должно использовать HTTPS" });
      }
    }

    const result = await pool.query(
      `INSERT INTO products
       (weapon, skin, category, condition, price, quantity, image_url)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [weapon, skin.trim(), category, condition, price, quantity, image_url]
    );

    res.status(201).json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Не удалось добавить товар" });
  }
});

app.delete("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) {
      return res.status(400).json({ error: "Неверный ID" });
    }

    const result = await pool.query(
      "DELETE FROM products WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Товар не найден" });
    }

    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Не удалось удалить товар" });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

async function start() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL не настроен");
  }
  if (!process.env.BOT_TOKEN || !process.env.ADMIN_TELEGRAM_ID) {
    throw new Error("BOT_TOKEN или ADMIN_TELEGRAM_ID не настроен");
  }

  await initDatabase();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`REZZKIY MARKET server started on port ${PORT}`);
  });
}

start().catch(err => {
  console.error("Server startup failed:", err.message);
  process.exit(1);
});

