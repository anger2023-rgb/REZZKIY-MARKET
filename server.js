
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
  ssl:
    process.env.DATABASE_URL?.includes("localhost") ||
    process.env.DATABASE_URL?.includes("127.0.0.1") ||
    process.env.DATABASE_URL?.includes(".railway.internal")
      ? false
      : { rejectUnauthorized: false }
});

// =====================================
// КАТЕГОРИИ CS2
// =====================================

const categories = {
  rifles: [
    "AK-47",
    "M4A4",
    "M4A1-S",
    "AWP",
    "AUG",
    "FAMAS",
    "Galil AR",
    "SG 553",
    "SSG 08",
    "SCAR-20",
    "G3SG1"
  ],

  pistols: [
    "Glock-18",
    "USP-S",
    "P2000",
    "Desert Eagle",
    "P250",
    "Five-SeveN",
    "Tec-9",
    "CZ75-Auto",
    "Dual Berettas",
    "R8 Revolver"
  ],

  smg: [
    "MP9",
    "MAC-10",
    "MP7",
    "MP5-SD",
    "UMP-45",
    "P90",
    "PP-Bizon"
  ],

  heavy: [
    "Nova",
    "XM1014",
    "MAG-7",
    "Sawed-Off",
    "M249",
    "Negev"
  ],

  knives: [
    "Karambit",
    "Bayonet",
    "M9 Bayonet",
    "Butterfly Knife",
    "Flip Knife",
    "Gut Knife",
    "Huntsman Knife",
    "Falchion Knife",
    "Bowie Knife",
    "Shadow Daggers",
    "Navaja Knife",
    "Stiletto Knife",
    "Ursus Knife",
    "Talon Knife",
    "Classic Knife",
    "Paracord Knife",
    "Survival Knife",
    "Nomad Knife",
    "Skeleton Knife",
    "Kukri Knife"
  ],

  gloves: [
    "Sport Gloves",
    "Driver Gloves",
    "Hand Wraps",
    "Moto Gloves",
    "Specialist Gloves",
    "Hydra Gloves",
    "Bloodhound Gloves",
    "Broken Fang Gloves"
  ]
};

function getCategory(weapon) {
  for (const [category, weapons] of Object.entries(categories)) {
    if (weapons.includes(weapon)) {
      return category;
    }
  }

  return null;
}

// =====================================
// TELEGRAM АВТОРИЗАЦИЯ
// =====================================

function verifyTelegram(initData) {
  const token = process.env.BOT_TOKEN;

  if (!token || typeof initData !== "string" || !initData) {
    return null;
  }

  try {
    const params = new URLSearchParams(initData);

    const hash = params.get("hash");

    if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) {
      return null;
    }

    // Для проверки hash удаляется только hash.
    // Поле signature, если оно есть, остаётся.
    params.delete("hash");

    const authDateRaw = params.get("auth_date");
    const authDate = Number(authDateRaw);
    const now = Math.floor(Date.now() / 1000);

    if (
      !authDateRaw ||
      !Number.isSafeInteger(authDate) ||
      authDate > now + 60 ||
      now - authDate > 3600
    ) {
      return null;
    }

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => {
        if (a < b) return -1;
        if (a > b) return 1;
        return 0;
      })
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(token)
      .digest();

    const calculatedHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest();

    const receivedHash = Buffer.from(hash, "hex");

    if (
      receivedHash.length !== calculatedHash.length ||
      !crypto.timingSafeEqual(receivedHash, calculatedHash)
    ) {
      return null;
    }

    const userRaw = params.get("user");

    if (!userRaw) {
      return null;
    }

    const user = JSON.parse(userRaw);

    if (
      !user ||
      typeof user !== "object" ||
      !Number.isSafeInteger(user.id)
    ) {
      return null;
    }

    return user;

  } catch (error) {
    console.error("Telegram verification failed:", error.message);
    return null;
  }
}

// =====================================
// ПРОВЕРКА АДМИНИСТРАТОРА
// =====================================

function requireAdmin(req, res, next) {
  const initData = req.get("X-Telegram-Init-Data");
  const user = verifyTelegram(initData);

  if (!user) {
    return res.status(401).json({
      error: "Telegram-авторизация не прошла"
    });
  }

  const adminId = Number(process.env.ADMIN_TELEGRAM_ID);

  if (
    !Number.isSafeInteger(adminId) ||
    user.id !== adminId
  ) {
    return res.status(403).json({
      error: "Нет прав администратора"
    });
  }

  req.admin = user;
  next();
}

// =====================================
// POSTGRESQL
// =====================================

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

  console.log("Database initialized");
}

// =====================================
// КАТЕГОРИИ
// =====================================

app.get("/api/categories", (req, res) => {
  res.json(categories);
});

// =====================================
// КАТАЛОГ ТОВАРОВ
// =====================================

app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM products
      ORDER BY created_at DESC, id DESC
    `);

    res.json(result.rows);

  } catch (error) {
    console.error("Products error:", error.message);

    res.status(500).json({
      error: "Ошибка загрузки товаров"
    });
  }
});

// =====================================
// ПРОВЕРКА ПРАВ АДМИНА
// =====================================

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({
    admin: true,
    id: req.admin.id
  });
});

// =====================================
// ДОБАВЛЕНИЕ ТОВАРА
// =====================================

app.post("/api/products", requireAdmin, async (req, res) => {
  try {
    const {
      weapon,
      skin,
      condition,
      price,
      quantity,
      image_url
    } = req.body || {};

    const category = getCategory(weapon);

    const validConditions = [
      "Factory New",
      "Minimal Wear",
      "Field-Tested",
      "Well-Worn",
      "Battle-Scarred",
      "Not Painted"
    ];

    if (
      !category ||
      typeof skin !== "string" ||
      !skin.trim() ||
      skin.length > 150 ||
      !validConditions.includes(condition) ||
      !Number.isSafeInteger(price) ||
      price <= 0 ||
      price > 2147483647 ||
      !Number.isSafeInteger(quantity) ||
      quantity < 0 ||
      quantity > 2147483647 ||
      typeof image_url !== "string" ||
      image_url.length > 2000
    ) {
      return res.status(400).json({
        error: "Неверные данные товара"
      });
    }

    if (image_url) {
      let imageUrl;

      try {
        imageUrl = new URL(image_url);
      } catch {
        return res.status(400).json({
          error: "Некорректная ссылка на изображение"
        });
      }

      if (imageUrl.protocol !== "https:") {
        return res.status(400).json({
          error: "Изображение должно использовать HTTPS"
        });
      }
    }

    const result = await pool.query(
      `
      INSERT INTO products (
        weapon,
        skin,
        category,
        condition,
        price,
        quantity,
        image_url
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *
      `,
      [
        weapon,
        skin.trim(),
        category,
        condition,
        price,
        quantity,
        image_url
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("Add product error:", error.message);

    res.status(500).json({
      error: "Не удалось добавить товар"
    });
  }
});

// =====================================
// УДАЛЕНИЕ ТОВАРА
// =====================================

app.delete("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    if (!/^\d+$/.test(id)) {
      return res.status(400).json({
        error: "Неверный ID товара"
      });
    }

    const result = await pool.query(
      "DELETE FROM products WHERE id = $1 RETURNING id",
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Товар не найден"
      });
    }

    res.json({
      success: true
    });

  } catch (error) {
    console.error("Delete product error:", error.message);

    res.status(500).json({
      error: "Не удалось удалить товар"
    });
  }
});

// =====================================
// ПРОВЕРКА РАБОТЫ СЕРВЕРА
// =====================================

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok"
  });
});

// =====================================
// FRONTEND
// =====================================

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// =====================================
// ЗАПУСК
// =====================================

async function start() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL не настроен");
  }

  if (!process.env.BOT_TOKEN) {
    throw new Error("BOT_TOKEN не настроен");
  }

  if (!process.env.ADMIN_TELEGRAM_ID) {
    throw new Error("ADMIN_TELEGRAM_ID не настроен");
  }

  await initDatabase();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(
      `REZZKIY MARKET server started on port ${PORT}`
    );
  });
}

start().catch(error => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});
