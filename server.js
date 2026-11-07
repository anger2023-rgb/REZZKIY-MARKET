
import express from "express";
import pg from "pg";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const { Pool } = pg;
const PORT = Number(process.env.PORT || 8080);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(express.json({ limit: "5mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes(".railway.internal") ||
       process.env.DATABASE_URL?.includes("localhost") ||
       process.env.DATABASE_URL?.includes("127.0.0.1")
    ? false
    : { rejectUnauthorized: false }
});

const categories = {
  rifles: [
    "AK-47","M4A4","M4A1-S","AWP","AUG",
    "FAMAS","Galil AR","SG 553","SSG 08",
    "SCAR-20","G3SG1"
  ],
  pistols: [
    "Glock-18","USP-S","P2000","Desert Eagle",
    "P250","Five-SeveN","Tec-9","CZ75-Auto",
    "Dual Berettas","R8 Revolver"
  ],
  smg: [
    "MP9","MAC-10","MP7","MP5-SD",
    "UMP-45","P90","PP-Bizon"
  ],
  heavy: [
    "Nova","XM1014","MAG-7",
    "Sawed-Off","M249","Negev"
  ],
  knives: [
    "Karambit","Bayonet","M9 Bayonet",
    "Butterfly Knife","Flip Knife","Gut Knife",
    "Huntsman Knife","Falchion Knife","Bowie Knife",
    "Shadow Daggers","Navaja Knife","Stiletto Knife",
    "Ursus Knife","Talon Knife","Classic Knife",
    "Paracord Knife","Survival Knife","Nomad Knife",
    "Skeleton Knife","Kukri Knife"
  ],
  gloves: [
    "Sport Gloves","Driver Gloves","Hand Wraps",
    "Moto Gloves","Specialist Gloves","Hydra Gloves",
    "Bloodhound Gloves","Broken Fang Gloves"
  ]
};

const conditions = [
  "Factory New","Minimal Wear","Field-Tested",
  "Well-Worn","Battle-Scarred","Not Painted"
];

function getCategory(weapon) {
  for (const [category, weapons] of Object.entries(categories)) {
    if (weapons.includes(weapon)) return category;
  }
  return null;
}

function verifyTelegram(initData) {
  const token = process.env.BOT_TOKEN;

  if (!token || typeof initData !== "string" || !initData) {
    return null;
  }

  try {
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");

    if (!hash || !/^[0-9a-f]{64}$/i.test(hash)) {
      return null;
    }

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
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secret = crypto
      .createHmac("sha256", "WebAppData")
      .update(token)
      .digest();

    const expected = crypto
      .createHmac("sha256", secret)
      .update(dataCheckString)
      .digest();

    const received = Buffer.from(hash, "hex");

    if (
      received.length !== expected.length ||
      !crypto.timingSafeEqual(received, expected)
    ) {
      return null;
    }

    const user = JSON.parse(params.get("user") || "null");

    return user && Number.isSafeInteger(user.id)
      ? user
      : null;

  } catch {
    return null;
  }
}

function requireAdmin(req, res, next) {
  const user = verifyTelegram(req.get("X-Telegram-Init-Data"));

  if (!user) {
    return res.status(401).json({
      error: "Telegram-авторизация не прошла"
    });
  }

  const adminId = Number(process.env.ADMIN_TELEGRAM_ID);

  if (!Number.isSafeInteger(adminId) || user.id !== adminId) {
    return res.status(403).json({
      error: "Нет прав администратора"
    });
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
      price INTEGER NOT NULL CHECK(price > 0),
      quantity INTEGER NOT NULL DEFAULT 1 CHECK(quantity >= 0),
      image_url TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS product_images (
      id UUID PRIMARY KEY,
      mime TEXT NOT NULL,
      data BYTEA NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  console.log("Database ready");
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/api/categories", (req, res) => {
  res.json(categories);
});

app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM products ORDER BY created_at DESC, id DESC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Products:", err.message);
    res.status(500).json({
      error: "Не удалось загрузить товары"
    });
  }
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({ admin: true, id: req.admin.id });
});

// Загрузка фотографии из галереи
app.post("/api/images", requireAdmin, async (req, res) => {
  try {
    const image = req.body?.image;

    if (typeof image !== "string") {
      return res.status(400).json({
        error: "Выбери фотографию"
      });
    }

    const match = image.match(
      /^data:(image\/jpeg|image\/png|image\/webp);base64,([A-Za-z0-9+/]+={0,2})$/
    );

    if (!match) {
      return res.status(400).json({
        error: "Нужен файл JPG, PNG или WebP"
      });
    }

    const mime = match[1];
    const base64 = match[2];

    if (base64.length > 4 * 1024 * 1024) {
      return res.status(400).json({
        error: "Фотография слишком большая"
      });
    }

    const data = Buffer.from(base64, "base64");

    if (!data.length || data.length > 3 * 1024 * 1024) {
      return res.status(400).json({
        error: "Максимальный размер фотографии — 3 МБ"
      });
    }

    const isJpeg =
      data.length >= 3 &&
      data[0] === 0xff &&
      data[1] === 0xd8 &&
      data[2] === 0xff;

    const isPng =
      data.length >= 8 &&
      data.subarray(0, 8).equals(
        Buffer.from([137,80,78,71,13,10,26,10])
      );

    const isWebp =
      data.length >= 12 &&
      data.toString("ascii", 0, 4) === "RIFF" &&
      data.toString("ascii", 8, 12) === "WEBP";

    if (
      !(
        (mime === "image/jpeg" && isJpeg) ||
        (mime === "image/png" && isPng) ||
        (mime === "image/webp" && isWebp)
      )
    ) {
      return res.status(400).json({
        error: "Формат фотографии не соответствует файлу"
      });
    }

    const id = crypto.randomUUID();

    await pool.query(
      "INSERT INTO product_images(id,mime,data) VALUES($1,$2,$3)",
      [id, mime, data]
    );

    res.status(201).json({
      url: `/api/images/${id}`
    });

  } catch (err) {
    console.error("Upload:", err.message);
    res.status(500).json({
      error: "Ошибка загрузки фотографии"
    });
  }
});

// Отображение фотографии в каталоге
app.get("/api/images/:id", async (req, res) => {
  const id = req.params.id;

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    return res.sendStatus(400);
  }

  try {
    const result = await pool.query(
      "SELECT mime,data FROM product_images WHERE id=$1",
      [id]
    );

    if (!result.rowCount) {
      return res.sendStatus(404);
    }

    res.set("Content-Type", result.rows[0].mime);
    res.set("Cache-Control", "public, max-age=86400");
    res.set("X-Content-Type-Options", "nosniff");
    res.send(result.rows[0].data);

  } catch (err) {
    console.error("Image:", err.message);
    res.sendStatus(500);
  }
});

// Добавление товара
app.post("/api/products", requireAdmin, async (req, res) => {
  try {
    const {
      weapon, skin, condition,
      price, quantity, image_url
    } = req.body || {};

    const category = getCategory(weapon);

    if (
      !category ||
      typeof skin !== "string" ||
      !skin.trim() ||
      skin.length > 150 ||
      !conditions.includes(condition) ||
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
        error: "Проверь данные товара"
      });
    }

    if (image_url) {
      const internalImage =
        /^\/api\/images\/[0-9a-f-]{36}$/i.test(image_url);

      if (!internalImage) {
        try {
          const url = new URL(image_url);
          if (url.protocol !== "https:") throw Error();
        } catch {
          return res.status(400).json({
            error: "Неверный адрес изображения"
          });
        }
      }
    }

    const result = await pool.query(
      `INSERT INTO products
      (weapon,skin,category,condition,price,quantity,image_url)
      VALUES($1,$2,$3,$4,$5,$6,$7)
      RETURNING *`,
      [
        weapon, skin.trim(), category, condition,
        price, quantity, image_url
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch (err) {
    console.error("Add product:", err.message);
    res.status(500).json({
      error: "Не удалось добавить товар"
    });
  }
});

// Удаление товара
app.delete("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) {
      return res.status(400).json({
        error: "Неверный ID"
      });
    }

    const result = await pool.query(
      "DELETE FROM products WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Товар не найден"
      });
    }

    res.json({ success: true });

  } catch (err) {
    console.error("Delete:", err.message);
    res.status(500).json({
      error: "Не удалось удалить товар"
    });
  }
});

// Сайт
app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

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
    console.log(`REZZKIY MARKET started on port ${PORT}`);
  });
}

start().catch(err => {
  console.error("Startup error:", err.message);
  process.exit(1);
});
