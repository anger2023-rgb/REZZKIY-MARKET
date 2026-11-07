
import express from 'express';
import pg from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const { Pool } = pg;
const PORT = Number(process.env.PORT || 8080);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SITE_URL = 'https://rezzkiy-market-production-dbf4.up.railway.app';
const STEAM_OPENID = 'https://steamcommunity.com/openid/login';
const OPENID_NS = 'http://specs.openid.net/auth/2.0';
const IDENTIFIER_SELECT = OPENID_NS + '/identifier_select';
const RULES_VERSION = '2026-11-07-v1';

app.disable('x-powered-by');
app.use(express.json({ limit: '5mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('.railway.internal') ||
       process.env.DATABASE_URL?.includes('localhost') ||
       process.env.DATABASE_URL?.includes('127.0.0.1')
    ? false : { rejectUnauthorized: false }
});

const categories = {
  rifles: ['AK-47','M4A4','M4A1-S','AWP','AUG','FAMAS','Galil AR','SG 553','SSG 08','SCAR-20','G3SG1'],
  pistols: ['Glock-18','USP-S','P2000','Desert Eagle','P250','Five-SeveN','Tec-9','CZ75-Auto','Dual Berettas','R8 Revolver'],
  smg: ['MP9','MAC-10','MP7','MP5-SD','UMP-45','P90','PP-Bizon'],
  heavy: ['Nova','XM1014','MAG-7','Sawed-Off','M249','Negev'],
  knives: ['Karambit','Bayonet','M9 Bayonet','Butterfly Knife','Flip Knife','Gut Knife','Huntsman Knife','Falchion Knife','Bowie Knife','Shadow Daggers','Navaja Knife','Stiletto Knife','Ursus Knife','Talon Knife','Classic Knife','Paracord Knife','Survival Knife','Nomad Knife','Skeleton Knife','Kukri Knife'],
  gloves: ['Sport Gloves','Driver Gloves','Hand Wraps','Moto Gloves','Specialist Gloves','Hydra Gloves','Bloodhound Gloves','Broken Fang Gloves']
};

const conditions = [
  'Factory New',
  'Minimal Wear',
  'Field-Tested',
  'Well-Worn',
  'Battle-Scarred',
  'Not Painted'
];

function getCategory(weapon) {
  for (const [category, weapons] of Object.entries(categories)) {
    if (weapons.includes(weapon)) return category;
  }
  return null;
}

function verifyTelegram(initData) {
  const token = process.env.BOT_TOKEN;
  if (!token || typeof initData !== 'string' || !initData) return null;

  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');

    if (!hash || !/^[0-9a-f]{64}$/i.test(hash)) return null;
    params.delete('hash');

    const authDateRaw = params.get('auth_date');
    const authDate = Number(authDateRaw);
    const now = Math.floor(Date.now() / 1000);

    if (
      !authDateRaw ||
      !Number.isSafeInteger(authDate) ||
      authDate > now + 60 ||
      now - authDate > 3600
    ) return null;

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');

    const secret = crypto
      .createHmac('sha256', 'WebAppData')
      .update(token)
      .digest();

    const expected = crypto
      .createHmac('sha256', secret)
      .update(dataCheckString)
      .digest();

    const received = Buffer.from(hash, 'hex');

    if (
      received.length !== expected.length ||
      !crypto.timingSafeEqual(received, expected)
    ) return null;

    const user = JSON.parse(params.get('user') || 'null');

    return user && Number.isSafeInteger(user.id) ? user : null;
  } catch {
    return null;
  }
}

function requireTelegram(req, res, next) {
  const user = verifyTelegram(req.get('X-Telegram-Init-Data'));

  if (!user) {
    return res.status(401).json({
      error: 'Открой магазин через Telegram'
    });
  }

  req.telegramUser = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = verifyTelegram(req.get('X-Telegram-Init-Data'));

  if (!user) {
    return res.status(401).json({
      error: 'Telegram-авторизация не прошла'
    });
  }

  const adminId = Number(process.env.ADMIN_TELEGRAM_ID);

  if (!Number.isSafeInteger(adminId) || user.id !== adminId) {
    return res.status(403).json({
      error: 'Нет прав администратора'
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS steam_accounts (
      telegram_id BIGINT PRIMARY KEY,
      steam_id TEXT NOT NULL UNIQUE,
      linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS steam_auth_states (
      state_hash TEXT PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sell_consents (
      telegram_id BIGINT PRIMARY KEY,
      rules_version TEXT NOT NULL,
      agreed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS buyout_requests (
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      steam_id TEXT NOT NULL,
      items JSONB NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      offer_rub INTEGER,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  console.log('Database ready');
}

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.get('/api/categories', (_req, res) => {
  res.json(categories);
});

app.get('/api/products', async (_req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM products ORDER BY created_at DESC, id DESC'
    );

    res.json(result.rows);
  } catch (err) {
    console.error('Products:', err.message);
    res.status(500).json({
      error: 'Не удалось загрузить товары'
    });
  }
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
  res.json({
    admin: true,
    id: req.admin.id
  });
});

app.post('/api/images', requireAdmin, async (req, res) => {
  try {
    const image = req.body?.image;

    if (typeof image !== 'string') {
      return res.status(400).json({
        error: 'Выбери фотографию'
      });
    }

    const match = image.match(
      /^data:(image\/jpeg|image\/png|image\/webp);base64,([A-Za-z0-9+/]+={0,2})$/
    );

    if (!match) {
      return res.status(400).json({
        error: 'Нужен файл JPG, PNG или WebP'
      });
    }

    const [, mime, base64] = match;

    if (base64.length > 4 * 1024 * 1024) {
      return res.status(400).json({
        error: 'Фотография слишком большая'
      });
    }

    const data = Buffer.from(base64, 'base64');

    if (!data.length || data.length > 3 * 1024 * 1024) {
      return res.status(400).json({
        error: 'Максимальный размер фотографии — 3 МБ'
      });
    }

    const isJpeg =
      data.length >= 3 &&
      data[0] === 255 &&
      data[1] === 216 &&
      data[2] === 255;

    const isPng =
      data.length >= 8 &&
      data.subarray(0, 8).equals(
        Buffer.from([137,80,78,71,13,10,26,10])
      );

    const isWebp =
      data.length >= 12 &&
      data.toString('ascii', 0, 4) === 'RIFF' &&
      data.toString('ascii', 8, 12) === 'WEBP';

    if (
      !(
        (mime === 'image/jpeg' && isJpeg) ||
        (mime === 'image/png' && isPng) ||
        (mime === 'image/webp' && isWebp)
      )
    ) {
      return res.status(400).json({
        error: 'Формат фотографии не соответствует файлу'
      });
    }

    const id = crypto.randomUUID();

    await pool.query(
      'INSERT INTO product_images(id,mime,data) VALUES($1,$2,$3)',
      [id, mime, data]
    );

    res.status(201).json({
      url: `/api/images/${id}`
    });
  } catch (err) {
    console.error('Upload:', err.message);
    res.status(500).json({
      error: 'Ошибка загрузки фотографии'
    });
  }
});

app.get('/api/images/:id', async (req, res) => {
  const id = req.params.id;

  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)
  ) {
    return res.sendStatus(400);
  }

  try {
    const result = await pool.query(
      'SELECT mime,data FROM product_images WHERE id=$1',
      [id]
    );

    if (!result.rowCount) return res.sendStatus(404);

    res.set('Content-Type', result.rows[0].mime);
    res.set('Cache-Control', 'public, max-age=86400');
    res.set('X-Content-Type-Options', 'nosniff');

    res.send(result.rows[0].data);
  } catch (err) {
    console.error('Image:', err.message);
    res.sendStatus(500);
  }
});

app.post('/api/products', requireAdmin, async (req, res) => {
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

    if (
      !category ||
      typeof skin !== 'string' ||
      !skin.trim() ||
      skin.length > 150 ||
      !conditions.includes(condition) ||
      !Number.isSafeInteger(price) ||
      price <= 0 ||
      price > 2147483647 ||
      !Number.isSafeInteger(quantity) ||
      quantity < 0 ||
      quantity > 2147483647 ||
      typeof image_url !== 'string' ||
      image_url.length > 2000
    ) {
      return res.status(400).json({
        error: 'Проверь данные товара'
      });
    }

    if (image_url) {
      const internal =
        /^\/api\/images\/[0-9a-f-]{36}$/i.test(image_url);

      if (!internal) {
        try {
          if (new URL(image_url).protocol !== 'https:') {
            throw Error();
          }
        } catch {
          return res.status(400).json({
            error: 'Неверный адрес изображения'
          });
        }
      }
    }

    const result = await pool.query(`
      INSERT INTO products
      (weapon,skin,category,condition,price,quantity,image_url)
      VALUES($1,$2,$3,$4,$5,$6,$7)
      RETURNING *
    `, [
      weapon,
      skin.trim(),
      category,
      condition,
      price,
      quantity,
      image_url
    ]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Add product:', err.message);
    res.status(500).json({
      error: 'Не удалось добавить товар'
    });
  }
});

app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) {
      return res.status(400).json({
        error: 'Неверный ID'
      });
    }

    const result = await pool.query(
      'DELETE FROM products WHERE id=$1 RETURNING id',
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Товар не найден'
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Delete:', err.message);
    res.status(500).json({
      error: 'Не удалось удалить товар'
    });
  }
});

function hashState(value) {
  return crypto
    .createHash('sha256')
    .update(value)
    .digest('hex');
}

app.post('/api/steam/connect', requireTelegram, async (req, res) => {
  try {
    const state = crypto.randomBytes(32).toString('hex');

    await pool.query(
      'DELETE FROM steam_auth_states WHERE expires_at < NOW()'
    );

    await pool.query(`
      INSERT INTO steam_auth_states
      (state_hash,telegram_id,expires_at)
      VALUES($1,$2,NOW() + INTERVAL '10 minutes')
    `, [
      hashState(state),
      req.telegramUser.id
    ]);

    const url = new URL(STEAM_OPENID);
    const callback =
      `${SITE_URL}/auth/steam/callback?state=${state}`;

    const params = {
      'openid.ns': OPENID_NS,
      'openid.mode': 'checkid_setup',
      'openid.return_to': callback,
      'openid.realm': SITE_URL + '/',
      'openid.identity': IDENTIFIER_SELECT,
      'openid.claimed_id': IDENTIFIER_SELECT
    };

    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }

    res.json({
      url: url.toString()
    });
  } catch (err) {
    console.error('Steam connect:', err.message);
    res.status(500).json({
      error: 'Не удалось начать привязку Steam'
    });
  }
});

app.get('/auth/steam/callback', async (req, res) => {
  const fail = () => res.redirect(303, '/?steam=error');
  const state = req.query.state;

  if (
    typeof state !== 'string' ||
    !/^[0-9a-f]{64}$/.test(state)
  ) {
    return fail();
  }

  try {
    const pending = await pool.query(`
      DELETE FROM steam_auth_states
      WHERE state_hash=$1 AND expires_at>NOW()
      RETURNING telegram_id
    `, [hashState(state)]);

    if (!pending.rowCount) return fail();

    const params = new URLSearchParams();

    for (const [key, value] of Object.entries(req.query)) {
      if (
        key.startsWith('openid.') &&
        typeof value === 'string'
      ) {
        params.set(key, value);
      }
    }

    const claimed = params.get('openid.claimed_id') || '';
    const match =
      /^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/.exec(claimed);

    if (
      params.get('openid.mode') !== 'id_res' ||
      params.get('openid.ns') !== OPENID_NS ||
      params.get('openid.op_endpoint') !== STEAM_OPENID ||
      params.get('openid.return_to') !==
        `${SITE_URL}/auth/steam/callback?state=${state}` ||
      !match ||
      params.get('openid.identity') !== claimed ||
      !params.get('openid.response_nonce') ||
      !params.get('openid.assoc_handle') ||
      !params.get('openid.sig')
    ) {
      return fail();
    }

    const signed =
      (params.get('openid.signed') || '').split(',');

    const required = [
      'return_to',
      'claimed_id',
      'identity',
      'response_nonce',
      'assoc_handle',
      'op_endpoint'
    ];

    if (!required.every(key => signed.includes(key))) {
      return fail();
    }

    params.set('openid.mode', 'check_authentication');

    const response = await fetch(STEAM_OPENID, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString(),
      signal: AbortSignal.timeout(10000)
    });

    const body = await response.text();

    if (
      !response.ok ||
      !/^is_valid:true\s*$/m.test(body)
    ) {
      return fail();
    }

    await pool.query(`
      INSERT INTO steam_accounts(telegram_id,steam_id)
      VALUES($1,$2)
      ON CONFLICT(telegram_id)
      DO UPDATE SET
        steam_id=EXCLUDED.steam_id,
        linked_at=NOW()
    `, [
      pending.rows[0].telegram_id,
      match[1]
    ]);

    res.redirect(303, '/?steam=success');
  } catch (err) {
    console.error('Steam callback:', err.message);
    return fail();
  }
});

app.get('/api/steam/me', requireTelegram, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT steam_id,linked_at
      FROM steam_accounts
      WHERE telegram_id=$1
    `, [req.telegramUser.id]);

    res.json({
      connected: result.rowCount > 0,
      steamId: result.rows[0]?.steam_id || null
    });
  } catch (err) {
    console.error('Steam me:', err.message);
    res.status(500).json({
      error: 'Ошибка проверки Steam'
    });
  }
});

const inventoryCache = new Map();
const inventoryRequests = new Map();

async function steamForUser(id) {
  const result = await pool.query(
    'SELECT steam_id FROM steam_accounts WHERE telegram_id=$1',
    [id]
  );

  return result.rows[0]?.steam_id || null;
}

async function fetchInventory(steamId) {
  const all = [];
  let cursor = null;

  for (let page = 0; page < 5; page++) {
    const url = new URL(
      `https://steamcommunity.com/inventory/${steamId}/730/2`
    );

    url.searchParams.set('l', 'english');
    url.searchParams.set('count', '1000');

    if (cursor) {
      url.searchParams.set('start_assetid', cursor);
    }

    const response = await fetch(url, {
      headers: {
        Accept: 'application/json'
      },
      signal: AbortSignal.timeout(12000)
    });

    if (response.status === 429) {
      const error = new Error(
        'Steam ограничил запросы. Попробуй позже.'
      );
      error.status = 429;
      throw error;
    }

    if (response.status === 403) {
      const error = new Error(
        'Инвентарь закрыт или Steam запретил доступ. Сделай его публичным.'
      );
      error.status = 403;
      throw error;
    }

    if (!response.ok) {
      const error = new Error(
        'Steam временно не отдаёт инвентарь (HTTP ' +
        response.status + ').'
      );
      error.status = 502;
      throw error;
    }

    const data = await response.json();

    if (!data || data.success !== 1) {
      const error = new Error(
        'Steam не предоставил инвентарь. Проверь настройки приватности.'
      );
      error.status = 502;
      throw error;
    }

    const descriptions = new Map(
      (data.descriptions || []).map(item => [
        `${item.classid}_${item.instanceid}`,
        item
      ])
    );

    for (const asset of data.assets || []) {
      const description = descriptions.get(
        `${asset.classid}_${asset.instanceid}`
      );

      if (!description || description.tradable !== 1) {
        continue;
      }

      const icon =
        typeof description.icon_url === 'string' &&
        /^[a-zA-Z0-9_/-]+$/.test(description.icon_url)
          ? 'https://community.fastly.steamstatic.com/economy/image/' +
            description.icon_url
          : '';

      all.push({
        assetid: String(asset.assetid),
        classid: String(asset.classid),
        instanceid: String(asset.instanceid),
        name: String(
          description.market_hash_name ||
          description.name ||
          'CS2 item'
        ).slice(0, 200),
        icon,
        type: String(description.type || '').slice(0, 120),
        amount: Number(asset.amount || 1)
      });
    }

    if (!data.more_items || !data.last_assetid) {
      break;
    }

    cursor = String(data.last_assetid);
  }

  return all;
}

app.get('/api/sell/rules', requireTelegram, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT rules_version
      FROM sell_consents
      WHERE telegram_id=$1
    `, [req.telegramUser.id]);

    res.json({
      version: RULES_VERSION,
      accepted:
        result.rows[0]?.rules_version === RULES_VERSION
    });
  } catch {
    res.status(500).json({
      error: 'Ошибка проверки правил'
    });
  }
});

app.post('/api/sell/agree', requireTelegram, async (req, res) => {
  try {
    if (
      req.body?.version !== RULES_VERSION ||
      req.body?.accepted !== true
    ) {
      return res.status(400).json({
        error: 'Подтверди актуальные правила'
      });
    }

    await pool.query(`
      INSERT INTO sell_consents(telegram_id,rules_version)
      VALUES($1,$2)
      ON CONFLICT(telegram_id)
      DO UPDATE SET
        rules_version=EXCLUDED.rules_version,
        agreed_at=NOW()
    `, [
      req.telegramUser.id,
      RULES_VERSION
    ]);

    res.json({ accepted: true });
  } catch {
    res.status(500).json({
      error: 'Не удалось сохранить согласие'
    });
  }
});

async function requireSellConsent(req, res, next) {
  try {
    const result = await pool.query(`
      SELECT 1
      FROM sell_consents
      WHERE telegram_id=$1
        AND rules_version=$2
    `, [
      req.telegramUser.id,
      RULES_VERSION
    ]);

    if (!result.rowCount) {
      return res.status(403).json({
        error: 'Сначала прими правила продажи'
      });
    }

    next();
  } catch {
    res.status(500).json({
      error: 'Ошибка проверки согласия'
    });
  }
}

app.get(
  '/api/steam/inventory',
  requireTelegram,
  requireSellConsent,
  async (req, res) => {
    try {
      const steamId = await steamForUser(
        req.telegramUser.id
      );

      if (!steamId) {
        return res.status(400).json({
          error: 'Сначала привяжи Steam'
        });
      }

      const previous =
        inventoryRequests.get(steamId) || 0;

      if (Date.now() - previous < 15000) {
        return res.status(429).json({
          error: 'Подожди 15 секунд перед повторным обновлением'
        });
      }

      inventoryRequests.set(steamId, Date.now());

      const items = await fetchInventory(steamId);

      inventoryCache.set(
        String(req.telegramUser.id),
        {
          steamId,
          items,
          expires: Date.now() + 120000
        }
      );

      res.json({
        items,
        count: items.length,
        partial: items.length >= 5000
      });
    } catch (err) {
      console.error('Inventory:', err.message);

      res.status(err.status || 502).json({
        error: err.message || 'Ошибка Steam'
      });
    }
  }
);

app.post(
  '/api/sell/requests',
  requireTelegram,
  requireSellConsent,
  async (req, res) => {
    try {
      const ids = req.body?.assetids;

      if (
        !Array.isArray(ids) ||
        ids.length < 1 ||
        ids.length > 30 ||
        ids.some(
          id =>
            typeof id !== 'string' ||
            !/^\d{1,25}$/.test(id)
        ) ||
        new Set(ids).size !== ids.length
      ) {
        return res.status(400).json({
          error: 'Выбери от 1 до 30 разных предметов'
        });
      }

      const steamId = await steamForUser(
        req.telegramUser.id
      );

      const cached = inventoryCache.get(
        String(req.telegramUser.id)
      );

      if (
        !steamId ||
        !cached ||
        cached.steamId !== steamId ||
        cached.expires < Date.now()
      ) {
        return res.status(400).json({
          error: 'Обнови инвентарь перед отправкой заявки'
        });
      }

      const items = ids.map(id =>
        cached.items.find(item => item.assetid === id)
      );

      if (items.some(item => !item)) {
        return res.status(400).json({
          error: 'Некоторые предметы отсутствуют в инвентаре'
        });
      }

      const result = await pool.query(`
        INSERT INTO buyout_requests
        (telegram_id,steam_id,items)
        VALUES($1,$2,$3::jsonb)
        RETURNING id,status
      `, [
        req.telegramUser.id,
        steamId,
        JSON.stringify(items)
      ]);

      res.status(201).json(result.rows[0]);
    } catch (err) {
      console.error('Sell request:', err.message);

      res.status(500).json({
        error: 'Не удалось создать заявку'
      });
    }
  }
);

app.get(
  '/api/sell/requests',
  requireTelegram,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT id,items,status,offer_rub,created_at
        FROM buyout_requests
        WHERE telegram_id=$1
        ORDER BY id DESC
        LIMIT 50
      `, [req.telegramUser.id]);

      res.json(result.rows);
    } catch {
      res.status(500).json({
        error: 'Не удалось загрузить заявки'
      });
    }
  }
);

app.get(
  '/api/admin/buyouts',
  requireAdmin,
  async (_req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          telegram_id,
          steam_id,
          items,
          status,
          offer_rub,
          created_at
        FROM buyout_requests
        ORDER BY id DESC
        LIMIT 100
      `);

      res.json(result.rows);
    } catch {
      res.status(500).json({
        error: 'Не удалось загрузить заявки'
      });
    }
  }
);

app.post(
  '/api/admin/buyouts/:id/quote',
  requireAdmin,
  async (req, res) => {
    const price = req.body?.price;

    if (
      !/^\d+$/.test(req.params.id) ||
      !Number.isSafeInteger(price) ||
      price < 1 ||
      price > 2147483647
    ) {
      return res.status(400).json({
        error: 'Укажи корректную цену в рублях'
      });
    }

    try {
      const result = await pool.query(`
        UPDATE buyout_requests
        SET
          offer_rub=$1,
          status='quoted',
          updated_at=NOW()
        WHERE id=$2
          AND status IN ('pending','quoted')
        RETURNING id,status,offer_rub
      `, [
        price,
        req.params.id
      ]);

      if (!result.rowCount) {
        return res.status(409).json({
          error: 'Заявка недоступна для оценки'
        });
      }

      res.json(result.rows[0]);
    } catch {
      res.status(500).json({
        error: 'Не удалось назначить цену'
      });
    }
  }
);

app.post(
  '/api/sell/requests/:id/decision',
  requireTelegram,
  async (req, res) => {
    if (
      !/^\d+$/.test(req.params.id) ||
      !['accept', 'decline'].includes(
        req.body?.decision
      )
    ) {
      return res.status(400).json({
        error: 'Неверное решение'
      });
    }

    try {
      const status =
        req.body.decision === 'accept'
          ? 'accepted'
          : 'declined';

      const result = await pool.query(`
        UPDATE buyout_requests
        SET
          status=$1,
          updated_at=NOW()
        WHERE id=$2
          AND telegram_id=$3
          AND status='quoted'
        RETURNING id,status
      `, [
        status,
        req.params.id,
        req.telegramUser.id
      ]);

      if (!result.rowCount) {
        return res.status(409).json({
          error: 'Предложение уже обработано'
        });
      }

      res.json(result.rows[0]);
    } catch {
      res.status(500).json({
        error: 'Не удалось сохранить решение'
      });
    }
  }
);

app.use(express.static(__dirname));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

async function start() {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL не настроен');
  }

  if (!process.env.BOT_TOKEN) {
    throw new Error('BOT_TOKEN не настроен');
  }

  if (!process.env.ADMIN_TELEGRAM_ID) {
    throw new Error('ADMIN_TELEGRAM_ID не настроен');
  }

  await initDatabase();

  app.listen(PORT, '0.0.0.0', () => {
    console.log(
      `REZZKIY MARKET started on port ${PORT}`
    );
  });
}

start().catch(err => {
  console.error('Startup error:', err.message);
  process.exit(1);
});
