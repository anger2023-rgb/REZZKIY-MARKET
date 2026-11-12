
import express from 'express';
import pg from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const app=express();
const {Pool}=pg;
const PORT=Number(process.env.PORT||8080);
const DIR=path.dirname(fileURLToPath(import.meta.url));

const SITE_URL='https://rezzkiy-market-production-dbf4.up.railway.app';
const OPENID='https://steamcommunity.com/openid/login';
const NS='http://specs.openid.net/auth/2.0';
const RULES='2026-11-10-auto-buyout-v2';

app.disable('x-powered-by');
app.use(express.json({limit:'5mb',verify:(req,_res,buf)=>{req.rawBody=Buffer.from(buf)}}));

const pool=new Pool({
  connectionString:process.env.DATABASE_URL,
  ssl:/railway\.internal|localhost|127\.0\.0\.1/.test(
    process.env.DATABASE_URL||''
  )?false:{rejectUnauthorized:false}
});

const categories={
  rifles:['AK-47','M4A4','M4A1-S','AWP','AUG','FAMAS','Galil AR','SG 553','SSG 08','SCAR-20','G3SG1'],
  pistols:['Glock-18','USP-S','P2000','Desert Eagle','P250','Five-SeveN','Tec-9','CZ75-Auto','Dual Berettas','R8 Revolver'],
  smg:['MP9','MAC-10','MP7','MP5-SD','UMP-45','P90','PP-Bizon'],
  heavy:['Nova','XM1014','MAG-7','Sawed-Off','M249','Negev'],
  knives:['Karambit','Bayonet','M9 Bayonet','Butterfly Knife','Flip Knife','Gut Knife','Huntsman Knife','Falchion Knife','Bowie Knife','Shadow Daggers','Navaja Knife','Stiletto Knife','Ursus Knife','Talon Knife','Classic Knife','Paracord Knife','Survival Knife','Nomad Knife','Skeleton Knife','Kukri Knife'],
  gloves:['Sport Gloves','Driver Gloves','Hand Wraps','Moto Gloves','Specialist Gloves','Hydra Gloves','Bloodhound Gloves','Broken Fang Gloves']
};

const conditions=[
  'Factory New',
  'Minimal Wear',
  'Field-Tested',
  'Well-Worn',
  'Battle-Scarred',
  'Not Painted'
];

const categoryOf=w=>Object.keys(categories).find(
  c=>categories[c].includes(w)
);

function auth(raw){
  try{
    if(!process.env.BOT_TOKEN||!raw)return null;
    const p=new URLSearchParams(raw);
    const hash=p.get('hash');

    if(!/^[0-9a-f]{64}$/i.test(hash||''))return null;
    p.delete('hash');

    const t=Number(p.get('auth_date'));
    const now=Math.floor(Date.now()/1000);

    if(!Number.isSafeInteger(t)||t>now+60||now-t>3600){
      return null;
    }

    const s=[...p]
      .sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0)
      .map(([k,v])=>`${k}=${v}`)
      .join('\n');

    const secret=crypto
      .createHmac('sha256','WebAppData')
      .update(process.env.BOT_TOKEN)
      .digest();

    const expected=crypto
      .createHmac('sha256',secret)
      .update(s)
      .digest();

    const received=Buffer.from(hash,'hex');

    if(!crypto.timingSafeEqual(expected,received)){
      return null;
    }

    const u=JSON.parse(p.get('user')||'null');
    return Number.isSafeInteger(u?.id)?u:null;
  }catch{
    return null;
  }
}

async function user(req,res,next){
  const u=auth(req.get('X-Telegram-Init-Data'));

  if(!u){
    return res.status(401).json({
      error:'Открой приложение через Telegram'
    });
  }

  req.telegramUser=u;
  try{
    await registerMarketUser(u);
  }catch(e){
    console.error('Register user:',e.message);
  }
  next();
}

function admin(req,res,next){
  const u=auth(req.get('X-Telegram-Init-Data'));

  if(!u){
    return res.status(401).json({
      error:'Требуется Telegram'
    });
  }

  if(
    !Number.isSafeInteger(Number(process.env.ADMIN_TELEGRAM_ID))||
    u.id!==Number(process.env.ADMIN_TELEGRAM_ID)
  ){
    return res.status(403).json({
      error:'Нет прав администратора'
    });
  }

  req.admin=u;
  next();
}

const bad=(res,code,error)=>res.status(code).json({error});
const validId=x=>/^\d+$/.test(String(x));

const key=()=>{
  const raw=process.env.PAYMENT_DATA_KEY||'';

  if(!/^[0-9a-fA-F]{64}$/.test(raw)){
    throw Error(
      'PAYMENT_DATA_KEY должен содержать 64 шестнадцатеричных символа'
    );
  }

  return Buffer.from(raw,'hex');
};

function encrypt(value){
  const iv=crypto.randomBytes(12);
  const cipher=crypto.createCipheriv(
    'aes-256-gcm',key(),iv
  );

  const payload=Buffer.concat([
    cipher.update(JSON.stringify(value),'utf8'),
    cipher.final()
  ]);

  return Buffer.concat([
    iv,cipher.getAuthTag(),payload
  ]).toString('base64');
}

function decrypt(raw){
  const buf=Buffer.from(raw,'base64');

  const d=crypto.createDecipheriv(
    'aes-256-gcm',key(),buf.subarray(0,12)
  );

  d.setAuthTag(buf.subarray(12,28));

  return JSON.parse(
    Buffer.concat([
      d.update(buf.subarray(28)),
      d.final()
    ]).toString('utf8')
  );
}

function paymentInput(body){
  const method=body?.method;

  if(method==='RUB'){
    const card=String(body.card||'').replace(/[\s-]/g,'');
    const phone=String(body.phone||'').replace(/[\s()\-]/g,'');
    const fullName=String(body.fullName||'')
      .trim().replace(/\s+/g,' ');
    const bank=String(body.bank||'').trim();

    if(
      !/^\d{16,19}$/.test(card)||
      !/^\+?\d{10,15}$/.test(phone)||
      !/^\S+\s+\S+/.test(fullName)||
      fullName.length>120||
      bank.length<2||
      bank.length>100
    ){
      throw Error(
        'Проверь номер карты, телефон, имя и фамилию и банк'
      );
    }

    return {method,card,phone,fullName,bank};
  }

  if(method==='BALANCE'){
    return {method:'BALANCE'};
  }

  if(method==='USDT'){
    const network=body.network;
    const address=String(body.address||'').trim();

    if(!['TRC20','ERC20','BEP20'].includes(network)){
      throw Error('Выбери сеть USDT');
    }

    if(
      network==='TRC20'&&
      !/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address)
    ){
      throw Error('Неверный адрес TRC20');
    }

    if(
      network!=='TRC20'&&
      !/^0x[a-fA-F0-9]{40}$/.test(address)
    ){
      throw Error('Неверный адрес EVM');
    }

    return {method,network,address};
  }

  throw Error('Выбери валюту выплаты');
}

function publicPayment(row){
  if(!row?.payment_details)return null;

  const p=decrypt(row.payment_details);

  return p.method==='BALANCE'
    ?{method:'BALANCE'}
    :p.method==='RUB'
      ?{
        method:'RUB',
        cardMasked:'•••• '+p.card.slice(-4),
        phoneMasked:'•••• '+p.phone.slice(-4),
        fullName:p.fullName,
        bank:p.bank
      }
      :{
        method:'USDT',
        network:p.network,
        address:p.address
      };
}

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products(
      id BIGSERIAL PRIMARY KEY,
      weapon TEXT NOT NULL,
      skin TEXT NOT NULL,
      category TEXT NOT NULL,
      condition TEXT NOT NULL,
      price INTEGER NOT NULL CHECK(price>0),
      quantity INTEGER NOT NULL DEFAULT 1 CHECK(quantity>=0),
      image_url TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Stage 1: source metadata. Existing listings remain OWN.
  await pool.query(`
    ALTER TABLE products
      ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'OWN',
      ADD COLUMN IF NOT EXISTS supplier_code TEXT,
      ADD COLUMN IF NOT EXISTS supplier_listing_id TEXT,
      ADD COLUMN IF NOT EXISTS steam_asset_id TEXT,
      ADD COLUMN IF NOT EXISTS delivery_ready BOOLEAN NOT NULL DEFAULT FALSE
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS products_supplier_listing_unique
    ON products(supplier_code,supplier_listing_id)
    WHERE supplier_code IS NOT NULL AND supplier_listing_id IS NOT NULL
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS products_source_type_id_idx ON products(source_type,id DESC)`);

  // Supplier markup: base_cost_rub is immutable wholesale baseline, never the marked-up price.
  await pool.query(`ALTER TABLE products
    ADD COLUMN IF NOT EXISTS base_cost_rub INTEGER,
    ADD COLUMN IF NOT EXISTS markup_override NUMERIC(6,2)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS supplier_pricing_settings(
    id INTEGER PRIMARY KEY CHECK(id=1), default_markup NUMERIC(6,2) NOT NULL DEFAULT 5
  )`);
  await pool.query(`INSERT INTO supplier_pricing_settings(id,default_markup) VALUES(1,5) ON CONFLICT(id) DO NOTHING`);
  await pool.query(`ALTER TABLE supplier_pricing_settings ADD COLUMN IF NOT EXISTS usd_rub NUMERIC(12,4)`);
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS supplier_cost_usd_cents BIGINT`);
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS supplier_published BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS supplier_market_hash_name TEXT`);
  // Existing manual supplier drafts: current price is taken as baseline (not a verified BuyCS2 cost).
  await pool.query(`UPDATE products SET base_cost_rub=price WHERE source_type='SUPPLIER' AND base_cost_rub IS NULL`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS product_images(
      id UUID PRIMARY KEY,
      mime TEXT NOT NULL,
      data BYTEA NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS steam_accounts(
      telegram_id BIGINT PRIMARY KEY,
      steam_id TEXT NOT NULL UNIQUE,
      linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS steam_auth_states(
      state_hash TEXT PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sell_consents(
      telegram_id BIGINT PRIMARY KEY,
      rules_version TEXT NOT NULL,
      agreed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS buyout_requests(
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

  for(const sql of [
    'trade_opened_at TIMESTAMPTZ',
    'received_at TIMESTAMPTZ',
    'payout_due_at TIMESTAMPTZ',
    'received_by BIGINT',
    'payment_details TEXT',
    'payment_saved_at TIMESTAMPTZ',
    'seller_username TEXT',
    'seller_name TEXT',
    'paid_at TIMESTAMPTZ',
    'paid_by BIGINT'
  ]){
    await pool.query(
      'ALTER TABLE buyout_requests ADD COLUMN IF NOT EXISTS '+sql
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS balance_ledger(
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      request_id BIGINT NOT NULL UNIQUE
        REFERENCES buyout_requests(id),
      amount_rub INTEGER NOT NULL CHECK(amount_rub>0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS usdt_settings(
      id INTEGER PRIMARY KEY DEFAULT 1 CHECK(id=1),
      rate_kopecks INTEGER NOT NULL DEFAULT 8500
        CHECK(rate_kopecks>0),
      trc20_address TEXT NOT NULL DEFAULT '',
      bep20_address TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    INSERT INTO usdt_settings(id)
    VALUES(1)
    ON CONFLICT(id) DO NOTHING
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS usdt_orders(
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      items JSONB NOT NULL,
      total_rub INTEGER NOT NULL CHECK(total_rub>0),
      rate_kopecks INTEGER NOT NULL CHECK(rate_kopecks>0),
      amount_cents BIGINT NOT NULL CHECK(amount_cents>0),
      network TEXT NOT NULL
        CHECK(network IN ('TRC20','BEP20')),
      wallet_address TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'awaiting',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reported_at TIMESTAMPTZ,
      reviewed_at TIMESTAMPTZ,
      reviewed_by BIGINT
    )
  `);

  await pool.query(`
    ALTER TABLE usdt_orders
      ADD COLUMN IF NOT EXISTS order_kind TEXT NOT NULL DEFAULT 'purchase' CHECK(order_kind IN ('purchase','topup')),
      ADD COLUMN IF NOT EXISTS tron_amount_units BIGINT,
      ADD COLUMN IF NOT EXISTS tron_expires_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS tron_txid TEXT,
      ADD COLUMN IF NOT EXISTS tron_block_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS bsc_amount_units BIGINT,
      ADD COLUMN IF NOT EXISTS bsc_expires_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS bsc_txid TEXT,
      ADD COLUMN IF NOT EXISTS bsc_block_at TIMESTAMPTZ
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_promo_codes(
      id BIGSERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      topup_bps INTEGER NOT NULL CHECK(topup_bps BETWEEN 0 AND 10000),
      discount_bps INTEGER NOT NULL CHECK(discount_bps BETWEEN 0 AND 9999),
      CHECK(topup_bps>0 OR discount_bps>0)
    );
    ALTER TABLE usdt_orders
      ADD COLUMN IF NOT EXISTS promo_code_id BIGINT REFERENCES market_promo_codes(id),
      ADD COLUMN IF NOT EXISTS promo_rub INTEGER NOT NULL DEFAULT 0 CHECK(promo_rub>=0);
    CREATE INDEX IF NOT EXISTS usdt_orders_paid_promo_idx
      ON usdt_orders(promo_code_id,telegram_id) WHERE status='paid' AND promo_code_id IS NOT NULL
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS usdt_orders_topups_user_idx
    ON usdt_orders(telegram_id,id DESC) WHERE order_kind='topup'
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS usdt_orders_tron_amount_unique
    ON usdt_orders(wallet_address,tron_amount_units) WHERE tron_amount_units IS NOT NULL
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS usdt_orders_tron_txid_unique
    ON usdt_orders(tron_txid) WHERE tron_txid IS NOT NULL
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS usdt_orders_bsc_amount_unique
    ON usdt_orders(LOWER(wallet_address),bsc_amount_units) WHERE bsc_amount_units IS NOT NULL
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS usdt_orders_bsc_txid_unique
    ON usdt_orders(bsc_txid) WHERE bsc_txid IS NOT NULL
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bsc_payment_cursors(
      wallet_address TEXT PRIMARY KEY,
      next_block BIGINT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_carts(
      telegram_id BIGINT PRIMARY KEY,
      items JSONB NOT NULL DEFAULT '[]'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS skin_withdrawals(
      id BIGSERIAL PRIMARY KEY,
      order_id BIGINT NOT NULL UNIQUE REFERENCES usdt_orders(id),
      telegram_id BIGINT NOT NULL,
      telegram_username TEXT,
      telegram_name TEXT,
      trade_url TEXT NOT NULL,
      items JSONB NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sent')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      sent_at TIMESTAMPTZ,
      sent_by BIGINT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS supplier_fulfillments(
      id BIGSERIAL PRIMARY KEY,
      order_id BIGINT NOT NULL REFERENCES usdt_orders(id) ON DELETE CASCADE,
      product_id BIGINT NOT NULL,
      provider TEXT NOT NULL DEFAULT 'BUYCS2',
      external_id TEXT NOT NULL UNIQUE,
      market_hash_name TEXT NOT NULL,
      max_price_usd_cents BIGINT NOT NULL CHECK(max_price_usd_cents>0),
      trade_url TEXT NOT NULL,
      trade_id TEXT UNIQUE,
      offer_id TEXT,
      status TEXT NOT NULL DEFAULT 'QUEUED',
      fail_reason TEXT,
      error_code INTEGER,
      actual_price_usd_cents BIGINT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      completed_at TIMESTAMPTZ,
      UNIQUE(order_id,product_id)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS supplier_fulfillments_order_idx ON supplier_fulfillments(order_id)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS balance_purchases(
      order_id BIGINT PRIMARY KEY REFERENCES usdt_orders(id),
      telegram_id BIGINT NOT NULL,
      amount_rub INTEGER NOT NULL CHECK(amount_rub>0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(
    `ALTER TABLE usdt_orders
     DROP CONSTRAINT IF EXISTS usdt_orders_network_check`
  );

  await pool.query(`
    ALTER TABLE usdt_orders
    ADD CONSTRAINT usdt_orders_network_check
    CHECK(network IN ('TRC20','BEP20','BALANCE'))
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_users(
      telegram_id BIGINT PRIMARY KEY,
      username TEXT,
      first_name TEXT,
      last_name TEXT,
      first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_balance_credits(
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      amount_rub INTEGER NOT NULL CHECK(amount_rub>0),
      admin_id BIGINT NOT NULL,
      note TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(
    `ALTER TABLE buyout_requests
     ADD COLUMN IF NOT EXISTS rejection_reason TEXT`
  );

  // Six manually curated products on the home page.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS featured_products(
      product_id BIGINT PRIMARY KEY REFERENCES products(id) ON DELETE CASCADE,
      position SMALLINT NOT NULL UNIQUE CHECK(position BETWEEN 1 AND 6)
    )
  `);
  await pool.query(`CREATE TABLE IF NOT EXISTS featured_settings(
    id INTEGER PRIMARY KEY CHECK(id=1), initialized BOOLEAN NOT NULL DEFAULT TRUE
  )`);
  // On the first deployment preserve the current home selection (first four).
  await pool.query(`
    INSERT INTO featured_products(product_id,position)
    SELECT id, ROW_NUMBER() OVER(ORDER BY created_at DESC,id DESC)::smallint
    FROM (SELECT id,created_at FROM products WHERE source_type='OWN' AND quantity>0
          ORDER BY created_at DESC,id DESC LIMIT 4) first_four
    WHERE NOT EXISTS (SELECT 1 FROM featured_settings)
    ON CONFLICT DO NOTHING
  `);
  await pool.query(`INSERT INTO featured_settings(id) VALUES(1) ON CONFLICT DO NOTHING`);
  await repairSupplierCategories();
  console.log('Database ready');
}

async function registerMarketUser(u){
  await pool.query(
    `INSERT INTO market_users(
      telegram_id,username,first_name,last_name
    )
    VALUES($1,$2,$3,$4)
    ON CONFLICT(telegram_id) DO UPDATE SET
      username=EXCLUDED.username,
      first_name=EXCLUDED.first_name,
      last_name=EXCLUDED.last_name,
      last_seen=NOW()`,
    [
      u.id,
      u.username||null,
      u.first_name||null,
      u.last_name||null
    ]
  );
}

app.get('/api/health',(_q,r)=>{
  r.json({status:'ok'});
});

app.get('/api/categories',(_q,r)=>{
  r.json(categories);
});

app.get('/api/products',async(_q,r)=>{
  try{
    const result=await pool.query(
      `SELECT id,weapon,skin,category,condition,price,quantity,image_url,
              source_type,delivery_ready,created_at
       FROM products
       WHERE (source_type='OWN' OR (source_type='SUPPLIER' AND supplier_published=TRUE))
         AND quantity>0
       ORDER BY created_at DESC,id DESC`
    );

    r.json(result.rows);
  }catch(e){
    bad(r,500,'Ошибка каталога');
  }
});

// Public selection: only active own-stock listings are visible.
app.get('/api/featured',async(_q,r)=>{
  try{
    const x=await pool.query(`
      SELECT f.product_id AS id, f.position
      FROM featured_products f JOIN products p ON p.id=f.product_id
      WHERE p.source_type='OWN' AND p.quantity>0
      ORDER BY f.position
    `);
    r.set('Cache-Control','no-store');
    r.json(x.rows);
  }catch(e){console.error('Featured read:',e);bad(r,500,'Ошибка избранных товаров')}
});

// Admin can pin, unpin and reorder by submitting the complete ordered list.
app.put('/api/admin/featured',admin,async(q,r)=>{
  const ids=q.body?.ids;
  if(!Array.isArray(ids)||ids.length>6||
     ids.some(id=>!validId(id))||new Set(ids.map(String)).size!==ids.length){
    return bad(r,400,'Выбери не более 6 разных товаров');
  }
  let client;
  try{
    client=await pool.connect();
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(927301)');
    if(ids.length){
      const valid=await client.query(`SELECT id FROM products
        WHERE id=ANY($1::bigint[]) AND source_type='OWN' AND quantity>0`,[ids.map(String)]);
      if(valid.rowCount!==ids.length){
        await client.query('ROLLBACK');
        return bad(r,409,'Один из товаров отсутствует или закончился');
      }
    }
    await client.query('DELETE FROM featured_products');
    for(let i=0;i<ids.length;i++){
      await client.query('INSERT INTO featured_products(product_id,position) VALUES($1,$2)',[String(ids[i]),i+1]);
    }
    await client.query('COMMIT');
    r.set('Cache-Control','no-store');
    r.json({ids:ids.map(String)});
  }catch(e){
    if(client)await client.query('ROLLBACK').catch(()=>{});
    console.error('Featured save:',e);bad(r,500,'Не удалось сохранить закрепления');
  }finally{if(client)client.release()}
});

app.get('/api/admin/supplier-products',admin,async(q,r)=>{
  try{
    const page=Math.max(1,Math.min(100000,Number.parseInt(String(q.query.page||'1'),10)||1));
    const limit=Math.max(10,Math.min(50,Number.parseInt(String(q.query.limit||'30'),10)||30));
    const search=String(q.query.q||'').trim().slice(0,120);
    const offset=(page-1)*limit;
    const params=[];
    let where="source_type='SUPPLIER'";
    if(search){params.push('%'+search+'%');where+=` AND (weapon ILIKE $${params.length} OR skin ILIKE $${params.length} OR (weapon || ' | ' || skin) ILIKE $${params.length})`;}
    const count=await pool.query(`SELECT COUNT(*)::int AS total FROM products WHERE ${where}`,params);
    params.push(limit,offset);
    const x=await pool.query(`SELECT id,weapon,skin,condition,price,quantity,image_url,
      source_type,supplier_code,supplier_listing_id,steam_asset_id,delivery_ready,created_at,base_cost_rub,markup_override,supplier_published,supplier_market_hash_name
      FROM products WHERE ${where} ORDER BY id DESC LIMIT $${params.length-1} OFFSET $${params.length}`,params);
    const total=Number(count.rows[0]?.total||0);
    r.set('Cache-Control','no-store');
    r.json({items:x.rows,total,page,limit,pages:Math.max(1,Math.ceil(total/limit)),query:search});
  }catch(e){console.error('Supplier drafts:',e);bad(r,500,'Ошибка черновиков поставщика')}
});

// Admin-only supplier pricing. Changes affect supplier drafts only, never OWN stock.
const validMarkup=v=>typeof v==='number'&&Number.isFinite(v)&&v>=0&&v<=500&&Math.round(v*100)===v*100;
app.get('/api/admin/supplier-markup',admin,async(_q,r)=>{
  try{const x=await pool.query('SELECT default_markup FROM supplier_pricing_settings WHERE id=1');
    r.set('Cache-Control','no-store');r.json({defaultMarkup:Number(x.rows[0].default_markup)})
  }catch(e){console.error('Read supplier markup:',e);bad(r,500,'Не удалось загрузить наценку')}
});
app.put('/api/admin/supplier-markup',admin,async(q,r)=>{
  const value=q.body?.markup;
  if(!validMarkup(value))return bad(r,400,'Наценка должна быть от 0 до 500% с точностью 0,01%');
  const client=await pool.connect();
  try{await client.query('BEGIN');
    await client.query('UPDATE supplier_pricing_settings SET default_markup=$1 WHERE id=1',[value]);
    await client.query(`UPDATE products SET price=LEAST(2147483647::numeric,GREATEST(1::numeric,CEIL(base_cost_rub*(1+$1::numeric/100))))::integer
      WHERE source_type='SUPPLIER' AND base_cost_rub IS NOT NULL AND markup_override IS NULL`,[value]);
    await client.query('COMMIT');r.json({defaultMarkup:value});
  }catch(e){await client.query('ROLLBACK');console.error('Save supplier markup:',e);bad(r,500,'Не удалось сохранить наценку')}
  finally{client.release()}
});
// Bulk publication is scoped to one exact weapon across all supplier pages.
const supplierGroupScope="source_type='SUPPLIER' AND supplier_code='BUYCS2'";
const supplierGroupAvailable='quantity>0 AND supplier_cost_usd_cents>0 AND supplier_market_hash_name IS NOT NULL';
app.get('/api/admin/supplier-product-groups',admin,async(_q,r)=>{
  try{
    const x=await pool.query(`SELECT weapon,category,
      COUNT(*) FILTER (WHERE ${supplierGroupAvailable})::int AS total,
      COUNT(*) FILTER (WHERE ${supplierGroupAvailable} AND supplier_published)::int AS published,
      COUNT(*) FILTER (WHERE supplier_published)::int AS removable
      FROM products WHERE ${supplierGroupScope}
        AND (supplier_published OR (${supplierGroupAvailable}))
      GROUP BY weapon,category ORDER BY category,weapon`);
    r.set('Cache-Control','no-store');r.json({groups:x.rows});
  }catch(e){console.error('Supplier groups:',e);bad(r,500,'Не удалось загрузить группы скинов')}
});
app.patch('/api/admin/supplier-product-groups/publish',admin,async(q,r)=>{
  const weapon=q.body?.weapon;
  const count=q.body?.count;
  if(typeof weapon!=='string'||!weapon.trim()||weapon.length>120)return bad(r,400,'Выбери вид оружия');
  if(count!==undefined&&(!Number.isSafeInteger(count)||count<1||count>2147483647)){
    return bad(r,400,'Укажи целое количество от 1');
  }
  try{
    if(count!==undefined){
      const x=await pool.query(`WITH selected AS (
        SELECT id FROM products
        WHERE ${supplierGroupScope} AND weapon=$1
          AND ${supplierGroupAvailable} AND supplier_published IS DISTINCT FROM TRUE
        ORDER BY id DESC LIMIT $2::integer FOR UPDATE
      ), selection AS (
        SELECT COUNT(*)::int AS total FROM selected
      ), published AS (
        UPDATE products AS p SET supplier_published=TRUE
        FROM selected, selection
        WHERE p.id=selected.id AND selection.total=$2::integer
        RETURNING p.id
      )
      SELECT selection.total AS available, (SELECT COUNT(*)::int FROM published) AS published
      FROM selection`,[weapon,count]);
      const {available,published}=x.rows[0];
      if(available<count)return bad(r,409,'Можно выставить только '+available+' позиций этого оружия. Укажи меньшее количество.');
      return r.json({weapon,published});
    }
    const x=await pool.query(`UPDATE products SET supplier_published=TRUE
      WHERE ${supplierGroupScope} AND weapon=$1
        AND ${supplierGroupAvailable}
        AND supplier_published IS DISTINCT FROM TRUE`,[weapon]);
    r.json({weapon,published:x.rowCount});
  }catch(e){console.error('Bulk supplier publish:',e);bad(r,500,'Не удалось выставить группу скинов')}
});
app.patch('/api/admin/supplier-product-groups/unpublish',admin,async(q,r)=>{
  const weapon=q.body?.weapon;
  if(typeof weapon!=='string'||!weapon.trim()||weapon.length>120)return bad(r,400,'Выбери вид оружия');
  try{
    const x=await pool.query(`UPDATE products SET supplier_published=FALSE
      WHERE ${supplierGroupScope} AND weapon=$1 AND supplier_published`,[weapon]);
    r.json({weapon,unpublished:x.rowCount});
  }catch(e){console.error('Bulk supplier unpublish:',e);bad(r,500,'Не удалось снять группу с каталога')}
});

app.patch('/api/admin/supplier-products/:id/publish',admin,async(q,r)=>{
  const published=q.body?.published;
  if(!validId(q.params.id)||typeof published!=='boolean')return bad(r,400,'Неверные данные публикации');
  try{
    const x=await pool.query(`UPDATE products SET supplier_published=$2
      WHERE id=$1 AND source_type='SUPPLIER' AND supplier_code='BUYCS2'
        AND ($2=FALSE OR (quantity>0 AND supplier_cost_usd_cents IS NOT NULL AND supplier_market_hash_name IS NOT NULL))
      RETURNING id,supplier_published,quantity`,[q.params.id,published]);
    if(!x.rowCount)return bad(r,409,'Товар поставщика недоступен для публикации');
    r.json(x.rows[0]);
  }catch(e){console.error('Supplier publish:',e);bad(r,500,'Не удалось изменить публикацию')}
});

app.patch('/api/admin/supplier-products/:id/markup',admin,async(q,r)=>{
  const value=q.body?.markup;
  if(!validId(q.params.id)||!(value===null||validMarkup(value)))return bad(r,400,'Неверная наценка');
  try{const x=await pool.query(`UPDATE products SET markup_override=$2,
    price=LEAST(2147483647::numeric,GREATEST(1::numeric,CEIL(base_cost_rub*(1+COALESCE($2::numeric,(SELECT default_markup FROM supplier_pricing_settings WHERE id=1))/100))))::integer
    WHERE id=$1 AND source_type='SUPPLIER' AND base_cost_rub IS NOT NULL
    RETURNING id,price,base_cost_rub,markup_override`,[q.params.id,value]);
    if(!x.rowCount)return bad(r,404,'Черновик поставщика не найден');r.json(x.rows[0]);
  }catch(e){console.error('Supplier markup:',e);bad(r,500,'Не удалось изменить наценку')}
});

app.get('/api/admin/suppliers',admin,(_q,r)=>{
  r.set('Cache-Control','no-store');
  r.json({connected:Boolean(process.env.BUYCS2_API_KEY&&process.env.BUYCS2_MERCHANT_ID),autoImport:false,checkoutEnabled:true,
    message:'BuyCS2 подключён. Опубликованные товары могут выкупаться автоматически после оплаты и ввода Steam Trade URL.'});
});

// Import remains admin-only and draft-only. No supplier purchase endpoints are used.
const buycs2Name = (name) => {
  const full=String(name||'').trim();
  const match=full.match(/\s\((Factory New|Minimal Wear|Field-Tested|Well-Worn|Battle-Scarred|Not Painted)\)$/);
  const condition=match?.[1]||'Not Painted';
  const bare=(match?full.slice(0,-match[0].length):full).replace(/^★\s*/, '').replace(/^(?:StatTrak™|Souvenir)\s+/, '').trim();
  const pipe=bare.indexOf(' | ');
  return {weapon:pipe>=0?bare.slice(0,pipe):'Другое',skin:pipe>=0?bare.slice(pipe+3):bare,condition};
};
// Repair previously imported listings without changing publication or pricing.
async function repairSupplierCategories(){
  const result=await pool.query(`SELECT id,supplier_market_hash_name FROM products
    WHERE supplier_code='BUYCS2' AND supplier_market_hash_name IS NOT NULL`);
  for(let i=0;i<result.rows.length;i+=250){
    const batch=result.rows.slice(i,i+250).map(row=>{
      const name=buycs2Name(row.supplier_market_hash_name);
      return {id:String(row.id),weapon:name.weapon.slice(0,120),category:categoryOf(name.weapon)||'OTHER'};
    });
    await pool.query(`UPDATE products p SET weapon=v.weapon,category=v.category
      FROM jsonb_to_recordset($1::jsonb) AS v(id bigint,weapon text,category text)
      WHERE p.id=v.id AND (p.weapon IS DISTINCT FROM v.weapon OR p.category IS DISTINCT FROM v.category)`,[JSON.stringify(batch)]);
  }
}
app.get('/api/admin/buycs2/import-settings',admin,async(_q,r)=>{
  try{const x=await pool.query('SELECT usd_rub FROM supplier_pricing_settings WHERE id=1');
    r.set('Cache-Control','no-store');r.json({usdRub:x.rows[0]?.usd_rub===null?null:Number(x.rows[0].usd_rub)});
  }catch(e){console.error('Import settings:',e);bad(r,500,'Ошибка настроек курса')}
});
app.put('/api/admin/buycs2/import-settings',admin,async(q,r)=>{
  const rate=q.body?.usdRub;
  if(typeof rate!=='number'||!Number.isFinite(rate)||rate<1||rate>1000||Math.round(rate*10000)!==rate*10000)
    return bad(r,400,'Укажи курс USD/RUB от 1 до 1000, до 4 знаков после запятой');
  try{await pool.query('UPDATE supplier_pricing_settings SET usd_rub=$1 WHERE id=1',[rate]);r.json({usdRub:rate})}
  catch(e){console.error('Save rate:',e);bad(r,500,'Не удалось сохранить курс')}
});
const buycs2ImportState={
  running:false,status:'idle',message:'Импорт ещё не запускался',imported:0,total:0,usdRub:null,
  startedAt:null,finishedAt:null,error:null
};
const setBuycs2ImportState=patch=>Object.assign(buycs2ImportState,patch);
async function runBuycs2Import(){
  const merchantId=process.env.BUYCS2_MERCHANT_ID?.trim(),apiKey=process.env.BUYCS2_API_KEY?.trim();
  try{
    if(!merchantId||!apiKey)throw Error('Не настроен BuyCS2 API');
    const settings=await pool.query('SELECT usd_rub FROM supplier_pricing_settings WHERE id=1');
    const rate=Number(settings.rows[0]?.usd_rub);
    if(!Number.isFinite(rate)||rate<1)throw Error('Сначала сохрани курс USD/RUB');
    setBuycs2ImportState({status:'fetching',message:'Получаем каталог BuyCS2...',usdRub:rate});
    const response=await fetch('https://api.buycs2.com/Items/GetAllItemsOnSale',{
      headers:{'x-merchant-id':merchantId,'x-api-key':apiKey,'Accept':'application/json','Accept-Encoding':'gzip'},
      signal:AbortSignal.timeout(90000)
    });
    if(!response.ok)throw Error('BuyCS2 не отдал каталог: HTTP '+response.status);
    const payload=await response.json();
    if(!payload||!Array.isArray(payload.items))throw Error('Некорректный формат каталога BuyCS2');
    if(Number.isSafeInteger(payload.totalItems)&&payload.totalItems!==payload.items.length)
      throw Error('BuyCS2 вернул неполный каталог');
    const rows=[];const seen=new Set();
    for(const item of payload.items){
      if(!Number.isSafeInteger(item.itemId)||item.itemId<=0||!Number.isSafeInteger(item.price)||item.price<=0||
         typeof item.assetId!=='string'||!item.assetId||typeof item.market_hash_name!=='string'||!item.market_hash_name.trim())
        continue;
      const listingId=String(item.itemId);
      if(seen.has(listingId))continue;
      seen.add(listingId);
      const cost=Math.ceil(item.price*rate/100);
      if(!Number.isSafeInteger(cost)||cost<1||cost>100000000)continue;
      const name=buycs2Name(item.market_hash_name);
      const img=typeof item.img==='string'&&/^https:\/\//i.test(item.img)?item.img.slice(0,2048):'';
      rows.push({listingId,assetId:item.assetId,market_hash_name:item.market_hash_name.trim(),weapon:name.weapon.slice(0,120),category:categoryOf(name.weapon)||'OTHER',skin:name.skin.slice(0,240),condition:name.condition,
        image_url:img,base_cost_rub:cost,usd_cents:item.price});
    }
    if(!rows.length)throw Error('В каталоге BuyCS2 не найдено подходящих товаров');
    setBuycs2ImportState({status:'saving',message:'Записываем '+rows.length+' товаров в черновики...',total:rows.length});
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      await client.query('SELECT id FROM supplier_pricing_settings WHERE id=1 FOR UPDATE');
      let saved=0;
      for(let i=0;i<rows.length;i+=250){
        const batch=JSON.stringify(rows.slice(i,i+250));
        await client.query(`INSERT INTO products
          (weapon,skin,category,condition,price,quantity,image_url,source_type,delivery_ready,supplier_code,supplier_listing_id,steam_asset_id,base_cost_rub,supplier_cost_usd_cents,supplier_market_hash_name)
          SELECT v.weapon,v.skin,v.category,v.condition,
            LEAST(2147483647::numeric,GREATEST(1::numeric,CEIL(v.base_cost_rub*(1+s.default_markup/100))))::integer,
            1,v.image_url,'SUPPLIER',FALSE,'BUYCS2',v."listingId",v."assetId",v.base_cost_rub,v.usd_cents,v.market_hash_name
          FROM jsonb_to_recordset($1::jsonb) AS v("listingId" text,"assetId" text,market_hash_name text,weapon text,category text,skin text,condition text,image_url text,base_cost_rub numeric,usd_cents bigint)
          CROSS JOIN supplier_pricing_settings s
          WHERE s.id=1
          ON CONFLICT (supplier_code,supplier_listing_id) WHERE supplier_code IS NOT NULL AND supplier_listing_id IS NOT NULL
          DO UPDATE SET weapon=EXCLUDED.weapon,skin=EXCLUDED.skin,category=EXCLUDED.category,condition=EXCLUDED.condition,
            image_url=EXCLUDED.image_url,quantity=1,steam_asset_id=EXCLUDED.steam_asset_id,base_cost_rub=EXCLUDED.base_cost_rub,
            supplier_cost_usd_cents=EXCLUDED.supplier_cost_usd_cents,supplier_market_hash_name=EXCLUDED.supplier_market_hash_name,
            price=LEAST(2147483647::numeric,GREATEST(1::numeric,CEIL(EXCLUDED.base_cost_rub*(1+COALESCE(products.markup_override,(SELECT default_markup FROM supplier_pricing_settings WHERE id=1))/100))))::integer,
            delivery_ready=FALSE`,[batch]);
        saved=Math.min(i+250,rows.length);
        setBuycs2ImportState({imported:saved,message:'Записано '+saved+' из '+rows.length+'...'});
      }
      await client.query(`UPDATE products SET quantity=0 WHERE source_type='SUPPLIER' AND supplier_code='BUYCS2'
        AND NOT (supplier_listing_id=ANY($1::text[]))`,[rows.map(x=>x.listingId)]);
      await client.query('COMMIT');
    }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
    setBuycs2ImportState({running:false,status:'done',message:'Черновики BuyCS2 обновлены',imported:rows.length,total:rows.length,
      usdRub:rate,finishedAt:new Date().toISOString(),error:null});
  }catch(e){
    console.error('BuyCS2 import:',e?.message||e);
    setBuycs2ImportState({running:false,status:'error',message:e?.message||'Импорт не выполнен',error:e?.message||'Ошибка импорта',finishedAt:new Date().toISOString()});
  }
}
app.get('/api/admin/buycs2/import-status',admin,(_q,r)=>{
  r.set('Cache-Control','no-store');
  r.json({...buycs2ImportState,purchasesEnabled:true,publiclyVisible:true});
});
app.post('/api/admin/buycs2/import',admin,async(_q,r)=>{
  if(buycs2ImportState.running)return r.status(202).json({...buycs2ImportState,alreadyRunning:true});
  const settings=await pool.query('SELECT usd_rub FROM supplier_pricing_settings WHERE id=1');
  const rate=Number(settings.rows[0]?.usd_rub);
  if(!Number.isFinite(rate)||rate<1)return bad(r,400,'Сначала сохрани курс USD/RUB');
  if(!process.env.BUYCS2_MERCHANT_ID?.trim()||!process.env.BUYCS2_API_KEY?.trim())return bad(r,503,'Не настроен BuyCS2 API');
  setBuycs2ImportState({running:true,status:'starting',message:'Импорт запущен...',imported:0,total:0,usdRub:rate,
    startedAt:new Date().toISOString(),finishedAt:null,error:null});
  setImmediate(()=>{runBuycs2Import().catch(e=>console.error('BuyCS2 background import:',e))});
  r.status(202).set('Cache-Control','no-store').json({...buycs2ImportState,accepted:true});
});

// BuyCS2 read-only connection test. No orders, transfers or catalog mutations.
app.get('/api/admin/buycs2/test',admin,async(_req,res)=>{
  res.set('Cache-Control','no-store');
  const merchantId=process.env.BUYCS2_MERCHANT_ID?.trim();
  const apiKey=process.env.BUYCS2_API_KEY?.trim();
  if(!merchantId||!apiKey){
    return res.status(503).json({connected:false,message:'Не настроены BUYCS2_MERCHANT_ID или BUYCS2_API_KEY в Railway'});
  }
  try{
    const response=await fetch('https://api.buycs2.com/Wallet/GetBalance',{
      method:'GET',
      headers:{'x-merchant-id':merchantId,'x-api-key':apiKey,'Accept':'application/json','Accept-Encoding':'gzip'},
      signal:AbortSignal.timeout(10000)
    });
    if(!response.ok){
      const messages={401:'Ключ или Merchant ID неверны либо аккаунт неактивен',403:'IP Railway не разрешён поставщиком',404:'Поставщик не распознал запрос или авторизацию',429:'Лимит запросов BuyCS2 превышен'};
      return res.status(502).json({connected:false,message:messages[response.status]||`BuyCS2 вернул HTTP ${response.status}`});
    }
    const payload=await response.json();
    if(!payload||typeof payload!=='object'||!Number.isFinite(payload.total_available)){
      return res.status(502).json({connected:false,message:'Неожиданный формат ответа BuyCS2'});
    }
    // Do not return wallet addresses, API credentials or full upstream response.
    return res.json({connected:true,message:'BuyCS2 подключён. Авторизация подтверждена.',
      availableUsd:(payload.total_available/100).toFixed(2),
      currency:'USD',autoImport:false,checkoutEnabled:false});
  }catch(e){
    console.error('BuyCS2 connection test:',e?.name||'Error');
    return res.status(502).json({connected:false,message:'Не удалось связаться с BuyCS2. Проверь доступность API и сеть Railway.'});
  }
});

app.get('/api/admin/me',admin,(q,r)=>{
  r.json({admin:true,id:q.admin.id});
});

app.post('/api/images',admin,async(q,r)=>{
  try{
    const m=String(q.body?.image||'').match(
      /^data:(image\/jpeg|image\/png|image\/webp);base64,([A-Za-z0-9+/]+={0,2})$/
    );

    if(!m){
      return bad(r,400,'Нужен JPG, PNG или WebP');
    }

    const data=Buffer.from(m[2],'base64');

    if(!data.length||data.length>3*1024*1024){
      return bad(r,400,'Максимум 3 МБ');
    }

    const jpeg=
      data[0]===255&&
      data[1]===216&&
      data[2]===255;

    const png=data.subarray(0,8).equals(
      Buffer.from([137,80,78,71,13,10,26,10])
    );

    const webp=
      data.toString('ascii',0,4)==='RIFF'&&
      data.toString('ascii',8,12)==='WEBP';

    if(!(
      (m[1]==='image/jpeg'&&jpeg)||
      (m[1]==='image/png'&&png)||
      (m[1]==='image/webp'&&webp)
    )){
      return bad(r,400,'Неверный формат файла');
    }

    const id=crypto.randomUUID();

    await pool.query(
      'INSERT INTO product_images VALUES($1,$2,$3,NOW())',
      [id,m[1],data]
    );

    r.status(201).json({
      url:'/api/images/'+id
    });
  }catch(e){
    bad(r,500,'Ошибка загрузки фото');
  }
});

app.get('/api/images/:id',async(q,r)=>{
  if(!/^[0-9a-f-]{36}$/i.test(q.params.id)){
    return r.sendStatus(400);
  }

  try{
    const x=await pool.query(
      'SELECT mime,data FROM product_images WHERE id=$1',
      [q.params.id]
    );

    if(!x.rowCount){
      return r.sendStatus(404);
    }

    r.set('Content-Type',x.rows[0].mime);
    r.set('X-Content-Type-Options','nosniff');
    r.set('Cache-Control','public,max-age=86400');
    r.send(x.rows[0].data);
  }catch{
    r.sendStatus(500);
  }
});

app.post('/api/products',admin,async(q,r)=>{
  const {
    weapon,
    skin,
    condition,
    price,
    quantity,
    image_url='',
    source_type='OWN',
    delivery_ready=false,
    supplier_code=null,
    supplier_listing_id=null
  }=q.body||{};

  if(
    !categoryOf(weapon)||
    typeof skin!=='string'||
    !skin.trim()||
    skin.length>150||
    !conditions.includes(condition)||
    !Number.isSafeInteger(price)||
    price<1||
    price>2147483647||
    !Number.isSafeInteger(quantity)||
    quantity<0||
    quantity>2147483647||
    typeof image_url!=='string'||
    image_url.length>2000||
    !['OWN','SUPPLIER'].includes(source_type)||
    typeof delivery_ready!=='boolean'||
    (supplier_code!==null&&(typeof supplier_code!=='string'||supplier_code.length>80))||
    (supplier_listing_id!==null&&(typeof supplier_listing_id!=='string'||supplier_listing_id.length>150))
  ){
    return bad(r,400,'Проверь товар');
  }

  if(
    image_url&&
    !/^\/api\/images\/[0-9a-f-]{36}$/i.test(image_url)
  ){
    try{
      if(new URL(image_url).protocol!=='https:'){
        throw Error();
      }
    }catch{
      return bad(r,400,'Неверная ссылка фото');
    }
  }

  try{
    const x=await pool.query(
      `INSERT INTO products(
        weapon,skin,category,condition,
        price,quantity,image_url,source_type,delivery_ready,supplier_code,supplier_listing_id
      ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING *`,
      [
        weapon,
        skin.trim(),
        categoryOf(weapon),
        condition,
        price,
        quantity,
        image_url,source_type,source_type==='OWN'&&delivery_ready,
        source_type==='SUPPLIER'?(supplier_code||null):null,
        source_type==='SUPPLIER'?(supplier_listing_id||null):null
      ]
    );

    if(source_type==='SUPPLIER'){
      const updated=await pool.query(`UPDATE products SET base_cost_rub=$2,
        price=LEAST(2147483647::numeric,GREATEST(1::numeric,CEIL($2::numeric*(1+(SELECT default_markup FROM supplier_pricing_settings WHERE id=1)/100))))::integer
        WHERE id=$1 RETURNING *`,[x.rows[0].id,price]);
      return r.status(201).json(updated.rows[0]);
    }
    r.status(201).json(x.rows[0]);
  }catch{
    bad(r,500,'Ошибка добавления');
  }
});

// Admin-only readiness toggle for own inventory. Supplier items are not editable here.
app.patch('/api/admin/products/:id/readiness',admin,async(q,r)=>{
  if(!validId(q.params.id)||typeof q.body?.delivery_ready!=='boolean'){
    return bad(r,400,'Неверные данные');
  }
  try{
    const result=await pool.query(
      `UPDATE products SET delivery_ready=$2
       WHERE id=$1 AND source_type='OWN' RETURNING *`,
      [q.params.id,q.body.delivery_ready]
    );
    if(!result.rowCount)return bad(r,404,'Собственный товар не найден');
    r.json(result.rows[0]);
  }catch(e){
    console.error('Product readiness update:',e);
    bad(r,500,'Не удалось изменить готовность');
  }
});

app.patch('/api/admin/products/:id/source',admin,async(q,r)=>{
  const type=q.body?.source_type;
  if(!validId(q.params.id)||!['OWN','SUPPLIER'].includes(type))
    return bad(r,400,'Неверный источник товара');
  try{
    const x=await pool.query(`UPDATE products
      SET source_type=$2,delivery_ready=FALSE,
          supplier_code=NULL,supplier_listing_id=NULL,
          base_cost_rub=CASE WHEN $2='SUPPLIER' THEN price ELSE NULL END,
          markup_override=NULL
      WHERE id=$1 RETURNING id,source_type,delivery_ready`,[q.params.id,type]);
    if(!x.rowCount)return bad(r,404,'Товар не найден');
    r.json(x.rows[0]);
  }catch(e){console.error('Change product source:',e);bad(r,500,'Ошибка смены источника')}
});

app.delete('/api/products/:id',admin,async(q,r)=>{
  if(!validId(q.params.id)){
    return bad(r,400,'Неверный ID');
  }

  try{
    const x=await pool.query(
      'DELETE FROM products WHERE id=$1 RETURNING id',
      [q.params.id]
    );

    if(x.rowCount){
      r.json({success:true});
    }else{
      bad(r,404,'Товар не найден');
    }
  }catch{
    bad(r,500,'Ошибка удаления');
  }
});

const stateHash=s=>crypto
  .createHash('sha256')
  .update(s)
  .digest('hex');

app.post('/api/steam/connect',user,async(q,r)=>{
  try{
    const state=crypto.randomBytes(32).toString('hex');

    await pool.query(
      'DELETE FROM steam_auth_states WHERE expires_at<NOW()'
    );

    await pool.query(
      `INSERT INTO steam_auth_states
       VALUES($1,$2,NOW()+INTERVAL '10 minutes')`,
      [stateHash(state),q.telegramUser.id]
    );

    const u=new URL(OPENID);

    const params={
      'openid.ns':NS,
      'openid.mode':'checkid_setup',
      'openid.return_to':
        SITE_URL+'/auth/steam/callback?state='+state,
      'openid.realm':SITE_URL+'/',
      'openid.identity':NS+'/identifier_select',
      'openid.claimed_id':NS+'/identifier_select'
    };

    for(const [k,v] of Object.entries(params)){
      u.searchParams.set(k,v);
    }

    r.json({url:u.toString()});
  }catch(e){
    bad(r,500,'Не удалось подключить Steam');
  }
});

app.get('/auth/steam/callback',async(q,r)=>{
  const fail=()=>r.redirect(303,'/?steam=error');
  const state=q.query.state;

  if(
    typeof state!=='string'||
    !/^[0-9a-f]{64}$/.test(state)
  ){
    return fail();
  }

  try{
    const pending=await pool.query(
      `DELETE FROM steam_auth_states
       WHERE state_hash=$1 AND expires_at>NOW()
       RETURNING telegram_id`,
      [stateHash(state)]
    );

    if(!pending.rowCount){
      return fail();
    }

    const p=new URLSearchParams();

    for(const [k,v] of Object.entries(q.query)){
      if(k.startsWith('openid.')&&typeof v==='string'){
        p.set(k,v);
      }
    }

    const claimed=p.get('openid.claimed_id')||'';

    const m=
      /^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/
      .exec(claimed);

    const signed=(p.get('openid.signed')||'').split(',');

    if(
      !m||
      p.get('openid.mode')!=='id_res'||
      p.get('openid.ns')!==NS||
      p.get('openid.op_endpoint')!==OPENID||
      p.get('openid.return_to')!==
        SITE_URL+'/auth/steam/callback?state='+state||
      p.get('openid.identity')!==claimed||
      !p.get('openid.sig')||
      ![
        'return_to',
        'claimed_id',
        'identity',
        'response_nonce',
        'assoc_handle',
        'op_endpoint'
      ].every(k=>signed.includes(k))
    ){
      return fail();
    }

    p.set('openid.mode','check_authentication');

    const resp=await fetch(OPENID,{
      method:'POST',
      headers:{
        'Content-Type':'application/x-www-form-urlencoded'
      },
      body:p.toString(),
      signal:AbortSignal.timeout(10000)
    });

    if(
      !resp.ok||
      !/^is_valid:true\s*$/m.test(await resp.text())
    ){
      return fail();
    }

    await pool.query(
      `INSERT INTO steam_accounts(telegram_id,steam_id)
       VALUES($1,$2)
       ON CONFLICT(telegram_id)
       DO UPDATE SET
       steam_id=EXCLUDED.steam_id,
       linked_at=NOW()`,
      [pending.rows[0].telegram_id,m[1]]
    );

    r.redirect(303,'/?steam=success');
  }catch(e){
    console.error(e);
    fail();
  }
});

const avatarCache=new Map();

async function avatarFor(id){
  const cached=avatarCache.get(id);
  if(cached?.expires>Date.now())return cached.value;

  const value={avatar:'',nickname:''};

  try{
    const resp=await fetch(
      'https://steamcommunity.com/profiles/'+id+'/?xml=1',
      {signal:AbortSignal.timeout(7000)}
    );

    if(resp.ok){
      const xml=await resp.text();

      const avatar=xml.match(
        /<avatarFull>(?:<!\[CDATA\[)?(https:\/\/[^<\]]+)/
      );

      if(avatar){
        const url=new URL(
          avatar[1].replace(/&amp;/g,'&')
        );

        if([
          'avatars.steamstatic.com',
          'steamcdn-a.akamaihd.net',
          'avatars.akamai.steamstatic.com'
        ].includes(url.hostname)){
          value.avatar=url.toString();
        }
      }

      const persona=xml.match(
        /<steamID>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/steamID>/
      );

      if(persona){
        value.nickname=persona[1]
          .replace(/\]\]>$/,'')
          .replace(/&amp;/g,'&')
          .replace(/&lt;/g,'<')
          .replace(/&gt;/g,'>')
          .replace(/&quot;/g,'"')
          .replace(/&#39;/g,"'")
          .trim()
          .slice(0,100);
      }
    }
  }catch(e){
    console.warn(
      'Steam public profile unavailable:',
      e.message
    );
  }

  avatarCache.set(id,{
    value,
    expires:Date.now()+300000
  });

  return value;
}

async function steamFor(id){
  const x=await pool.query(
    'SELECT steam_id FROM steam_accounts WHERE telegram_id=$1',
    [id]
  );
  return x.rows[0]?.steam_id||null;
}

app.get('/api/steam/me',user,async(q,r)=>{
  try{
    const steamId=await steamFor(q.telegramUser.id);
    const profile=steamId
      ?await avatarFor(steamId)
      :{avatar:'',nickname:''};

    r.json({
      connected:!!steamId,
      steamId,
      avatar:profile.avatar,
      nickname:profile.nickname
    });
  }catch(e){
    bad(r,500,'Ошибка Steam');
  }
});

// Skinport public prices: server-side cached, never trust client quotations.
const skinportCache={prices:new Map(),expires:0,inflight:null};
const MIN_MARKET_RUB=40;
const BUYOUT_RATE=.75;
function inventoryPriceKey(name){
  return String(name||'').trim().normalize('NFC');
}

function skinportPriceMap(rows){
  const prices=new Map();
  for(const row of rows){
    if(row?.currency!=='RUB'||row.version)continue;
    const name=inventoryPriceKey(row.market_hash_name);
    // When there are no listings, Skinport can still provide a suggested price.
    const value=Number(row.min_price??row.suggested_price);
    if(name&&Number.isFinite(value)&&value>0)prices.set(name,value);
  }
  return prices;
}

async function skinportPrices(){
  if(skinportCache.expires>Date.now()&&skinportCache.prices.size)return skinportCache.prices;
  if(skinportCache.inflight)return skinportCache.inflight;
  skinportCache.inflight=(async()=>{
    const u='https://api.skinport.com/v1/items?app_id=730&currency=RUB&tradable=0';
    const resp=await fetch(u,{headers:{'Accept':'application/json','Accept-Encoding':'br'},signal:AbortSignal.timeout(18000)});
    if(!resp.ok)throw Error('Skinport HTTP '+resp.status);
    const data=await resp.json();
    if(!Array.isArray(data))throw Error('Skinport вернул неожиданный формат');
    const prices=skinportPriceMap(data);
    if(!prices.size)throw Error('Skinport не вернул цены');
    skinportCache.prices=prices;skinportCache.expires=Date.now()+6*60*1000;
    return prices;
  })();
  try{return await skinportCache.inflight}
  catch(e){if(skinportCache.prices.size&&skinportCache.expires+9*60*1000>Date.now())return skinportCache.prices;throw e}
  finally{skinportCache.inflight=null}
}
function quoteInventory(items,prices){
  const stats={tradable:items.length,excluded:0,unpriced:0,belowMinimum:0,eligible:0};
  // Only aggregated item types are logged: no Steam IDs, inventory names, or secrets.
  const excludedByType=Object.create(null);
  const belowMinimumByType=Object.create(null);
  const eligibleByType=Object.create(null);
  const unpricedByType=Object.create(null);
  const summarize=(target,type)=>{
    const key=String(type||'Unknown').slice(0,80);
    target[key]=(target[key]||0)+1;
  };
  const quoted=[];
  for(const item of items){
    // Retain existing exclusion of items requiring individual appraisal.
    if(/(?:Sticker|Charm|Patch|Graffiti|Sealed Graffiti|Case|Container|Key|Music Kit|Agent|Pin|Collectible)/i.test(item.type||'')){
      stats.excluded++;summarize(excludedByType,item.type);continue;
    }
    const market=prices.get(inventoryPriceKey(item.name));
    if(!Number.isFinite(market)||market<=0){stats.unpriced++;summarize(unpricedByType,item.type);continue;}
    if(market<MIN_MARKET_RUB){stats.belowMinimum++;summarize(belowMinimumByType,item.type);continue;}
    const buyout=Math.floor(market*BUYOUT_RATE*100)/100;
    if(buyout<=0){stats.belowMinimum++;summarize(belowMinimumByType,item.type);continue;}
    quoted.push({...item,market_rub:market,buyout_rub:buyout});
    summarize(eligibleByType,item.type);
    stats.eligible++;
  }
  return {items:quoted,stats,categoryDiagnostics:{excludedByType,belowMinimumByType,unpricedByType,eligibleByType}};
}
function inventoryResponse(inventory,prices){
  const {items,totalAssets,nonTradable,missingDescriptions}=inventory;
  const {items:quoted,stats,categoryDiagnostics}=quoteInventory(items,prices);
  // An inventory with unpriced items is not proven to contain no qualifying skins.
  let state='ready';
  if(!quoted.length){
    if(missingDescriptions)state='incomplete_inventory';
    else if(!totalAssets)state='empty_inventory';
    else if(!items.length)state='no_tradable_items';
    else if(stats.unpriced)state='prices_unavailable';
    else state='no_eligible_items';
  }
  console.info('[sell-inventory] evaluated',JSON.stringify(stats), 'state='+state);
  console.info('[sell-inventory] categories',JSON.stringify(categoryDiagnostics));
  return {items:quoted,count:quoted.length,rate:BUYOUT_RATE,minMarketRub:MIN_MARKET_RUB,state,
    stats:{...stats,totalAssets,nonTradable,missingDescriptions}};
}
const inventoryCache=new Map();
const inventoryRequests=new Map();

async function fetchInventory(id){
  let cursor=null;
  const items=[];
  let pages=0;
  let totalAssets=0;
  let nonTradable=0;
  let missingDescriptions=0;

  for(let i=0;i<20;i++){
    const u=new URL(
      'https://steamcommunity.com/inventory/'+id+'/730/2'
    );

    u.searchParams.set('l','english');
    u.searchParams.set('count','1000');

    if(cursor){
      u.searchParams.set('start_assetid',cursor);
    }

    const resp=await fetch(u,{
      signal:AbortSignal.timeout(12000)
    });

    if(!resp.ok){
      console.warn('[sell-inventory] Steam HTTP status='+resp.status+' page='+ (i+1));
      const e=Error(
        resp.status===429
          ?'Steam ограничил запросы'
          :resp.status===403
            ?'Сделай инвентарь публичным'
            :'Ошибка Steam HTTP '+resp.status
      );

      e.status=resp.status===429?429:502;
      throw e;
    }

    let data;
    try{data=await resp.json()}catch(e){throw Error('Steam вернул некорректный JSON')}
    const success=data?.success===1||data?.success==='1'||data?.success===true;
    if(success&&i===0&&Number(data.total_inventory_count)===0&&!data.more_items&&(!data.assets||data.assets.length===0)){
      return {items,totalAssets,nonTradable,missingDescriptions};
    }
    if(!success||!Array.isArray(data.assets)||!Array.isArray(data.descriptions)){
      throw Error('Steam не предоставил корректный инвентарь');
    }
    pages++;
    totalAssets+=data.assets.length;

    const desc=new Map(
      (data.descriptions||[]).map(d=>[
        d.classid+'_'+d.instanceid,
        d
      ])
    );

    for(const a of data.assets||[]){
      const d=desc.get(
        a.classid+'_'+a.instanceid
      );

      if(!d){missingDescriptions++;continue;}
      if(d.tradable!==1&&d.tradable!=='1'&&d.tradable!==true){nonTradable++;continue;}

      items.push({
        assetid:String(a.assetid),
        classid:String(a.classid),
        instanceid:String(a.instanceid),
        name:String(
          d.market_hash_name||d.name||'CS2 item'
        ),
        icon:/^[a-zA-Z0-9_/-]+$/.test(d.icon_url||'')
          ?'https://community.fastly.steamstatic.com/economy/image/'+d.icon_url
          :'',
        type:String(d.type||'').slice(0,120),
        amount:Number(a.amount||1)
      });
    }

    if(!data.more_items){
      console.info('[sell-inventory] Steam loaded',JSON.stringify({pages,totalAssets,tradable:items.length,nonTradable,missingDescriptions}));
      return {items,totalAssets,nonTradable,missingDescriptions};
    }
    if(!data.last_assetid||String(data.last_assetid)===cursor){
      throw Error('Steam вернул некорректную пагинацию инвентаря');
    }
    cursor=String(data.last_assetid);
  }
  // Never present the first 20 pages as the complete inventory.
  throw Error('Инвентарь слишком большой: не все страницы Steam загружены');
}

app.get('/api/sell/rules',user,async(q,r)=>{
  try{
    const x=await pool.query(
      'SELECT rules_version FROM sell_consents WHERE telegram_id=$1',
      [q.telegramUser.id]
    );

    r.json({
      version:RULES,
      accepted:x.rows[0]?.rules_version===RULES
    });
  }catch(e){
    bad(r,500,'Ошибка правил');
  }
});

app.post('/api/sell/agree',user,async(q,r)=>{
  if(
    q.body?.version!==RULES||
    q.body?.accepted!==true
  ){
    return bad(r,400,'Подтверди правила');
  }

  try{
    await pool.query(
      `INSERT INTO sell_consents(
        telegram_id,rules_version
      ) VALUES($1,$2)
      ON CONFLICT(telegram_id)
      DO UPDATE SET
        rules_version=EXCLUDED.rules_version,
        agreed_at=NOW()`,
      [q.telegramUser.id,RULES]
    );

    r.json({accepted:true});
  }catch(e){
    bad(r,500,'Ошибка сохранения');
  }
});

async function consent(q,r,next){
  try{
    const x=await pool.query(
      `SELECT 1 FROM sell_consents
       WHERE telegram_id=$1 AND rules_version=$2`,
      [q.telegramUser.id,RULES]
    );

    if(!x.rowCount){
      return bad(r,403,'Сначала прими правила');
    }

    next();
  }catch(e){
    bad(r,500,'Ошибка согласия');
  }
}

app.get('/api/steam/inventory',user,consent,async(q,r)=>{
  try{
    const id=await steamFor(q.telegramUser.id);

    if(!id){
      return bad(r,400,'Привяжи Steam');
    }

    const cached=inventoryCache.get(
      String(q.telegramUser.id)
    );

    if(
      cached?.steamId===id&&
      cached.expires>Date.now()
    ){
      const prices=cached.items.length?await skinportPrices():new Map();
      return r.json(inventoryResponse(cached,prices));
    }

    if(
      Date.now()-(inventoryRequests.get(id)||0)<15000
    ){
      return bad(r,429,'Подожди 15 секунд');
    }

    inventoryRequests.set(id,Date.now());

    const inventory=await fetchInventory(id);

    inventoryCache.set(
      String(q.telegramUser.id),
      {
        steamId:id,
        ...inventory,
        expires:Date.now()+120000
      }
    );

    const prices=inventory.items.length?await skinportPrices():new Map();
    r.json(inventoryResponse(inventory,prices));
  }catch(e){
    console.warn('[sell-inventory] load failed',JSON.stringify({type:e.name||'Error',status:e.status||502,reason:String(e.message||'Unknown').slice(0,120)}));
    bad(r,e.status||502,e.message||'Ошибка загрузки инвентаря');
  }
});

app.post('/api/sell/requests',user,consent,async(q,r)=>{
  const ids=q.body?.assetids;

  if(
    !Array.isArray(ids)||
    ids.length<1||
    ids.length>30||
    ids.some(id=>
      typeof id!=='string'||
      !/^\d{1,25}$/.test(id)
    )||
    new Set(ids).size!==ids.length
  ){
    return bad(r,400,'Выбери от 1 до 30 предметов');
  }

  try{
    const id=await steamFor(q.telegramUser.id);
    const cache=inventoryCache.get(
      String(q.telegramUser.id)
    );

    if(
      !id||
      cache?.steamId!==id||
      cache.expires<Date.now()
    ){
      return bad(r,400,'Обнови инвентарь');
    }

    const items=ids.map(assetid=>
      cache.items.find(i=>i.assetid===assetid)
    );

    if(items.some(x=>!x)){
      return bad(
        r,400,'Предмет отсутствует в инвентаре'
      );
    }

    // Reprice on the server immediately before accepting an order.
    const prices=await skinportPrices();
    const {items:quoted}=quoteInventory(items,prices);
    if(quoted.length!==items.length)return bad(r,409,'Цена изменилась. Обнови инвентарь');
    const totalKopecks=quoted.reduce((sum,item)=>sum+Math.round(item.buyout_rub*100)*Number(item.amount||1),0);
    const offer=Math.floor(totalKopecks/100);
    if(!Number.isSafeInteger(offer)||offer<1||offer>2147483647)return bad(r,400,'Неверная сумма выкупа');
    const x=await pool.query(
      `INSERT INTO buyout_requests(
        telegram_id,steam_id,items,seller_username,seller_name,offer_rub,status
      ) VALUES($1,$2,$3::jsonb,$4,$5,$6,'quoted')
      RETURNING id,status,offer_rub`,
      [q.telegramUser.id,id,JSON.stringify(quoted),q.telegramUser.username||null,
       [q.telegramUser.first_name,q.telegramUser.last_name].filter(Boolean).join(' ')||null,offer]
    );

    r.status(201).json(x.rows[0]);
  }catch(e){
    bad(r,500,'Ошибка заявки');
  }
});

app.get('/api/sell/requests',user,async(q,r)=>{
  try{
    const x=await pool.query(
      `SELECT
        id,
        items,
        status,
        offer_rub,
        rejection_reason,
        created_at,
        trade_opened_at,
        received_at,
        payout_due_at,
        paid_at,
        payment_details
      FROM buyout_requests
      WHERE telegram_id=$1
      ORDER BY id DESC
      LIMIT 50`,
      [q.telegramUser.id]
    );

    r.json(x.rows.map(
      ({payment_details,...row})=>({
        ...row,
        paymentSaved:!!payment_details,
        payment:publicPayment({payment_details})
      })
    ));
  }catch(e){
    console.error(e);
    bad(r,500,'Ошибка заявок');
  }
});

app.get('/api/admin/buyouts',admin,async(q,r)=>{
  try{
    const x=await pool.query(
      `SELECT
        id,
        telegram_id,
        steam_id,
        seller_username,
        seller_name,
        items,
        status,
        offer_rub,
        rejection_reason,
        created_at,
        trade_opened_at,
        received_at,
        payout_due_at,
        paid_at,
        received_by,
        payment_details
      FROM buyout_requests
      ORDER BY id DESC
      LIMIT 100`
    );

    r.json(x.rows.map(
      ({payment_details,...row})=>({
        ...row,
        paymentSaved:!!payment_details,
        payment:publicPayment({payment_details})
      })
    ));
  }catch(e){
    console.error(e);
    bad(r,500,'Ошибка заявок');
  }
});

app.get('/api/admin/buyouts/:id/payment',admin,async(q,r)=>{
  if(!validId(q.params.id)){
    return bad(r,400,'Неверный ID');
  }

  try{
    const x=await pool.query(
      `SELECT payment_details
       FROM buyout_requests
       WHERE id=$1`,
      [q.params.id]
    );

    if(
      !x.rowCount||
      !x.rows[0].payment_details
    ){
      return bad(r,404,'Реквизиты не найдены');
    }

    r.set('Cache-Control','no-store');

    r.json({
      payment:decrypt(x.rows[0].payment_details)
    });
  }catch(e){
    console.error(e);
    bad(r,500,'Ошибка реквизитов');
  }
});

app.post('/api/admin/buyouts/:id/quote',admin,async(q,r)=>{
  const price=q.body?.price;

  if(
    !validId(q.params.id)||
    !Number.isSafeInteger(price)||
    price<1||
    price>2147483647
  ){
    return bad(r,400,'Неверная цена');
  }

  try{
    const x=await pool.query(
      `UPDATE buyout_requests
       SET offer_rub=$1,
           status='quoted',
           payment_details=NULL,
           payment_saved_at=NULL,
           updated_at=NOW()
       WHERE id=$2
       AND status='pending'
       RETURNING id,status,offer_rub`,
      [price,q.params.id]
    );

    if(x.rowCount){
      r.json(x.rows[0]);
    }else{
      bad(r,409,'Заявка недоступна');
    }
  }catch(e){
    bad(r,500,'Ошибка цены');
  }
});

app.post('/api/admin/buyouts/:id/reject',admin,async(q,r)=>{
  if(
    !validId(q.params.id)||
    q.body?.confirmed!==true
  ){
    return bad(r,400,'Подтверди отклонение');
  }

  const reason=String(q.body?.reason||'')
    .trim().slice(0,500);

  if(!reason){
    return bad(r,400,'Укажи причину отклонения');
  }

  try{
    const x=await pool.query(
      `UPDATE buyout_requests
       SET status='rejected',
           rejection_reason=$1,
           updated_at=NOW()
       WHERE id=$2
         AND status IN ('pending','quoted')
       RETURNING id,status,rejection_reason`,
      [reason,q.params.id]
    );

    if(!x.rowCount){
      return bad(
        r,409,'Эту заявку уже нельзя отклонить'
      );
    }

    r.json(x.rows[0]);
  }catch(e){
    console.error('Reject buyout:',e);
    bad(r,500,'Ошибка отклонения заявки');
  }
});

app.post('/api/sell/requests/:id/decision',user,async(q,r)=>{
  if(
    !validId(q.params.id)||
    !['accept','decline'].includes(q.body?.decision)
  ){
    return bad(r,400,'Неверное решение');
  }

  try{
    const status=q.body.decision==='accept'
      ?'accepted'
      :'declined';

    const sellerName=[
      q.telegramUser.first_name,
      q.telegramUser.last_name
    ].filter(Boolean).join(' ')||null;

    const x=await pool.query(
      `UPDATE buyout_requests
       SET status=$1,
           seller_username=COALESCE($4,seller_username),
           seller_name=COALESCE($5,seller_name),
           updated_at=NOW()
       WHERE id=$2
         AND telegram_id=$3
         AND status='quoted'
       RETURNING id,status`,
      [
        status,
        q.params.id,
        q.telegramUser.id,
        q.telegramUser.username||null,
        sellerName
      ]
    );

    if(x.rowCount){
      r.json(x.rows[0]);
    }else{
      bad(r,409,'Заявка уже обработана');
    }
  }catch(e){
    bad(r,500,'Ошибка решения');
  }
});

app.post('/api/sell/requests/:id/payment',user,consent,async(q,r)=>{
  if(!validId(q.params.id)){
    return bad(r,400,'Неверный ID');
  }

  let payment;

  try{
    payment=paymentInput(q.body);
  }catch(e){
    return bad(r,400,e.message);
  }

  try{
    const sealed=encrypt(payment);

    const x=await pool.query(
      `UPDATE buyout_requests
       SET payment_details=$1,
           payment_saved_at=NOW(),
           updated_at=NOW()
       WHERE id=$2
         AND telegram_id=$3
         AND status='accepted'
         AND trade_opened_at IS NULL
       RETURNING id`,
      [
        sealed,
        q.params.id,
        q.telegramUser.id
      ]
    );

    if(x.rowCount){
      r.json({
        saved:true,
        payment:publicPayment({
          payment_details:sealed
        })
      });
    }else{
      bad(
        r,
        409,
        'Реквизиты можно изменить только до открытия обмена'
      );
    }
  }catch(e){
    console.error(e);
    bad(r,500,'Ошибка сохранения реквизитов');
  }
});

function tradeUrl(){
  const u=new URL(
    process.env.STEAM_TRADE_URL||''
  );

  if(
    u.protocol!=='https:'||
    u.hostname!=='steamcommunity.com'||
    u.pathname!=='/tradeoffer/new/'||
    !/^\d+$/.test(
      u.searchParams.get('partner')||''
    )||
    !/^[A-Za-z0-9_-]+$/.test(
      u.searchParams.get('token')||''
    )
  ){
    throw Error(
      'STEAM_TRADE_URL настроен неверно'
    );
  }

  return u.toString();
}

app.post('/api/sell/requests/:id/trade',user,consent,async(q,r)=>{
  if(!validId(q.params.id)){
    return bad(r,400,'Неверный ID');
  }

  try{
    const x=await pool.query(
      `SELECT
        id,
        steam_id,
        items,
        status,
        payment_details
       FROM buyout_requests
       WHERE id=$1 AND telegram_id=$2`,
      [
        q.params.id,
        q.telegramUser.id
      ]
    );

    if(!x.rowCount){
      return bad(r,404,'Заявка не найдена');
    }

    const row=x.rows[0];

    if(row.status!=='accepted'){
      return bad(r,409,'Цена не принята');
    }

    if(!row.payment_details){
      return bad(
        r,
        409,
        'Сначала сохрани реквизиты выплаты'
      );
    }

    if(
      await steamFor(q.telegramUser.id)!==
      row.steam_id
    ){
      return bad(
        r,
        409,
        'Подключи Steam из заявки'
      );
    }

    const url=tradeUrl();

    await pool.query(
      `UPDATE buyout_requests
       SET trade_opened_at=COALESCE(
         trade_opened_at,NOW()
       ),
       updated_at=NOW()
       WHERE id=$1
         AND telegram_id=$2
         AND status='accepted'`,
      [
        q.params.id,
        q.telegramUser.id
      ]
    );

    r.json({
      url,
      items:row.items,
      warning:
        'Ссылка не подтверждает получение предметов'
    });
  }catch(e){
    console.error(e);
    bad(r,503,e.message);
  }
});

app.post('/api/admin/buyouts/:id/received',admin,async(q,r)=>{
  if(
    !validId(q.params.id)||
    q.body?.confirmed!==true
  ){
    return bad(r,400,'Подтверди получение');
  }

  try{
    const x=await pool.query(
      `UPDATE buyout_requests
       SET status='received',
           received_at=NOW(),
           payout_due_at=NOW()+INTERVAL '7 days',
           received_by=$1,
           updated_at=NOW()
       WHERE id=$2
         AND status='accepted'
         AND payment_details IS NOT NULL
       RETURNING
         id,
         status,
         received_at,
         payout_due_at`,
      [
        q.admin.id,
        q.params.id
      ]
    );

    if(x.rowCount){
      r.json(x.rows[0]);
    }else{
      bad(
        r,
        409,
        'Заявка не готова к подтверждению'
      );
    }
  }catch(e){
    bad(r,500,'Ошибка подтверждения');
  }
});

app.get('/api/admin/payouts',admin,async(q,r)=>{
  try{
    const rows=(
      await pool.query(
        `SELECT
          id,
          telegram_id,
          seller_username,
          seller_name,
          steam_id,
          items,
          status,
          offer_rub,
          received_at,
          payout_due_at,
          paid_at,
          payment_details
         FROM buyout_requests
         WHERE status IN ('received','paid')
         ORDER BY received_at DESC
         LIMIT 500`
      )
    ).rows;

    const payments=rows.map(
      ({payment_details,...row})=>({
        ...row,
        payment:publicPayment({
          payment_details
        })
      })
    );

    const pending=payments.filter(
      x=>x.status==='received'
    );

    const paid=payments.filter(
      x=>x.status==='paid'
    );

    const stats={
      pendingCount:pending.length,
      pendingRub:pending.reduce(
        (a,x)=>a+Number(x.offer_rub||0),0
      ),
      paidCount:paid.length,
      paidRub:paid.reduce(
        (a,x)=>a+Number(x.offer_rub||0),0
      )
    };

    r.set('Cache-Control','no-store');

    r.json({
      payments,
      stats
    });
  }catch(e){
    console.error('Payouts:',e);
    bad(r,500,'Ошибка статистики выплат');
  }
});

// Админ-панель: пользователи

app.get('/api/admin/users',admin,async(q,r)=>{
  try{
    const x=await pool.query(`
      SELECT
        u.telegram_id,
        u.username,
        u.first_name,
        u.last_name,
        u.first_seen,
        u.last_seen,
        s.steam_id,
        (
          COALESCE((
            SELECT SUM(amount_rub)
            FROM balance_ledger
            WHERE telegram_id=u.telegram_id
          ),0)
          +
          COALESCE((
            SELECT SUM(amount_rub)
            FROM admin_balance_credits
            WHERE telegram_id=u.telegram_id
          ),0)
          + COALESCE((SELECT SUM(total_rub + promo_rub) FROM usdt_orders WHERE telegram_id=u.telegram_id AND order_kind='topup' AND status='paid'),0)
          - COALESCE((
            SELECT SUM(amount_rub)
            FROM balance_purchases
            WHERE telegram_id=u.telegram_id
          ),0)
        )::bigint AS balance_rub,
        (
          SELECT COUNT(*)
          FROM usdt_orders
          WHERE telegram_id=u.telegram_id AND order_kind='purchase'
        )::int AS purchases,
        (
          SELECT COUNT(*)
          FROM buyout_requests
          WHERE telegram_id=u.telegram_id
        )::int AS sales
      FROM market_users u
      LEFT JOIN steam_accounts s
        ON s.telegram_id=u.telegram_id
      ORDER BY u.last_seen DESC
      LIMIT 500
    `);

    r.set('Cache-Control','no-store');
    r.json(x.rows);
  }catch(e){
    console.error('Admin users:',e);
    bad(r,500,'Ошибка списка пользователей');
  }
});

app.get('/api/admin/users/:id',admin,async(q,r)=>{
  if(!validId(q.params.id)){
    return bad(r,400,'Неверный Telegram ID');
  }

  try{
    const [u,purchases,sales,credits]=await Promise.all([
      pool.query(
        `SELECT
           u.*,
           s.steam_id,
           (
             COALESCE((
               SELECT SUM(amount_rub)
               FROM balance_ledger
               WHERE telegram_id=u.telegram_id
             ),0)
             +
             COALESCE((
               SELECT SUM(amount_rub)
               FROM admin_balance_credits
               WHERE telegram_id=u.telegram_id
             ),0)
             + COALESCE((SELECT SUM(total_rub + promo_rub) FROM usdt_orders WHERE telegram_id=u.telegram_id AND order_kind='topup' AND status='paid'),0)
             - COALESCE((
               SELECT SUM(amount_rub)
               FROM balance_purchases
               WHERE telegram_id=u.telegram_id
             ),0)
           )::bigint AS balance_rub
         FROM market_users u
         LEFT JOIN steam_accounts s
           ON s.telegram_id=u.telegram_id
         WHERE u.telegram_id=$1`,
        [q.params.id]
      ),
      pool.query(
        `SELECT id,items,total_rub,status,created_at
         FROM usdt_orders
         WHERE telegram_id=$1 AND order_kind='purchase'
         ORDER BY id DESC
         LIMIT 100`,
        [q.params.id]
      ),
      pool.query(
        `SELECT
           id,items,offer_rub,status,
           created_at,rejection_reason
         FROM buyout_requests
         WHERE telegram_id=$1
         ORDER BY id DESC
         LIMIT 100`,
        [q.params.id]
      ),
      pool.query(
        `SELECT
           id,amount_rub,note,admin_id,created_at
         FROM admin_balance_credits
         WHERE telegram_id=$1
         ORDER BY id DESC
         LIMIT 100`,
        [q.params.id]
      )
    ]);

    if(!u.rowCount){
      return bad(r,404,'Пользователь не найден');
    }

    r.set('Cache-Control','no-store');

    r.json({
      user:u.rows[0],
      purchases:purchases.rows,
      sales:sales.rows,
      credits:credits.rows
    });
  }catch(e){
    console.error('User detail:',e);
    bad(r,500,'Ошибка профиля пользователя');
  }
});

app.post('/api/admin/users/:id/credit',admin,async(q,r)=>{
  const amount=q.body?.amount_rub;
  const note=String(q.body?.note||'').trim();

  if(
    !validId(q.params.id)||
    !Number.isSafeInteger(amount)||
    amount<1||
    amount>1000000||
    note.length>250
  ){
    return bad(r,400,'Неверная сумма или комментарий');
  }

  try{
    const x=await pool.query(
      `INSERT INTO admin_balance_credits(
         telegram_id,
         amount_rub,
         admin_id,
         note
       )
       SELECT telegram_id,$2,$3,$4
       FROM market_users
       WHERE telegram_id=$1
       RETURNING id,amount_rub,created_at`,
      [
        q.params.id,
        amount,
        q.admin.id,
        note
      ]
    );

    if(!x.rowCount){
      return bad(r,404,'Пользователь не найден');
    }

    r.status(201).json(x.rows[0]);
  }catch(e){
    console.error('Credit:',e);
    bad(r,500,'Ошибка начисления');
  }
});

app.get('/api/balance',user,async(q,r)=>{
  try{
    const x=await pool.query(
      `SELECT
         COALESCE(SUM(amount_rub),0)::bigint
         AS balance
       FROM (
         SELECT telegram_id,amount_rub
         FROM balance_ledger
         UNION ALL
         SELECT telegram_id,amount_rub
         FROM admin_balance_credits
         UNION ALL
         SELECT telegram_id,total_rub + promo_rub FROM usdt_orders WHERE order_kind='topup' AND status='paid'
         UNION ALL
         SELECT telegram_id,-amount_rub
         FROM balance_purchases
       ) ledger
       WHERE telegram_id=$1`,
      [q.telegramUser.id]
    );

    r.json({
      balanceRub:Number(x.rows[0].balance)
    });
  }catch(e){
    bad(r,500,'Ошибка баланса');
  }
});

app.post('/api/admin/payouts/:id/complete',admin,async(q,r)=>{
  if(
    !validId(q.params.id)||
    q.body?.confirmed!==true
  ){
    return bad(
      r,
      400,
      'Требуется подтверждение'
    );
  }

  let client;

  try{
    client=await pool.connect();

    await client.query('BEGIN');

    const x=await client.query(
      `SELECT
        id,
        telegram_id,
        offer_rub,
        status,
        payout_due_at,
        payment_details
       FROM buyout_requests
       WHERE id=$1
       FOR UPDATE`,
      [q.params.id]
    );

    if(
      !x.rowCount||
      x.rows[0].status!=='received'||
      !x.rows[0].payment_details
    ){
      await client.query('ROLLBACK');

      return bad(
        r,
        409,
        'Заявка недоступна для выплаты'
      );
    }

    const row=x.rows[0];

    if(
      new Date(row.payout_due_at).getTime()>
      Date.now()
    ){
      await client.query('ROLLBACK');

      return bad(
        r,
        409,
        'Семь суток ещё не истекли'
      );
    }

    const payment=decrypt(
      row.payment_details
    );

    if(payment.method==='BALANCE'){
      await client.query(
        `INSERT INTO balance_ledger(
          telegram_id,
          request_id,
          amount_rub
        )
        VALUES($1,$2,$3)
        ON CONFLICT(request_id)
        DO NOTHING`,
        [
          row.telegram_id,
          row.id,
          row.offer_rub
        ]
      );
    }

    await client.query(
      `UPDATE buyout_requests
       SET status='paid',
           paid_at=NOW(),
           paid_by=$1,
           updated_at=NOW()
       WHERE id=$2`,
      [
        q.admin.id,
        row.id
      ]
    );

    await client.query('COMMIT');

    r.json({
      success:true,
      method:payment.method
    });
  }catch(e){
    if(client){
      try{
        await client.query('ROLLBACK');
      }catch(rollbackError){
        console.error(
          'Rollback failed:',
          rollbackError
        );
      }
    }

    console.error('Payout completion:',e);
    bad(r,500,'Не удалось завершить выплату');
  }finally{
    if(client){
      client.release();
    }
  }
});

const tronGridKey=process.env.TRONGRID_API_KEY?.trim();
const tronUsdtContract='TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
const base58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const validTronTxid=value=>typeof value==='string'&&/^[a-f0-9]{64}$/i.test(value);

function validTronAddress(address){
  if(typeof address!=='string'||!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address))return false;
  let value=0n;
  for(const char of address)value=value*58n+BigInt(base58.indexOf(char));
  const bytes=Buffer.from(value.toString(16).padStart(50,'0'),'hex');
  if(bytes.length!==25||bytes[0]!==0x41)return false;
  const payload=bytes.subarray(0,21);
  const hash=crypto.createHash('sha256').update(payload).digest();
  const checksum=crypto.createHash('sha256').update(hash).digest().subarray(0,4);
  return bytes.subarray(21).equals(checksum);
}

async function allocateAutomaticAmount(client,network,address,amountCents){
  // Leave the whole-cent amount available to legacy invoices. Never reuse a suffix
  // for this wallet, so a late transfer cannot pay a later order.
  const base=BigInt(amountCents)*10000n;
  const ceiling=base+9999n;
  const isTron=network==='TRC20';
  const amountColumn=isTron?'tron_amount_units':'bsc_amount_units';
  const walletColumn=isTron?'wallet_address':'LOWER(wallet_address)';
  await client.query('SELECT pg_advisory_xact_lock(348286,hashtext($1))',[address]);
  const x=await client.query(`SELECT COALESCE(MAX(${amountColumn}),$2::bigint)+1 AS units
    FROM usdt_orders WHERE ${walletColumn}=$1 AND ${amountColumn} BETWEEN $2 AND $3`,
  [address,base.toString(),ceiling.toString()]);
  const units=BigInt(x.rows[0].units);
  return units<=ceiling?units.toString():null;
}

async function tronGridRequest(endpoint,options={}){
  const response=await fetch('https://api.trongrid.io'+endpoint,{
    ...options,
    headers:{'TRON-PRO-API-KEY':tronGridKey,'Content-Type':'application/json'},
    signal:AbortSignal.timeout(10000)
  });
  if(!response.ok)throw Error('TronGrid HTTP '+response.status);
  return response.json();
}

async function settleTronWallet(address,orders){
  const pending=new Map(orders.map(order=>[order.tron_amount_units,order]));
  const since=orders.reduce((oldest,order)=>Math.min(oldest,new Date(order.created_at).getTime()),Infinity);
  const params=new URLSearchParams({
    only_confirmed:'true',contract_address:tronUsdtContract,min_timestamp:String(since),limit:'200'
  });
  const cursors=new Set();
  do{
    const page=await tronGridRequest('/v1/accounts/'+encodeURIComponent(address)+'/transactions/trc20?'+params);
    if(page.success!==true||!Array.isArray(page.data))throw Error('Invalid TronGrid transfer response');
    for(const transfer of page.data){
      if(transfer.type!=='Transfer'||transfer.to!==address||
         transfer.token_info?.address!==tronUsdtContract||!validTronTxid(transfer.transaction_id)||
         !Number.isSafeInteger(transfer.block_timestamp))continue;
      const order=pending.get(transfer.value);
      if(!order||transfer.block_timestamp<new Date(order.created_at).getTime()||
         transfer.block_timestamp>new Date(order.tron_expires_at).getTime())continue;
      const txid=transfer.transaction_id.toLowerCase();
      const receipt=await tronGridRequest('/walletsolidity/gettransactioninfobyid',{
        method:'POST',body:JSON.stringify({value:txid})
      });
      if(receipt.id!==txid||receipt.result==='FAILED'||receipt.receipt?.result!=='SUCCESS'||
         receipt.blockTimeStamp!==transfer.block_timestamp)continue;
      try{
        const applied=await pool.query(`UPDATE usdt_orders
          SET status='paid',tron_txid=$2,tron_block_at=$3,reviewed_at=NOW(),reviewed_by=NULL
          WHERE id=$1 AND network='TRC20' AND status IN ('awaiting','review')
            AND tron_amount_units=$4 AND wallet_address=$5
            AND $3::timestamptz BETWEEN created_at AND tron_expires_at`,
        [order.id,txid,new Date(transfer.block_timestamp),transfer.value,address]);
        if(applied.rowCount)pending.delete(transfer.value);
      }catch(error){
        if(error.code!=='23505'||error.constraint!=='usdt_orders_tron_txid_unique')throw error;
      }
    }
    const cursor=page.meta?.fingerprint;
    if(!pending.size||!cursor||cursors.has(cursor))return;
    cursors.add(cursor);
    params.set('fingerprint',cursor);
  }while(true);
}

function startTronPaymentWatcher(){
  if(!tronGridKey)return;
  async function tick(){
    try{
      const x=await pool.query(`SELECT id,wallet_address,tron_amount_units,created_at,tron_expires_at
        FROM usdt_orders WHERE network='TRC20' AND status IN ('awaiting','review')
          AND tron_expires_at>NOW()-INTERVAL '24 hours'`);
      const wallets=new Map();
      for(const order of x.rows){
        if(!wallets.has(order.wallet_address))wallets.set(order.wallet_address,[]);
        wallets.get(order.wallet_address).push(order);
      }
      for(const [address,orders] of wallets){
        try{await settleTronWallet(address,orders)}
        catch(error){console.error('TRC20 wallet check:',error.message)}
      }
    }catch(error){console.error('TRC20 order check:',error.message)}
    finally{setTimeout(tick,30000).unref()}
  }
  void tick();
}

const bscRpcUrl=process.env.BSC_RPC_URL?.trim();
const bscUsdtContract='0x55d398326f99059ff775485246999027b3197955';
const transferTopic='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const validBscTxid=value=>typeof value==='string'&&/^0x[a-f0-9]{64}$/i.test(value);
const bscTopicAddress=address=>'0x'+address.slice(2).padStart(64,'0');
const bscHex=value=>'0x'+value.toString(16);
let bscLastHealthyAt=0;
let bscLogBatchSize=1000;

async function bscRpc(method,params){
  const url=new URL(bscRpcUrl);
  if(url.protocol!=='https:')throw Error('BSC_RPC_URL must use HTTPS');
  const response=await fetch(url,{
    method:'POST',redirect:'error',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(10000)
  });
  if(!response.ok)throw Error(method+' HTTP '+response.status);
  const payload=await response.json();
  if(payload.error){
    const error=Error(method+' RPC error '+payload.error.code);
    error.rangeLimit=payload.error.code===-32005||
      /range|too many results|more than|maximum.*blocks|limit.*blocks/i.test(payload.error.message||'');
    throw error;
  }
  if(payload.id!==1||!Object.hasOwn(payload,'result'))throw Error('Invalid '+method+' response');
  return payload.result;
}

function bscQuantity(value){
  if(typeof value!=='string'||!/^0x[0-9a-f]+$/i.test(value))throw Error('Invalid BSC quantity');
  const number=Number(BigInt(value));
  if(!Number.isSafeInteger(number))throw Error('BSC quantity out of range');
  return number;
}

async function getBscBlock(tag){
  const block=await bscRpc('eth_getBlockByNumber',[tag,false]);
  if(!block||!validBscTxid(block.hash))throw Error('Invalid BSC block');
  const number=bscQuantity(block.number);
  if(tag!=='finalized'&&number!==bscQuantity(tag))throw Error('Unexpected BSC block');
  return {number,at:bscQuantity(block.timestamp)*1000,hash:block.hash.toLowerCase()};
}

async function firstBscBlockAt(since,low,high){
  while(low<high){
    const middle=Math.floor((low+high)/2);
    const block=await getBscBlock(bscHex(middle));
    if(block.at<since)low=middle+1;
    else high=middle;
  }
  return low;
}

async function getBscTransfers(address,from,to){
  const logs=await bscRpc('eth_getLogs',[{
    address:bscUsdtContract,fromBlock:bscHex(from),toBlock:bscHex(to),
    topics:[transferTopic,null,bscTopicAddress(address)]
  }]);
  if(!Array.isArray(logs))throw Error('Invalid BSC transfer response');
  return logs;
}

async function scanBscWallet(address,since,tip){
  if(since>tip.at)return;
  const cursor=await pool.query('SELECT next_block FROM bsc_payment_cursors WHERE wallet_address=$1',[address]);
  let next=Number(cursor.rows[0]?.next_block||0);
  if(!next){
    let low=tip.number;
    for(let step=256;low>0;step*=2){
      low=Math.max(0,tip.number-step);
      if((await getBscBlock(bscHex(low))).at<since)break;
    }
    next=await firstBscBlockAt(since,low,tip.number);
  }else if(next<=tip.number&&(await getBscBlock(bscHex(next))).at<since){
    next=await firstBscBlockAt(since,next,tip.number);
  }
  for(let batch=0;next<=tip.number&&batch<16;batch++){
    const end=Math.min(next+bscLogBatchSize-1,tip.number);
    let logs;
    try{logs=await getBscTransfers(address,next,end)}
    catch(error){
      if(!error.rangeLimit||bscLogBatchSize===1)throw error;
      bscLogBatchSize=Math.max(1,Math.floor(bscLogBatchSize/2));
      continue;
    }
    const blocks=new Map();
    for(const log of logs){
      if(log.removed||log.address?.toLowerCase()!==bscUsdtContract||log.topics?.length!==3||
         log.topics[0]?.toLowerCase()!==transferTopic||log.topics[2]?.toLowerCase()!==bscTopicAddress(address)||
         !validBscTxid(log.transactionHash)||!validBscTxid(log.blockHash)||!/^0x[0-9a-f]{64}$/i.test(log.data||''))continue;
      const units18=BigInt(log.data);
      // The invoice is displayed in millionths of a USDT. The BSC token uses 18 decimals.
      if(units18===0n||units18%1000000000000n!==0n)continue;
      const units=units18/1000000000000n;
      if(units>9223372036854775807n)continue;
      const number=bscQuantity(log.blockNumber);
      if(number<next||number>end)throw Error('Transfer outside requested BSC block range');
      if(!blocks.has(number))blocks.set(number,await getBscBlock(bscHex(number)));
      const block=blocks.get(number);
      if(block.hash!==log.blockHash.toLowerCase())throw Error('BSC transfer block hash mismatch');
      try{
        await pool.query(`UPDATE usdt_orders
          SET status='paid',bsc_txid=$1,bsc_block_at=$2,reviewed_at=NOW(),reviewed_by=NULL
          WHERE network='BEP20' AND status IN ('awaiting','review')
            AND LOWER(wallet_address)=$3 AND bsc_amount_units=$4
            AND $2::timestamptz BETWEEN date_trunc('second',created_at) AND bsc_expires_at`,
        [log.transactionHash.toLowerCase(),new Date(block.at),address,units.toString()]);
      }catch(error){
        if(error.code!=='23505'||error.constraint!=='usdt_orders_bsc_txid_unique')throw error;
      }
    }
    next=end+1;
    await pool.query(`INSERT INTO bsc_payment_cursors(wallet_address,next_block)
      VALUES($1,$2) ON CONFLICT(wallet_address) DO UPDATE
      SET next_block=GREATEST(bsc_payment_cursors.next_block,EXCLUDED.next_block)`,[address,next]);
  }
}

function startBscPaymentWatcher(){
  if(!bscRpcUrl)return;
  async function tick(){
    try{
      if(await bscRpc('eth_chainId',[])!=='0x38')throw Error('BSC RPC must be on mainnet (chain ID 56)');
      const tip=await getBscBlock('finalized');
      if(Date.now()-tip.at>5*60*1000||tip.at>Date.now()+30000)throw Error('Stale or invalid BSC finalized block');
      // Verify that the configured endpoint actually serves logs before creating automatic invoices.
      await getBscTransfers('0x'+'0'.repeat(40),tip.number,tip.number);
      bscLastHealthyAt=Date.now();
      const x=await pool.query(`SELECT LOWER(wallet_address) AS address, date_trunc('second',MIN(created_at)) AS since
        FROM usdt_orders WHERE network='BEP20' AND status IN ('awaiting','review')
          AND bsc_expires_at>NOW()-INTERVAL '24 hours' GROUP BY LOWER(wallet_address)`);
      for(const {address,since} of x.rows){
        await scanBscWallet(address,new Date(since).getTime(),tip);
      }
    }catch(error){
      bscLastHealthyAt=0;
      console.error('BEP20 order check:',error instanceof TypeError?'RPC connection or URL error':error.message);
    }finally{setTimeout(tick,30000).unref()}
  }
  void tick();
}

function validUsdtAddress(network,address){
  if(network==='TRC20'){
    return address!==tronUsdtContract&&validTronAddress(address);
  }

  if(network==='BEP20'){
    return typeof address==='string'&&/^0x[a-fA-F0-9]{40}$/.test(address)&&
      address.toLowerCase()!==bscUsdtContract&&address!=='0x'+'0'.repeat(40);
  }

  return false;
}

app.get('/api/admin/payment-settings',admin,async(q,r)=>{
  try{
    const x=await pool.query(
      `SELECT
        rate_kopecks,
        trc20_address,
        bep20_address,
        updated_at
       FROM usdt_settings
       WHERE id=1`
    );

    r.set('Cache-Control','no-store');
    r.json(x.rows[0]);
  }catch(e){
    console.error('USDT settings:',e);
    bad(r,500,'Ошибка настроек USDT');
  }
});

app.put('/api/admin/payment-settings',admin,async(q,r)=>{
  const rate=q.body?.rate_kopecks;
  const trc=String(
    q.body?.trc20_address||''
  ).trim();
  const bep=String(
    q.body?.bep20_address||''
  ).trim();

  if(
    !Number.isSafeInteger(rate)||
    rate<100||
    rate>10000000
  ){
    return bad(
      r,400,'Укажи корректный курс USDT'
    );
  }

  if(
    trc&&
    !validUsdtAddress('TRC20',trc)
  ){
    return bad(r,400,'Неверный адрес TRC20');
  }

  if(
    bep&&
    !validUsdtAddress('BEP20',bep)
  ){
    return bad(r,400,'Неверный адрес BEP20');
  }

  try{
    const x=await pool.query(
      `UPDATE usdt_settings
       SET rate_kopecks=$1,
           trc20_address=$2,
           bep20_address=$3,
           updated_at=NOW()
       WHERE id=1
       RETURNING
         rate_kopecks,
         trc20_address,
         bep20_address,
         updated_at`,
      [rate,trc,bep]
    );

    r.set('Cache-Control','no-store');
    r.json(x.rows[0]);
  }catch(e){
    console.error('Save USDT settings:',e);
    bad(r,500,'Ошибка сохранения настроек');
  }
});


const BUYCS2_API='https://api.buycs2.com';
const buycs2Headers=()=>({
  'x-merchant-id':String(process.env.BUYCS2_MERCHANT_ID||'').trim(),
  'x-api-key':String(process.env.BUYCS2_API_KEY||'').trim(),
  'Accept':'application/json','Content-Type':'application/json','Accept-Encoding':'gzip'
});

async function buycs2Request(pathname,{method='GET',body}={}){
  if(!process.env.BUYCS2_MERCHANT_ID||!process.env.BUYCS2_API_KEY)throw Error('BuyCS2 API не настроен');
  const res=await fetch(BUYCS2_API+pathname,{method,headers:buycs2Headers(),body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(30000)});
  const data=await res.json().catch(()=>({}));
  if(!res.ok){const e=Error(data?.message||data?.error||('BuyCS2 HTTP '+res.status));e.code=data?.error||'buycs2_error';e.status=res.status;throw e}
  return data;
}

async function processBuycs2Fulfillments(orderId){
  const rows=(await pool.query(`SELECT * FROM supplier_fulfillments WHERE order_id=$1 AND status IN ('QUEUED','FAILED') ORDER BY id`,[orderId])).rows;
  for(const row of rows){
    try{
      await pool.query(`UPDATE supplier_fulfillments SET status='PURCHASING',updated_at=NOW(),fail_reason=NULL,error_code=NULL WHERE id=$1`,[row.id]);
      const data=await buycs2Request('/Items/BuyByName',{method:'POST',body:{
        market_hash_name:row.market_hash_name,
        maxPrice:Number(row.max_price_usd_cents),
        tradeUrl:row.trade_url,
        externalId:row.external_id,
        tradeDurationSeconds:1800
      }});
      await pool.query(`UPDATE supplier_fulfillments SET trade_id=$2,status='PENDING',actual_price_usd_cents=$3,updated_at=NOW() WHERE id=$1`,[row.id,data.tradeId||null,Number(data.price||row.max_price_usd_cents)]);
    }catch(e){
      await pool.query(`UPDATE supplier_fulfillments SET status='FAILED',fail_reason=$2,updated_at=NOW() WHERE id=$1`,[row.id,String(e?.message||'Ошибка BuyCS2').slice(0,500)]).catch(()=>{});
      console.error('BuyCS2 fulfillment:',orderId,row.id,e?.message||e);
    }
  }
}

app.post('/api/buycs2/webhook',async(q,r)=>{
  try{
    const sig=String(q.get('x-signature')||'').trim().toLowerCase();
    if(!/^[0-9a-f]{64}$/.test(sig)||!process.env.BUYCS2_API_KEY||!q.rawBody)return r.sendStatus(401);
    const expected=crypto.createHmac('sha256',process.env.BUYCS2_API_KEY).update(q.rawBody).digest('hex');
    const a=Buffer.from(sig,'hex'),b=Buffer.from(expected,'hex');
    if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return r.sendStatus(401);
    const type=String(q.get('x-webhook-type')||'');
    if(type==='trade_updated'){
      const d=q.body||{};
      const completed=d.status==='COMPLETED'?new Date():null;
      await pool.query(`UPDATE supplier_fulfillments SET status=$1,offer_id=$2,fail_reason=$3,error_code=$4,updated_at=NOW(),completed_at=CASE WHEN $1='COMPLETED' THEN NOW() ELSE completed_at END
        WHERE trade_id=$5 OR external_id=$6`,[String(d.status||'UNKNOWN'),d.offerId||null,d.failReason||null,Number.isInteger(d.errorCode)?d.errorCode:null,d.tradeId||null,d.externalId||null]);
    }else if(type==='item_removed'){
      const id=Number(q.body?.itemId);if(Number.isSafeInteger(id))await pool.query(`UPDATE products SET quantity=0 WHERE supplier_code='BUYCS2' AND supplier_listing_id=$1`,[String(id)]);
    }
    r.sendStatus(204);
  }catch(e){console.error('BuyCS2 webhook:',e);r.sendStatus(500)}
});

function normalizePromoCode(raw){
  return typeof raw==='string'?raw.normalize('NFKC').trim().replace(/\s+/gu,' ').toUpperCase():'';
}

function validPromoCode(code){
  return /^[\p{L}\p{N}][\p{L}\p{N} _-]{1,31}$/u.test(code);
}

function promoError(message){
  return Object.assign(new Error(message),{promoError:true});
}

async function calculatePromo(db,raw,kind,baseRub){
  if(raw==null||raw==='')return {id:null,adjustmentRub:0,baseRub,finalRub:baseRub};
  const code=normalizePromoCode(raw);
  if(!validPromoCode(code))throw promoError('Проверь написание промокода');
  const {rows:[promo]}=await db.query(
    'SELECT id,topup_bps,discount_bps FROM market_promo_codes WHERE code=$1',[code]
  );
  if(!promo)throw promoError('Промокод не найден');
  const bps=kind==='topup'?promo.topup_bps:promo.discount_bps;
  if(!bps)throw promoError('Этот промокод не действует для выбранной операции');
  const adjustmentRub=Math.floor(baseRub*bps/10000);
  if(!adjustmentRub)throw promoError('Сумма слишком мала для этого промокода');
  const finalRub=kind==='topup'?baseRub+adjustmentRub:baseRub-adjustmentRub;
  return {id:promo.id,code,bps,adjustmentRub,baseRub,finalRub};
}

async function paymentPromo(db,body,kind,baseRub){
  const promo=await calculatePromo(db,body?.promoCode,kind,baseRub);
  if(promo.id&&(body.promoBaseRub!==baseRub||body.promoFinalRub!==promo.finalRub)){
    throw promoError('Сумма изменилась. Примени промокод ещё раз.');
  }
  return promo;
}

app.post('/api/promos/quote',user,async(q,r)=>{
  const {kind,code,amountRub,productIds}=q.body||{};
  try{
    let baseRub=amountRub;
    if(kind==='purchase'){
      if(!Array.isArray(productIds)||!productIds.length||productIds.length>50||
         productIds.some(id=>!validId(id))||new Set(productIds.map(String)).size!==productIds.length){
        return bad(r,400,'Проверь выбранные товары');
      }
      const {rows}=await pool.query('SELECT price FROM products WHERE id=ANY($1::bigint[]) AND quantity>0',[productIds]);
      if(rows.length!==productIds.length)return bad(r,409,'Некоторые товары уже недоступны');
      baseRub=rows.reduce((total,row)=>total+Number(row.price),0);
    }else if(kind!=='topup'){
      return bad(r,400,'Неизвестная операция');
    }
    const max=kind==='topup'?1000000:2147483647;
    if(!Number.isSafeInteger(baseRub)||baseRub<1||baseRub>max)return bad(r,400,'Проверь сумму');
    if(!validPromoCode(normalizePromoCode(code)))return bad(r,400,'Введи промокод');
    const {id,...quote}=await calculatePromo(pool,code,kind,baseRub);
    r.json(quote);
  }catch(e){
    if(e.promoError)return bad(r,400,e.message);
    console.error('Promo quote:',e);
    bad(r,500,'Не удалось проверить промокод');
  }
});

app.get('/api/admin/promos',admin,async(_q,r)=>{
  try{
    const {rows}=await pool.query(`
      SELECT p.*,COUNT(DISTINCT o.telegram_id) AS users
      FROM market_promo_codes p
      LEFT JOIN usdt_orders o ON o.promo_code_id=p.id AND o.status='paid'
      GROUP BY p.id ORDER BY p.id DESC
    `);
    r.set('Cache-Control','no-store').json(rows);
  }catch(e){
    console.error('List promos:',e);
    bad(r,500,'Не удалось загрузить промокоды');
  }
});

app.post('/api/admin/promos',admin,async(q,r)=>{
  const {code:raw,topupBps,discountBps}=q.body||{};
  const code=normalizePromoCode(raw);
  if(!validPromoCode(code))return bad(r,400,'Укажи код из 2–32 символов: буквы, цифры, пробел, дефис или подчёркивание');
  if(!Number.isInteger(topupBps)||topupBps<0||topupBps>10000||
     !Number.isInteger(discountBps)||discountBps<0||discountBps>9999||!(topupBps||discountBps)){
    return bad(r,400,'Укажи бонус до 100% или скидку до 99,99%. Хотя бы один процент должен быть больше нуля.');
  }
  try{
    const {rows:[promo]}=await pool.query(`
      INSERT INTO market_promo_codes(code,topup_bps,discount_bps) VALUES($1,$2,$3)
      ON CONFLICT(code) DO NOTHING RETURNING *
    `,[code,topupBps,discountBps]);
    if(!promo)return bad(r,409,'Такой промокод уже существует');
    r.status(201).json({...promo,users:0});
  }catch(e){
    console.error('Create promo:',e);
    bad(r,500,'Не удалось создать промокод');
  }
});

/* Atomic balance checkout: authenticated user, locked products and per-user ledger. */
app.post('/api/orders/balance',user,async(q,r)=>{
  if(q.body?.promoCode!=null&&q.body.promoCode!==''){
    return bad(r,400,'При оплате с баланса промокод недоступен');
  }
  const ids=q.body?.productIds;
  if(!Array.isArray(ids)||ids.length<1||ids.length>50||
     ids.some(id=>!validId(id))||new Set(ids.map(String)).size!==ids.length){
    return bad(r,400,'Проверь выбранные товары');
  }
  let client;
  try{
    client=await pool.connect();
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1::bigint)',[q.telegramUser.id]);
    const products=await client.query(
      `SELECT id,weapon,skin,condition,price,quantity,source_type,supplier_code,supplier_listing_id,steam_asset_id,supplier_cost_usd_cents,supplier_market_hash_name,supplier_published FROM products
       WHERE id=ANY($1::bigint[]) ORDER BY id FOR UPDATE`,[ids]);
    if(products.rowCount!==ids.length||products.rows.some(p=>p.quantity<1||(p.source_type==='SUPPLIER'&&(!p.supplier_published||p.supplier_code!=='BUYCS2'||!p.supplier_cost_usd_cents||!p.supplier_market_hash_name)))){
      await client.query('ROLLBACK');
      return bad(r,409,'Некоторые скины закончились или недоступны');
    }
    const items=ids.map(id=>{
      const p=products.rows.find(x=>String(x.id)===String(id));
      return {product_id:p.id,weapon:p.weapon,skin:p.skin,condition:p.condition,price:p.price,quantity:1,source_type:p.source_type,
        supplier_code:p.supplier_code||null,supplier_listing_id:p.supplier_listing_id||null,steam_asset_id:p.steam_asset_id||null,
        supplier_cost_usd_cents:p.supplier_cost_usd_cents===null?null:Number(p.supplier_cost_usd_cents),supplier_market_hash_name:p.supplier_market_hash_name||null};
    });
    const total=items.reduce((sum,p)=>sum+Number(p.price),0);
    if(!Number.isSafeInteger(total)||total<1||total>2147483647){
      await client.query('ROLLBACK');return bad(r,400,'Неверная сумма');
    }
    const b=await client.query(`SELECT
      COALESCE((SELECT SUM(amount_rub) FROM balance_ledger WHERE telegram_id=$1),0)
      +COALESCE((SELECT SUM(amount_rub) FROM admin_balance_credits WHERE telegram_id=$1),0)
      +COALESCE((SELECT SUM(total_rub + promo_rub) FROM usdt_orders WHERE telegram_id=$1 AND order_kind='topup' AND status='paid'),0)
      -COALESCE((SELECT SUM(amount_rub) FROM balance_purchases WHERE telegram_id=$1),0)
      AS balance`,[q.telegramUser.id]);
    const balance=Number(b.rows[0].balance);
    if(balance<total){
      await client.query('ROLLBACK');
      return bad(r,409,'Недостаточно средств. Баланс: '+balance+' ₽, к оплате: '+total+' ₽');
    }
    const order=await client.query(`INSERT INTO usdt_orders
      (telegram_id,items,total_rub,rate_kopecks,amount_cents,network,wallet_address,status,reviewed_at)
      VALUES($1,$2::jsonb,$3,10000,$4,'BALANCE','','paid',NOW())
      RETURNING id,items,total_rub,status,network,created_at`,
      [q.telegramUser.id,JSON.stringify(items),total,total*100]);
    await client.query(`INSERT INTO balance_purchases(order_id,telegram_id,amount_rub)
      VALUES($1,$2,$3)`,[order.rows[0].id,q.telegramUser.id,total]);
    for(const id of ids){
      await client.query(`UPDATE products SET quantity=quantity-1 WHERE id=$1 AND source_type='OWN'`,[id]);
    }
    await client.query('COMMIT');
    r.status(201).json({...order.rows[0],balanceRub:balance-total});
  }catch(e){
    if(client)try{await client.query('ROLLBACK')}catch{}
    console.error('Balance checkout:',e);
    bad(r,500,'Ошибка оплаты с баланса. Проверь историю заказов перед повторной попыткой');
  }finally{if(client)client.release()}
});

/* USDT invoice and order routes */

app.post('/api/orders/usdt',user,async(q,r)=>{
  const ids=q.body?.productIds;
  const network=q.body?.network;

  if(
    !['TRC20','BEP20'].includes(network)||
    !Array.isArray(ids)||
    ids.length<1||
    ids.length>50||
    ids.some(id=>!validId(id))||
    new Set(ids.map(String)).size!==ids.length
  ){
    return bad(r,400,'Проверь товары и сеть оплаты');
  }

  let client;

  try{
    client=await pool.connect();
    await client.query('BEGIN');

    const settings=await client.query(
      `SELECT rate_kopecks,trc20_address,bep20_address
       FROM usdt_settings WHERE id=1`
    );

    const config=settings.rows[0];

    if(!config){
      await client.query('ROLLBACK');
      return bad(r,503,'Настройки USDT недоступны');
    }

    const address=network==='TRC20'
      ?config.trc20_address
      :config.bep20_address?.toLowerCase();

    if(!validUsdtAddress(network,address)){
      await client.query('ROLLBACK');
      return bad(r,409,'Кошелёк этой сети ещё не настроен');
    }
    if(network==='BEP20'&&bscRpcUrl&&Date.now()-bscLastHealthyAt>90000){
      await client.query('ROLLBACK');
      return bad(r,503,'Проверка BEP20 временно недоступна. Попробуй позже или выбери TRC20.');
    }

    const products=await client.query(
      `SELECT id,weapon,skin,condition,price,quantity,source_type,supplier_code,supplier_listing_id,steam_asset_id,supplier_cost_usd_cents,supplier_market_hash_name,supplier_published
       FROM products
       WHERE id=ANY($1::bigint[])
       FOR UPDATE`,
      [ids]
    );

    if(products.rowCount!==ids.length){
      await client.query('ROLLBACK');
      return bad(r,409,'Некоторые товары уже недоступны');
    }

    if(products.rows.some(p=>p.quantity<1||(p.source_type==='SUPPLIER'&&(!p.supplier_published||p.supplier_code!=='BUYCS2'||!p.supplier_cost_usd_cents||!p.supplier_market_hash_name)))){
      await client.query('ROLLBACK');
      return bad(r,409,'Один из товаров закончился');
    }

    const items=ids.map(id=>{
      const p=products.rows.find(
        x=>String(x.id)===String(id)
      );

      return {
        product_id:p.id,
        weapon:p.weapon,
        skin:p.skin,
        condition:p.condition,
        price:p.price,
        quantity:1,
        source_type:p.source_type,
        supplier_code:p.supplier_code||null,
        supplier_listing_id:p.supplier_listing_id||null,
        steam_asset_id:p.steam_asset_id||null,
        supplier_cost_usd_cents:p.supplier_cost_usd_cents===null?null:Number(p.supplier_cost_usd_cents),
        supplier_market_hash_name:p.supplier_market_hash_name||null
      };
    });

    const baseRub=items.reduce(
      (sum,item)=>sum+Number(item.price),0
    );

    const rate=Number(config.rate_kopecks);

    if(
      !Number.isSafeInteger(baseRub)||
      baseRub<1||
      baseRub>2147483647||
      !Number.isSafeInteger(rate)||
      rate<1
    ){
      await client.query('ROLLBACK');
      return bad(r,400,'Неверная сумма заказа');
    }

    const promo=await paymentPromo(client,q.body,'purchase',baseRub);
    const total=promo.finalRub;
    const amountCents=Math.ceil(
      total*10000/rate
    );
    const autoTron=network==='TRC20'&&Boolean(tronGridKey);
    const autoBsc=network==='BEP20'&&Boolean(bscRpcUrl);
    const exactAmount=autoTron||autoBsc?await allocateAutomaticAmount(client,network,address,amountCents):null;
    if((autoTron||autoBsc)&&!exactAmount){
      await client.query('ROLLBACK');
      return bad(r,409,'Не удалось выделить уникальную сумму USDT');
    }

    const order=await client.query(
      `INSERT INTO usdt_orders(
         telegram_id,
         items,
         total_rub,
         rate_kopecks,
         amount_cents,
         network,
         wallet_address,
         tron_amount_units,
         tron_expires_at,
         bsc_amount_units,
         bsc_expires_at,
         promo_code_id,promo_rub
       )
       VALUES($1,$2::jsonb,$3,$4,$5,$6,$7,$8::bigint,
         CASE WHEN $8::bigint IS NOT NULL THEN NOW()+INTERVAL '30 minutes' END,
         $9::bigint,CASE WHEN $9::bigint IS NOT NULL THEN NOW()+INTERVAL '30 minutes' END,$10,$11)
       RETURNING
         id,total_rub,rate_kopecks,
         amount_cents,network,
         wallet_address,status,created_at,tron_amount_units,tron_expires_at,bsc_amount_units,bsc_expires_at`,
      [
        q.telegramUser.id,
        JSON.stringify(items),
        total,
        rate,
        amountCents,
        network,
        address,
        autoTron?exactAmount:null,
        autoBsc?exactAmount:null,
        promo.id,promo.adjustmentRub
      ]
    );

    await client.query('COMMIT');
    r.status(201).json(order.rows[0]);
  }catch(e){
    if(client){
      try{
        await client.query('ROLLBACK');
      }catch{}
    }

    if(e.promoError)return bad(r,409,e.message);
    console.error('Create USDT order:',e);
    bad(r,500,'Не удалось создать счёт');
  }finally{
    if(client)client.release();
  }
});

app.get('/api/display-currency',async(_q,r)=>{
  try{
    const x=await pool.query('SELECT rate_kopecks FROM usdt_settings WHERE id=1');
    r.set('Cache-Control','no-store').json({rateKopecks:Number(x.rows[0]?.rate_kopecks||0)});
  }catch{
    bad(r,500,'Не удалось загрузить курс');
  }
});

const topupInvoiceFields=`id,order_kind,total_rub,promo_rub,rate_kopecks,amount_cents,network,wallet_address,
  status,created_at,reviewed_at,tron_amount_units,tron_expires_at,bsc_amount_units,bsc_expires_at`;

app.get('/api/balance/topups',user,async(q,r)=>{
  const id=q.query.id;
  if(id!==undefined&&(typeof id!=='string'||!validId(id)))return bad(r,400,'Неверный номер счёта');
  try{
    const x=await pool.query(`SELECT ${topupInvoiceFields} FROM usdt_orders
      WHERE telegram_id=$1 AND order_kind='topup' AND ($2::bigint IS NULL OR id=$2)
      ORDER BY id DESC LIMIT 30`,[q.telegramUser.id,id??null]);
    r.set('Cache-Control','no-store').json({topups:x.rows});
  }catch{
    bad(r,500,'Не удалось загрузить пополнения');
  }
});

app.post('/api/balance/topups',user,async(q,r)=>{
  const {amountRub,network}=q.body||{};
  if(!Number.isSafeInteger(amountRub)||amountRub<1||amountRub>1000000||
     !['TRC20','BEP20'].includes(network)){
    return bad(r,400,'Укажи целую сумму от 1 до 1 000 000 ₽ и сеть USDT');
  }
  const isTron=network==='TRC20';
  if(isTron?!tronGridKey:!bscRpcUrl||Date.now()-bscLastHealthyAt>90000){
    return bad(r,503,'Автопополнение в этой сети сейчас недоступно');
  }
  let client;
  try{
    client=await pool.connect();
    await client.query('BEGIN');
    const settings=await client.query('SELECT rate_kopecks,trc20_address,bep20_address FROM usdt_settings WHERE id=1');
    const config=settings.rows[0];
    const rate=Number(config?.rate_kopecks);
    const address=isTron?config?.trc20_address:config?.bep20_address?.toLowerCase();
    if(!Number.isSafeInteger(rate)||rate<1||!validUsdtAddress(network,address)){
      await client.query('ROLLBACK');
      return bad(r,409,'Кошелёк этой сети ещё не настроен');
    }
    const promo=await paymentPromo(client,q.body,'topup',amountRub);
    const amountCents=Math.ceil(amountRub*10000/rate);
    const exact=await allocateAutomaticAmount(client,network,address,amountCents);
    if(!exact){
      await client.query('ROLLBACK');
      return bad(r,409,'Не удалось выделить уникальную сумму USDT');
    }
    const x=await client.query(`INSERT INTO usdt_orders
      (order_kind,telegram_id,items,total_rub,rate_kopecks,amount_cents,network,wallet_address,
       tron_amount_units,tron_expires_at,bsc_amount_units,bsc_expires_at,promo_code_id,promo_rub)
      VALUES('topup',$1,'[]'::jsonb,$2,$3,$4,$5,$6,
        $7::bigint,CASE WHEN $7::bigint IS NOT NULL THEN NOW()+INTERVAL '30 minutes' END,
        $8::bigint,CASE WHEN $8::bigint IS NOT NULL THEN NOW()+INTERVAL '30 minutes' END,$9,$10)
      RETURNING ${topupInvoiceFields}`,
    [q.telegramUser.id,amountRub,rate,amountCents,network,address,isTron?exact:null,isTron?null:exact,promo.id,promo.adjustmentRub]);
    await client.query('COMMIT');
    r.status(201).json(x.rows[0]);
  }catch(error){
    if(client)await client.query('ROLLBACK').catch(()=>{});
    if(error.promoError)return bad(r,409,error.message);
    console.error('Create balance top-up:',error.message);
    bad(r,500,'Не удалось создать счёт на пополнение');
  }finally{if(client)client.release()}
});

app.post('/api/orders/:id/reported',user,async(q,r)=>{
  if(!validId(q.params.id)){
    return bad(r,400,'Неверный номер счёта');
  }

  try{
    const x=await pool.query(
      `UPDATE usdt_orders
       SET status='review',
           reported_at=NOW()
       WHERE id=$1
         AND telegram_id=$2
         AND status='awaiting' AND order_kind='purchase'
       RETURNING id,status,reported_at`,
      [q.params.id,q.telegramUser.id]
    );

    if(!x.rowCount){
      return bad(
        r,409,'Счёт уже отправлен на проверку'
      );
    }

    r.json(x.rows[0]);
  }catch(e){
    console.error('Report USDT payment:',e);
    bad(r,500,'Ошибка отправки на проверку');
  }
});

app.get('/api/admin/orders',admin,async(q,r)=>{
  try{
    const x=await pool.query(
      `SELECT * FROM usdt_orders
       ORDER BY
         CASE WHEN status='review' THEN 0 ELSE 1 END,
         created_at DESC
       LIMIT 200`
    );

    r.set('Cache-Control','no-store');
    r.json(x.rows);
  }catch(e){
    console.error('Admin USDT orders:',e);
    bad(r,500,'Ошибка списка платежей');
  }
});

app.post('/api/admin/orders/:id/review',admin,async(q,r)=>{
  const status=q.body?.status;
  const tronTxid=validTronTxid(q.body?.txid)?q.body.txid.toLowerCase():null;
  const bscTxid=validBscTxid(q.body?.txid)?q.body.txid.toLowerCase():null;

  if(
    !validId(q.params.id)||
    !['paid','rejected'].includes(status)||
    q.body?.confirmed!==true
  ){
    return bad(r,400,'Подтверди решение');
  }

  try{
    const x=await pool.query(
      `UPDATE usdt_orders
       SET status=$1,
           reviewed_at=NOW(),
           reviewed_by=$2,
           tron_txid=CASE WHEN tron_amount_units IS NOT NULL AND $1='paid' THEN $4::text ELSE tron_txid END,
           bsc_txid=CASE WHEN bsc_amount_units IS NOT NULL AND $1='paid' THEN $5::text ELSE bsc_txid END
       WHERE id=$3
         AND status='review' AND order_kind='purchase'
         AND (tron_amount_units IS NULL OR $1<>'paid' OR $4::text IS NOT NULL)
         AND (bsc_amount_units IS NULL OR $1<>'paid' OR $5::text IS NOT NULL)
       RETURNING id,status,reviewed_at`,
      [
        status,
        q.admin.id,
        q.params.id,
        tronTxid,
        bscTxid
      ]
    );

    if(!x.rowCount){
      return bad(r,409,'Платёж уже обработан или требуется хеш перевода в правильной сети');
    }

    r.json(x.rows[0]);
  }catch(e){
    if(e.code==='23505'&&['usdt_orders_tron_txid_unique','usdt_orders_bsc_txid_unique'].includes(e.constraint)){
      return bad(r,409,'Этот перевод уже использован');
    }
    console.error('Review USDT payment:',e);
    bad(r,500,'Ошибка подтверждения платежа');
  }
});

/* Вывод оплаченных скинов */

function parseSteamTradeUrl(raw){
  if(
    typeof raw!=='string'||
    raw.length>500
  ){
    return null;
  }

  try{
    const u=new URL(raw.trim());

    if(
      u.protocol!=='https:'||
      u.hostname!=='steamcommunity.com'||
      ![
        '/tradeoffer/new',
        '/tradeoffer/new/'
      ].includes(u.pathname)
    ){
      return null;
    }

    const partner=u.searchParams.get('partner');
    const token=u.searchParams.get('token');

    if(
      !/^\d{1,20}$/.test(partner||'')||
      !/^[A-Za-z0-9_-]{5,100}$/.test(token||'')
    ){
      return null;
    }

    return 'https://steamcommunity.com/tradeoffer/new/?partner='+
      partner+'&token='+token;
  }catch{
    return null;
  }
}

app.post('/api/orders/:id/withdraw',user,async(q,r)=>{
  if(!validId(q.params.id))return bad(r,400,'Неверный заказ');
  const tradeUrl=parseSteamTradeUrl(q.body?.trade_url);
  if(!tradeUrl)return bad(r,400,'Неверная Steam Trade URL');
  const tgUser=q.telegramUser;
  const username=String(tgUser.username||'').slice(0,100);
  const name=[tgUser.first_name,tgUser.last_name].filter(Boolean).join(' ').slice(0,200);
  let client;
  try{
    client=await pool.connect();await client.query('BEGIN');
    const order=await client.query(`SELECT id,telegram_id,items,status FROM usdt_orders WHERE id=$1 AND telegram_id=$2 AND order_kind='purchase' FOR UPDATE`,[q.params.id,tgUser.id]);
    if(!order.rowCount){await client.query('ROLLBACK');return bad(r,404,'Заказ не найден')}
    if(order.rows[0].status!=='paid'){await client.query('ROLLBACK');return bad(r,409,'Оплата ещё не подтверждена')}
    const items=Array.isArray(order.rows[0].items)?order.rows[0].items:[];
    const supplierItems=items.filter(x=>x.source_type==='SUPPLIER'&&x.supplier_code==='BUYCS2');
    const ownItems=items.filter(x=>x.source_type!=='SUPPLIER');
    for(const item of supplierItems){
      if(!item.product_id||!item.supplier_market_hash_name||!Number(item.supplier_cost_usd_cents))continue;
      const externalId=`rezzkiy_order_${order.rows[0].id}_product_${item.product_id}`;
      await client.query(`INSERT INTO supplier_fulfillments(order_id,product_id,external_id,market_hash_name,max_price_usd_cents,trade_url,status)
        VALUES($1,$2,$3,$4,$5,$6,'QUEUED') ON CONFLICT(order_id,product_id) DO UPDATE SET
          trade_url=EXCLUDED.trade_url,status=CASE WHEN supplier_fulfillments.status='FAILED' THEN 'QUEUED' ELSE supplier_fulfillments.status END,updated_at=NOW()`,
        [order.rows[0].id,item.product_id,externalId,item.supplier_market_hash_name,Number(item.supplier_cost_usd_cents),tradeUrl]);
    }
    let manualCreated=false;
    if(ownItems.length){
      const created=await client.query(`INSERT INTO skin_withdrawals(order_id,telegram_id,telegram_username,telegram_name,trade_url,items)
        VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(order_id) DO NOTHING RETURNING id,status`,
        [order.rows[0].id,tgUser.id,username,name,tradeUrl,JSON.stringify(ownItems)]);
      manualCreated=created.rowCount>0;
    }
    await client.query('COMMIT');
    if(supplierItems.length)processBuycs2Fulfillments(order.rows[0].id).catch(e=>console.error('Async BuyCS2:',e));
    r.status(201).json({ok:true,automaticCount:supplierItems.length,manualCount:ownItems.length,manualCreated});
  }catch(e){if(client)try{await client.query('ROLLBACK')}catch{};console.error('Withdraw:',e);bad(r,500,'Не удалось запустить выдачу')}
  finally{if(client)client.release()}
});

app.post('/api/orders/:id/supplier-retry',user,async(q,r)=>{
  if(!validId(q.params.id))return bad(r,400,'Неверный заказ');
  try{
    const own=await pool.query(`SELECT id FROM usdt_orders WHERE id=$1 AND telegram_id=$2 AND status='paid' AND order_kind='purchase'`,[q.params.id,q.telegramUser.id]);
    if(!own.rowCount)return bad(r,404,'Оплаченный заказ не найден');
    const x=await pool.query(`UPDATE supplier_fulfillments SET status='QUEUED',fail_reason=NULL,error_code=NULL,updated_at=NOW()
      WHERE order_id=$1 AND status IN ('FAILED','CANCELLED','EXPIRED') RETURNING id`,[q.params.id]);
    if(!x.rowCount)return bad(r,409,'Нет сделок для повторного запуска');
    processBuycs2Fulfillments(q.params.id).catch(e=>console.error('Retry BuyCS2:',e));
    r.json({queued:x.rowCount});
  }catch(e){console.error('Retry supplier:',e);bad(r,500,'Не удалось повторить автодоставку')}
});

app.get('/api/admin/withdrawals',admin,async(q,r)=>{
  try{
    const x=await pool.query(
      `SELECT w.*,o.total_rub
       FROM skin_withdrawals w
       JOIN usdt_orders o
         ON o.id=w.order_id
       ORDER BY
         CASE WHEN w.status='pending' THEN 0 ELSE 1 END,
         w.created_at DESC
       LIMIT 200`
    );

    r.set('Cache-Control','no-store');
    r.json(x.rows);
  }catch(e){
    console.error(e);
    bad(r,500,'Ошибка заявок на вывод');
  }
});

app.post('/api/admin/withdrawals/:id/sent',admin,async(q,r)=>{
  if(
    !validId(q.params.id)||
    q.body?.confirmed!==true
  ){
    return bad(r,400,'Подтверди отправку');
  }

  try{
    const x=await pool.query(
      `UPDATE skin_withdrawals
       SET status='sent',
           sent_at=NOW(),
           sent_by=$1
       WHERE id=$2
         AND status='pending'
       RETURNING id,status,sent_at`,
      [
        q.admin.id,
        q.params.id
      ]
    );

    if(!x.rowCount){
      return bad(
        r,409,'Заявка уже обработана'
      );
    }

    r.json(x.rows[0]);
  }catch(e){
    console.error(e);
    bad(r,500,'Ошибка подтверждения отправки');
  }
});

/*
  Постоянная корзина пользователя.
  Данные хранятся в PostgreSQL.
*/

app.get('/api/cart',user,async(q,r)=>{
  try{
    const x=await pool.query(
      `SELECT items,updated_at
       FROM user_carts
       WHERE telegram_id=$1`,
      [q.telegramUser.id]
    );

    r.set('Cache-Control','no-store');

    r.json({
      items:x.rows[0]?.items||[],
      updated_at:x.rows[0]?.updated_at||null
    });
  }catch(e){
    console.error('Load cart:',e);
    bad(r,500,'Не удалось загрузить корзину');
  }
});

app.put('/api/cart',user,async(q,r)=>{
  const items=q.body?.items;

  if(
    !Array.isArray(items)||
    items.length>100||
    items.some(id=>!validId(id))
  ){
    return bad(r,400,'Некорректная корзина');
  }

  const normalized=items.map(String);

  try{
    const x=await pool.query(
      `INSERT INTO user_carts(
        telegram_id,
        items,
        updated_at
      )
      VALUES($1,$2::jsonb,NOW())
      ON CONFLICT(telegram_id)
      DO UPDATE SET
        items=EXCLUDED.items,
        updated_at=NOW()
      RETURNING items,updated_at`,
      [
        q.telegramUser.id,
        JSON.stringify(normalized)
      ]
    );

    r.set('Cache-Control','no-store');

    r.json({
      success:true,
      items:x.rows[0].items,
      updated_at:x.rows[0].updated_at
    });
  }catch(e){
    console.error('Save cart:',e);
    bad(r,500,'Не удалось сохранить корзину');
  }
});

/*
  История заказов покупателя.
  Каждый пользователь видит только свои заказы.
*/

app.get('/api/orders/my',user,async(q,r)=>{
  try{
    const x=await pool.query(
      `SELECT
        id,
        items,
        total_rub,
        rate_kopecks,
        amount_cents,
        network,
        wallet_address,
        status,
        created_at,
        tron_amount_units,
        tron_expires_at,
        bsc_amount_units,
        bsc_expires_at,
        reported_at,
        reviewed_at,
        (SELECT status
         FROM skin_withdrawals w
         WHERE w.order_id=usdt_orders.id)
         AS withdrawal_status,
         COALESCE((SELECT jsonb_agg(jsonb_build_object(
           'status',sf.status,'tradeId',sf.trade_id,'offerId',sf.offer_id,'failReason',sf.fail_reason,
           'market_hash_name',sf.market_hash_name,'updatedAt',sf.updated_at) ORDER BY sf.id)
           FROM supplier_fulfillments sf WHERE sf.order_id=usdt_orders.id),'[]'::jsonb) AS supplier_fulfillments
       FROM usdt_orders
       WHERE telegram_id=$1 AND order_kind='purchase'
       ORDER BY created_at DESC
       LIMIT 100`,
      [q.telegramUser.id]
    );

    r.set('Cache-Control','no-store');

    r.json({
      orders:x.rows,
      count:x.rowCount
    });
  }catch(e){
    console.error('Order history:',e);
    bad(r,500,'Не удалось загрузить историю заказов');
  }
});

/*
  Запуск Telegram Mini App.
*/

app.get('/rules',(_q,r)=>{
  r.set('Cache-Control','public, max-age=300');
  r.sendFile(path.join(DIR,'rules.html'));
});

app.use(express.static(DIR));

app.get('/',(_q,r)=>{
  r.sendFile(
    path.join(DIR,'index.html')
  );
});

async function start(){
  for(const v of [
    'DATABASE_URL',
    'BOT_TOKEN',
    'ADMIN_TELEGRAM_ID',
    'PAYMENT_DATA_KEY'
  ]){
    if(!process.env[v]){
      throw Error(
        'Не задана переменная '+v
      );
    }
  }

  key();

  await initDb();

  app.listen(
    PORT,
    '0.0.0.0',
    ()=>{
      console.log(
        'REZZKIY MARKET port '+PORT
      );
      startTronPaymentWatcher();
      startBscPaymentWatcher();
    }
  );
}

start().catch(e=>{
  console.error(
    'Startup:',
    e.message
  );
  process.exit(1);
});
