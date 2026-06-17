import pg from 'pg';
const { Pool } = pg;

const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'psoc001db',
  user: 'soc',
  password: '123456',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[DB] Unexpected pool error:', err);
});

const query = (text, params) => pool.query(text, params);

const getClient = () => pool.connect();

const CREATE_TABLES = `
  CREATE TABLE IF NOT EXISTS ice_rule (
    id VARCHAR PRIMARY KEY,
    name TEXT,
    description TEXT,
    advice TEXT,
    xdr_rule_type VARCHAR DEFAULT 'xdr',
    scene_type VARCHAR,
    notification TEXT,
    notifier TEXT,
    status VARCHAR DEFAULT 'stopped',
    source VARCHAR,
    statement TEXT,
    raw TEXT,
    system BOOLEAN DEFAULT false,
    logic_delete BOOLEAN DEFAULT false,
    version INT DEFAULT 1,
    user_name TEXT,
    create_time TIMESTAMP DEFAULT NOW(),
    update_time TIMESTAMP DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS attack_scene (
    id VARCHAR PRIMARY KEY,
    parent_id VARCHAR,
    name TEXT,
    id_path TEXT,
    scene_type VARCHAR,
    scene_model VARCHAR,
    description TEXT
  );

  CREATE TABLE IF NOT EXISTS ice_analysis_task (
    id VARCHAR PRIMARY KEY,
    name TEXT,
    description TEXT,
    notifier TEXT,
    status INT DEFAULT 0,
    relative_rules TEXT,
    relative_ids TEXT,
    relative_type INT DEFAULT 0,
    finish_ids TEXT,
    progress INT DEFAULT 0,
    user_id TEXT,
    create_time TIMESTAMP DEFAULT NOW(),
    update_time TIMESTAMP DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    action VARCHAR,
    target_type VARCHAR,
    target_id VARCHAR,
    detail TEXT,
    user_name TEXT,
    ip_address VARCHAR,
    create_time TIMESTAMP DEFAULT NOW()
  );
`;

const SEED_ATTACK_SCENES = `
  INSERT INTO attack_scene (id, parent_id, name, id_path, scene_type, scene_model, description) VALUES
    ('scan', NULL, '扫描探测', 'scan', 'scan', NULL, '探测资产存在的端口、服务、漏洞等安全风险信息'),
    ('host-abnormal', NULL, '主机异常', 'host-abnormal', 'host-abnormal', NULL, '主机层面的异常行为，包括暴力破解、异常进程、异常登录等'),
    ('abnormal-comm', NULL, '异常通信', 'abnormal-comm', 'abnormal-comm', NULL, '网络通信异常，包括C2通信、隧道、异常外联等'),
    ('vuln-attack', NULL, '漏洞攻击', 'vuln-attack', 'vuln-attack', NULL, '利用已知漏洞进行的攻击行为'),
    ('remote-control', NULL, '远程控制', 'remote-control', 'remote-control', NULL, '远程控制工具的检测，包括RDP、SSH、VNC等远程访问'),
    ('web-attack', NULL, 'Web攻击', 'web-attack', 'web-attack', NULL, '针对Web应用的攻击，包括SQL注入、XSS、文件上传等'),
    ('network-attack', NULL, '网络攻击', 'network-attack', 'network-attack', NULL, '网络层攻击，包括DDoS、ARP欺骗、DNS攻击等'),
    ('account-abnormal', NULL, '账号异常', 'account-abnormal', 'account-abnormal', NULL, '账号层面的异常，包括异常登录、权限变更、暴力破解等'),
    ('threat-intel', NULL, '威胁情报', 'threat-intel', 'threat-intel', NULL, '基于威胁情报的攻击检测，包括恶意IP、域名、文件哈希等'),
    ('mail-attack', NULL, '邮件攻击', 'mail-attack', 'mail-attack', NULL, '邮件层面的攻击，包括钓鱼邮件、恶意附件、BEC等'),
    ('multi-correlation', NULL, '多源关联', 'multi-correlation', 'multi-correlation', NULL, '通过多源数据关联分析发现的复杂攻击'),
    ('content-security', NULL, '内容安全', 'content-security', 'content-security', NULL, '内容安全检测，包括敏感信息泄露、违规内容等'),
    ('malware', NULL, '恶意软件', 'malware', 'malware', NULL, '恶意软件检测，包括木马、蠕虫、勒索软件等')
  ON CONFLICT (id) DO NOTHING;
`;

async function seedAttackScenes(client) {
  const { rows } = await client.query('SELECT COUNT(*)::int AS cnt FROM attack_scene');
  if (rows[0].cnt === 0) {
    await client.query(SEED_ATTACK_SCENES);
    console.log('[DB] Seeded 13 attack scenes');
  } else {
    console.log(`[DB] attack_scene table already has ${rows[0].cnt} rows, skipping seed`);
  }
}

async function initDb() {
  const client = await pool.connect();
  try {
    console.log('[DB] Initializing database schema...');
    await client.query(CREATE_TABLES);
    console.log('[DB] Tables created/verified');

    await seedAttackScenes(client);

    console.log('[DB] Database initialization complete');
  } catch (err) {
    console.error('[DB] Initialization failed:', err);
    throw err;
  } finally {
    client.release();
  }
}

export { pool, initDb, query, getClient };
