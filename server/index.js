// =============================================================================
// event-security/server/index.js
// HTTP API server integrating with PostgreSQL, Elasticsearch, Redis, Kafka.
// Port 4173 · Host 127.0.0.1
// =============================================================================

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { validateDsl as validateDslAdvanced, compileToStatement } from './services/dsl.js';

import { initDb, query } from './db.js';
import { initEs, searchIndex, indexDocument } from './es.js';
import redisClient from './redis.js';
import { ensureTopics } from './kafka.js';
import { startAggregator } from './services/aggregator.js';
import { startSearcher } from './services/searcher.js';

// ── Paths & config ──────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const publicDir = path.join(rootDir, 'public');
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || '127.0.0.1';

// ── Reference Data ─────────────────────────────────────────────────────────

const dictionaries = {
  severities: [
    { value: 'critical', label: '紧急', level: 4 },
    { value: 'high', label: '严重', level: 3 },
    { value: 'medium', label: '警告', level: 2 },
    { value: 'low', label: '提醒', level: 1 }
  ],
  modelStatuses: [
    { value: 'running', label: '运行' },
    { value: 'stopped', label: '停用' }
  ],
  modelSources: [
    { value: 'custom', label: '自定义模型' },
    { value: 'system', label: '系统内置' },
    { value: 'imported', label: '导入模型' }
  ],
  attackResults: [
    { value: 'success', label: '攻击成功' },
    { value: 'failed', label: '攻击失败' },
    { value: 'unknown', label: '未知' }
  ]
};

const defaultDsl = `processList:\n  - condition: 主机IP = \"\${主机IP}\" and 文件MD5 = \"\${文件MD5}\"\n    source: \"告警\"\n    time: [\"-5h\", \"1h\"]\n    relationship: \"相同的病毒\"\n  - condition: 目的地址 = \"\${源地址}\" or 主机IP = \"\${主机IP}\"\n    source: \"日志\"\n    time: [\"-1h\", \"12h\"]\n    relationship: \"相同的受害者地址\"`;

const tableFields = [
  { key: 'id', label: '编号', visible: true },
  { key: 'title', label: '标题', visible: true },
  { key: 'severityLabel', label: '严重等级', visible: true },
  { key: 'attackResultLabel', label: '攻击结果', visible: true },
  { key: 'category', label: '分类', visible: false },
  { key: 'dataSource', label: '数据源', visible: false },
  { key: 'entities', label: '影响实体', visible: true },
  { key: 'organization', label: '组织机构', visible: true },
  { key: 'updatedAt', label: '更新时间', visible: true }
];

// ── Helpers ─────────────────────────────────────────────────────────────────

const json = (res, status, data) => {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
};

const parseBody = async (req) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
};

const getSeverity = (severity) =>
  dictionaries.severities.find((item) => item.value === severity);

// ── Audit logging ───────────────────────────────────────────────────────────

const AUDIT_ACTIONS = {
  CREATE: 'create',
  UPDATE: 'update',
  DELETE: 'delete',
  IMPORT: 'import',
  ENABLE: 'enable',
  DISABLE: 'disable',
};

async function insertAuditLog({ action, targetType, targetId, detail, userName, ipAddress }) {
  try {
    await query(
      `INSERT INTO audit_log (action, target_type, target_id, detail, user_name, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [action, targetType, targetId || '', detail || '', userName || 'system', ipAddress || '']
    );
  } catch (err) {
    console.error('[audit] insertAuditLog error:', err.message);
  }
}

// ── PG helpers: attack scenes ───────────────────────────────────────────────

async function getAttackScenesFromDb() {
  const { rows } = await query('SELECT id, parent_id AS "parentId", name, scene_type AS "sceneType", scene_model AS "sceneModel" FROM attack_scene ORDER BY id');
  return rows;
}

async function getAttackSceneById(sceneId) {
  const { rows } = await query('SELECT id, parent_id AS "parentId", name, scene_type AS "sceneType", scene_model AS "sceneModel" FROM attack_scene WHERE id = $1', [sceneId]);
  return rows[0] || null;
}

// ── PG helpers: models (ice_rule) ───────────────────────────────────────────

/**
 * Map a PG ice_rule row to the API model shape.
 */
function mapRuleToModel(row) {
  let entryAlerts = [];
  try { entryAlerts = row.raw ? JSON.parse(row.raw) : []; } catch { /* ignore */ }

  return {
    id: row.id,
    name: row.name || '',
    description: row.description || '',
    sceneId: row.scene_type || '',
    sceneName: '', // will be resolved separately if needed
    source: row.source || 'custom',
    sourceLabel: row.system ? '系统内置' : (row.source === 'imported' ? '导入模型' : '自定义模型'),
    status: row.status || 'stopped',
    entryAlerts,
    dsl: row.statement || '',
    active: row.status === 'running',
    notifier: row.notifier || '',
    useEntryAlertNameAsTitle: false,
    advice: row.advice || '',
    updatedAt: row.update_time
      ? new Date(row.update_time).toISOString().slice(0, 19).replace('T', ' ')
      : '',
    version: row.version || 1,
    history: [] // populated separately
  };
}

/**
 * Map an API model body to PG ice_rule columns for INSERT.
 */
function mapBodyToRuleInsert(body, id) {
  return {
    id,
    name: body.name || '',
    description: body.description || '',
    advice: body.advice || '',
    scene_type: body.sceneId || null,
    notifier: body.notifier || '',
    status: body.active !== undefined ? (body.active ? 'running' : 'stopped') : 'stopped',
    source: body.source || 'custom',
    statement: body.dsl || '',
    raw: JSON.stringify(body.entryAlerts || []),
    system: false,
    logic_delete: false,
    version: 1,
  };
}

/**
 * Map an API model body to PG ice_rule columns for UPDATE.
 */
function mapBodyToRuleUpdate(body) {
  const sets = [];
  const vals = [];
  let idx = 1;

  const push = (col, val) => {
    sets.push(`${col} = $${idx++}`);
    vals.push(val);
  };

  if (body.name !== undefined) push('name', body.name);
  if (body.description !== undefined) push('description', body.description);
  if (body.advice !== undefined) push('advice', body.advice);
  if (body.sceneId !== undefined) push('scene_type', body.sceneId);
  if (body.notifier !== undefined) push('notifier', body.notifier);
  if (body.active !== undefined) push('status', body.active ? 'running' : 'stopped');
  if (body.source !== undefined) push('source', body.source);
  if (body.dsl !== undefined) push('statement', body.dsl);
  if (body.entryAlerts !== undefined) push('raw', JSON.stringify(body.entryAlerts));

  push('update_time', 'NOW()');

  // Bump version on update
  sets.push(`version = version + 1`);

  return { sets, vals };
}

async function listModelsFromDb(filters) {
  const conditions = ['logic_delete = false'];
  const params = [];
  let idx = 1;

  if (filters.sceneId) {
    conditions.push(`scene_type = $${idx++}`);
    params.push(filters.sceneId);
  }
  if (filters.status) {
    conditions.push(`status = $${idx++}`);
    params.push(filters.status);
  }
  if (filters.source) {
    conditions.push(`source = $${idx++}`);
    params.push(filters.source);
  }
  if (filters.keyword) {
    conditions.push(`(name ILIKE $${idx} OR description ILIKE $${idx})`);
    params.push(`%${filters.keyword}%`);
    idx++;
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const { rows } = await query(`SELECT * FROM ice_rule ${where} ORDER BY update_time DESC`, params);
  return rows.map(mapRuleToModel);
}

async function getModelFromDb(id) {
  const { rows } = await query('SELECT * FROM ice_rule WHERE id = $1 AND logic_delete = false', [id]);
  return rows[0] ? mapRuleToModel(rows[0]) : null;
}

async function getModelHistoryFromDb(id) {
  // Use ice_analysis_task for history, falling back to version-based history
  try {
    const { rows } = await query(
      `SELECT name, description, create_time AS time, status
       FROM ice_analysis_task
       WHERE relative_ids LIKE $1
       ORDER BY create_time DESC`,
      [`%${id}%`]
    );
    if (rows.length > 0) {
      return rows.map((r) => ({
        time: r.time ? new Date(r.time).toISOString().slice(0, 19).replace('T', ' ') : '',
        content: r.name || r.description || '任务'
      }));
    }
  } catch {
    // Table may not have matching rows — fall through to version history
  }

  // Fallback: synthetic version history from the model itself
  const model = await getModelFromDb(id);
  if (!model) return [];
  return model.history && model.history.length > 0
    ? model.history
    : [{ time: model.updatedAt, content: '模型更新' }];
}

// ── Analysis task DB helpers ────────────────────────────────────────────────

function mapTaskToApi(row) {
  return {
    id: row.id,
    name: row.name || '',
    description: row.description || '',
    notifier: row.notifier || '',
    status: row.status,
    progress: row.progress,
    relativeIds: row.relative_ids ? row.relative_ids.split(',').filter(Boolean) : [],
    relativeRules: row.relative_rules ? row.relative_rules.split(',').filter(Boolean) : [],
    relativeType: row.relative_type,
    finishIds: row.finish_ids ? row.finish_ids.split(',').filter(Boolean) : [],
    userId: row.user_id || '',
    createTime: row.create_time ? new Date(row.create_time).toISOString().slice(0, 19).replace('T', ' ') : '',
    updateTime: row.update_time ? new Date(row.update_time).toISOString().slice(0, 19).replace('T', ' ') : '',
  };
}

// ── DSL validation helper ───────────────────────────────────────────────────

function validateDsl(dsl) {
  return Boolean(dsl && dsl.includes('processList'));
}

// ── Static file server ─────────────────────────────────────────────────────

const sendStatic = (req, res, pathname) => {
  const relativePath = pathname === '/' ? 'index.html' : pathname.slice(1);
  const filePath = path.normalize(path.join(publicDir, relativePath));
  if (!filePath.startsWith(publicDir)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }
  const ext = path.extname(filePath);
  const types = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.svg': 'image/svg+xml'
  };
  res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
  fs.createReadStream(filePath).pipe(res);
};

// ── ES-backed incident helpers ──────────────────────────────────────────────

const ATTACK_RESULT_MAP = {
  success: '攻击成功', failed: '攻击失败', unknown: '未知',
  '攻击成功': '攻击成功', '攻击失败': '攻击失败', '未知': '未知',
};
const SEVERITY_LABEL_MAP = {
  critical: '紧急', high: '严重', medium: '警告', low: '提醒',
  '紧急': '紧急', '严重': '严重', '警告': '警告', '提醒': '提醒',
};

/**
 * Map an ES incident document to the shape the frontend expects.
 */
function mapIncidentToFrontend(doc) {
  const attackerCount = (doc.attacker_array || []).length;
  const victimCount = (doc.victim_array || []).length;
  const relatedAlerts = doc.related_alerts || [];
  // Deduplicate hosts/accounts from related alerts
  const hosts = new Set();
  const accounts = new Set();
  for (const a of relatedAlerts) {
    if (a.host || a.hostname) hosts.add(a.host || a.hostname);
    if (a.account || a.user) accounts.add(a.account || a.user);
  }

  const severity = doc.severity || 'unknown';
  const attackResult = doc.attack_result || 'unknown';

  return {
    id: doc.id,
    title: doc.title || '未命名事件',
    severity,
    severityLabel: SEVERITY_LABEL_MAP[severity] || severity,
    attackResult,
    attackResultLabel: ATTACK_RESULT_MAP[attackResult] || attackResult,
    category: doc.scene_type || '',
    dataSource: doc.data_source || '',
    organization: doc.organization || '',
    updatedAt: doc.update_time || doc.end_time || '',
    startTime: doc.start_time || '',
    endTime: doc.end_time || '',
    owner: doc.owner || '-',
    device: (doc.victim_array && doc.victim_array[0]?.ip) || '-',
    modelId: doc.ice_rule_id || null,
    modelName: doc.model_name || '',
    advice: doc.advice || '',
    relatedLogIds: [],
    entities: { ip: attackerCount + victimCount, host: hosts.size, account: accounts.size },
    // Attach raw data for detail views
    alerts: relatedAlerts,
    graph: doc.graph || { nodes: [], edges: [] },
    entities_raw: doc.entities || { hosts: [], ips: [], accounts: [], files: [] },
    attacker_array: doc.attacker_array || [],
    victim_array: doc.victim_array || [],
    priority: doc.priority || 0,
  };
}

/**
 * Query ES for incidents with optional keyword/severity filtering.
 * Returns { items, total, stats } in the format the frontend expects.
 */
async function listIncidentsFromEs(queryParams) {
  const must = [];
  const filter = [];

  if (queryParams.keyword) {
    must.push({
      bool: {
        should: [
          { match: { title: { query: queryParams.keyword, boost: 2 } } },
          { match: { id: { query: queryParams.keyword, boost: 1 } } },
        ],
      },
    });
  }
  if (queryParams.severity) {
    filter.push({ term: { severity: queryParams.severity } });
  }

  const body = {
    query: must.length || filter.length
      ? { bool: { must: must.length ? must : [{ match_all: {} }], filter } }
      : { match_all: {} },
    sort: [{ update_time: { order: 'desc' } }],
    size: 200,
  };

  const result = await searchIndex('incident-index', body);
  const hits = result.hits?.hits || [];
  const items = hits.map((h) => mapIncidentToFrontend(h._source));

  // Compute severity stats
  const stats = { total: items.length, critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of items) {
    if (stats[item.severity] !== undefined) stats[item.severity]++;
  }

  return { items, total: items.length, stats };
}

/**
 * Get a single incident from ES by ID, mapped to frontend shape.
 */
async function getIncidentFromEs(id) {
  const result = await searchIndex('incident-index', {
    query: { term: { id } },
    size: 1,
  });
  const hit = result.hits?.hits?.[0];
  if (!hit) return null;
  return mapIncidentToFrontend(hit._source);
}

// =============================================================================
// ROUTER
// =============================================================================

const router = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const urlQuery = Object.fromEntries(url.searchParams.entries());
  const method = req.method;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

  try {
    // ── M20: Audit Logs ────────────────────────────────────────────────────
    if (pathname === '/api/security/audit-logs' && method === 'GET') {
      const page = Math.max(1, parseInt(urlQuery.page || '1', 10));
      const pageSize = Math.min(100, Math.max(1, parseInt(urlQuery.pageSize || '20', 10)));
      const offset = (page - 1) * pageSize;

      const conditions = [];
      const params = [];
      let idx = 1;

      if (urlQuery.action) {
        conditions.push(`action = $${idx++}`);
        params.push(urlQuery.action);
      }
      if (urlQuery.targetType) {
        conditions.push(`target_type = $${idx++}`);
        params.push(urlQuery.targetType);
      }
      if (urlQuery.targetId) {
        conditions.push(`target_id = $${idx++}`);
        params.push(urlQuery.targetId);
      }

      const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

      const countResult = await query(`SELECT COUNT(*)::int AS total FROM audit_log ${where}`, params);
      const total = countResult.rows[0]?.total || 0;

      params.push(pageSize);
      params.push(offset);
      const { rows } = await query(
        `SELECT id, action, target_type AS "targetType", target_id AS "targetId",
                detail, user_name AS "userName", ip_address AS "ipAddress",
                create_time AS "createTime"
         FROM audit_log ${where}
         ORDER BY id DESC
         LIMIT $${idx++} OFFSET $${idx++}`,
        params
      );

      return json(res, 200, { items: rows, total, page, pageSize });
    }

    // ── M19: Export model ──────────────────────────────────────────────────
    if (pathname === '/api/security/models/export' && method === 'GET') {
      const modelId = urlQuery.id;
      if (!modelId) return json(res, 400, { message: '缺少模型 id 参数' });

      const model = await getModelFromDb(modelId);
      if (!model) return json(res, 404, { message: '模型不存在' });

      const exportPayload = JSON.stringify(model, null, 2);
      const filename = `model-${modelId}.json`;
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Length': Buffer.byteLength(exportPayload)
      });
      return res.end(exportPayload);
    }

    // ── M19: Import model ──────────────────────────────────────────────────
    if (pathname === '/api/security/models/import' && method === 'POST') {
      const body = await parseBody(req);

      // Validate required fields
      if (!body.name) return json(res, 400, { message: '缺少模型名称' });
      if (!validateDsl(body.dsl)) return json(res, 400, { message: 'DSL 必须包含 processList' });

      const id = randomUUID();
      const rule = mapBodyToRuleInsert({ ...body, source: 'imported' }, id);

      await query(
        `INSERT INTO ice_rule (id, name, description, advice, scene_type, notifier, status, source, statement, raw, system, logic_delete, version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [rule.id, rule.name, rule.description, rule.advice, rule.scene_type, rule.notifier, rule.status, rule.source, rule.statement, rule.raw, rule.system, rule.logic_delete, rule.version]
      );

      const scene = body.sceneId ? await getAttackSceneById(body.sceneId) : null;
      const model = mapRuleToModel(rule);
      model.sceneName = scene?.name || '';
      model.history = [{ time: model.updatedAt || new Date().toISOString().slice(0, 19).replace('T', ' '), content: '模型导入' }];

      await insertAuditLog({
        action: AUDIT_ACTIONS.IMPORT,
        targetType: 'model',
        targetId: id,
        detail: `导入模型: ${rule.name}`,
        ipAddress: clientIp
      });

      return json(res, 201, model);
    }

    // ── M3: Dictionaries ───────────────────────────────────────────────────
    if (pathname === '/api/security/dictionaries' && method === 'GET') {
      return json(res, 200, dictionaries);
    }

    // ── M3: Attack scenes (from PG) ───────────────────────────────────────
    if (pathname === '/api/security/attack-scenes/tree' && method === 'GET') {
      const scenes = await getAttackScenesFromDb();
      return json(res, 200, scenes);
    }

    // ── M3: List models (from PG) ─────────────────────────────────────────
    if (pathname === '/api/security/models' && method === 'GET') {
      const items = await listModelsFromDb(urlQuery);
      // Resolve scene names
      for (const item of items) {
        if (item.sceneId) {
          const scene = await getAttackSceneById(item.sceneId);
          item.sceneName = scene?.name || '';
        }
      }
      return json(res, 200, { items, total: items.length });
    }

    // ── M4: Create model (to PG) ──────────────────────────────────────────
    if (pathname === '/api/security/models' && method === 'POST') {
      const body = await parseBody(req);

      if (!body.name) return json(res, 400, { message: '缺少模型名称' });
      if (!validateDsl(body.dsl)) return json(res, 400, { message: 'DSL 必须包含 processList' });

      const id = randomUUID();
      const rule = mapBodyToRuleInsert(body, id);

      await query(
        `INSERT INTO ice_rule (id, name, description, advice, scene_type, notifier, status, source, statement, raw, system, logic_delete, version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [rule.id, rule.name, rule.description, rule.advice, rule.scene_type, rule.notifier, rule.status, rule.source, rule.statement, rule.raw, rule.system, rule.logic_delete, rule.version]
      );

      const scene = body.sceneId ? await getAttackSceneById(body.sceneId) : null;
      const model = mapRuleToModel(rule);
      model.sceneName = scene?.name || '';
      model.history = [{ time: model.updatedAt || new Date().toISOString().slice(0, 19).replace('T', ' '), content: '模型创建' }];

      await insertAuditLog({
        action: AUDIT_ACTIONS.CREATE,
        targetType: 'model',
        targetId: id,
        detail: `创建模型: ${rule.name}`,
        ipAddress: clientIp
      });

      return json(res, 201, model);
    }

    // ── M3/M4: Model by ID (GET / PUT / DELETE) ────────────────────────────
    const modelMatch = pathname.match(/^\/api\/security\/models\/([^/]+)$/);

    if (modelMatch && !['enable', 'disable', 'history', 'validate', 'export', 'import'].includes(modelMatch[1])) {
      const modelId = modelMatch[1];

      if (method === 'GET') {
        const model = await getModelFromDb(modelId);
        if (!model) return json(res, 404, { message: '模型不存在' });
        if (model.sceneId) {
          const scene = await getAttackSceneById(model.sceneId);
          model.sceneName = scene?.name || '';
        }
        return json(res, 200, model);
      }

      if (method === 'PUT') {
        const body = await parseBody(req);
        const existing = await getModelFromDb(modelId);
        if (!existing) return json(res, 404, { message: '模型不存在' });

        const { sets, vals } = mapBodyToRuleUpdate(body);
        if (sets.length > 1) {
          // sets already includes update_time and version bump
          vals.push(modelId);
          await query(`UPDATE ice_rule SET ${sets.join(', ')} WHERE id = $${vals.length}`, vals);
        }

        const updated = await getModelFromDb(modelId);
        if (updated.sceneId) {
          const scene = await getAttackSceneById(updated.sceneId);
          updated.sceneName = scene?.name || '';
        }

        await insertAuditLog({
          action: AUDIT_ACTIONS.UPDATE,
          targetType: 'model',
          targetId: modelId,
          detail: `更新模型: ${updated.name}`,
          ipAddress: clientIp
        });

        return json(res, 200, updated);
      }

      if (method === 'DELETE') {
        const existing = await getModelFromDb(modelId);
        if (!existing) return json(res, 404, { message: '模型不存在' });

        // Soft delete
        await query(
          'UPDATE ice_rule SET logic_delete = true, update_time = NOW() WHERE id = $1',
          [modelId]
        );

        await insertAuditLog({
          action: AUDIT_ACTIONS.DELETE,
          targetType: 'model',
          targetId: modelId,
          detail: `删除模型: ${existing.name}`,
          ipAddress: clientIp
        });

        return json(res, 200, { ok: true });
      }
    }

    // ── M3/M4: Model actions (enable / disable / history) ─────────────────
    const modelActionMatch = pathname.match(/^\/api\/security\/models\/([^/]+)\/(enable|disable|history)$/);
    if (modelActionMatch) {
      const modelId = modelActionMatch[1];
      const action = modelActionMatch[2];

      const existing = await getModelFromDb(modelId);
      if (!existing) return json(res, 404, { message: '模型不存在' });

      if (action === 'history' && method === 'GET') {
        const history = await getModelHistoryFromDb(modelId);
        return json(res, 200, history);
      }

      if (method === 'POST') {
        const newStatus = action === 'enable' ? 'running' : 'stopped';
        await query(
          'UPDATE ice_rule SET status = $1, update_time = NOW() WHERE id = $2',
          [newStatus, modelId]
        );

        const updated = await getModelFromDb(modelId);
        if (updated.sceneId) {
          const scene = await getAttackSceneById(updated.sceneId);
          updated.sceneName = scene?.name || '';
        }

        await insertAuditLog({
          action: action === 'enable' ? AUDIT_ACTIONS.ENABLE : AUDIT_ACTIONS.DISABLE,
          targetType: 'model',
          targetId: modelId,
          detail: `${action === 'enable' ? '启用' : '停用'}模型: ${existing.name}`,
          ipAddress: clientIp
        });

        return json(res, 200, updated);
      }
    }

    // ── M16: Validate DSL ─────────────────────────────────────────────────
    if (pathname === '/api/security/models/validate' && method === 'POST') {
      const body = await parseBody(req);
      const result = validateDslAdvanced(body.dsl);
      if (result.valid) {
        return json(res, 200, {
          ok: true,
          variables: result.variables,
          stepCount: result.stepCount,
          compiled: result.compiled
        });
      }
      return json(res, 400, { message: result.errors.join('; ') });
    }

    // ── Analysis tasks for incident (list / create) ──────────────────────
    const analysisTasksListMatch = pathname.match(/^\/api\/security\/incidents\/([^/]+)\/analysis-tasks$/);
    if (analysisTasksListMatch) {
      const incidentId = analysisTasksListMatch[1];

      if (method === 'GET') {
        const { rows } = await query(
          `SELECT * FROM ice_analysis_task WHERE ($1 = ANY(string_to_array(relative_ids, ','))) ORDER BY create_time DESC`,
          [incidentId]
        );
        return json(res, 200, { items: rows.map(mapTaskToApi), total: rows.length });
      }

      if (method === 'POST') {
        const body = await parseBody(req);
        const taskId = randomUUID();
        await query(
          `INSERT INTO ice_analysis_task (id, name, description, notifier, status, relative_rules, relative_ids, relative_type, user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [
            taskId,
            body.name || '分析任务',
            body.description || '',
            body.notifier || '',
            0,
            (body.relativeRules || []).join(','),
            [incidentId, ...(body.additionalIds || [])].join(','),
            body.relativeType || 0,
            body.userId || ''
          ]
        );
        const { rows } = await query('SELECT * FROM ice_analysis_task WHERE id = $1', [taskId]);
        return json(res, 201, mapTaskToApi(rows[0]));
      }
    }

    // ── Analysis task for incident (single task status) ───────────────────
    const analysisTaskSingleMatch = pathname.match(/^\/api\/security\/incidents\/([^/]+)\/analysis-tasks\/([^/]+)$/);
    if (analysisTaskSingleMatch && method === 'GET') {
      const taskId = analysisTaskSingleMatch[2];
      const { rows } = await query('SELECT * FROM ice_analysis_task WHERE id = $1', [taskId]);
      if (!rows.length) return json(res, 404, { message: '分析任务不存在' });
      return json(res, 200, mapTaskToApi(rows[0]));
    }

    // ── M3: Incidents (ES-backed) ───────────────────────────────────────
    if (pathname === '/api/security/incidents' && method === 'GET') {
      const data = await listIncidentsFromEs(urlQuery);
      insertAuditLog({ action: 'list', targetType: 'incident', targetId: null, ipAddress: clientIp });
      return json(res, 200, data);
    }

    if (pathname === '/api/security/incidents' && method === 'POST') {
      const body = await parseBody(req);
      const scene = body.sceneId ? await getAttackSceneById(body.sceneId) : null;
      const severity = body.severity || 'low';
      const now = new Date().toISOString();
      const id = `inc-${randomUUID().slice(0, 8)}`;
      const incidentDoc = {
        id,
        title: body.title,
        severity,
        attack_result: 'unknown',
        scene_type: scene?.name || body.sceneId || '',
        ice_rule_id: null,
        data_source: '人工创建',
        organization: '总公司全局',
        advice: body.advice || '',
        start_time: now,
        end_time: now,
        update_time: now,
        attacker_array: [],
        victim_array: [],
        priority: { critical: 4, high: 3, medium: 2, low: 1 }[severity] || 0,
        threat_confidence: 0,
        related_alerts: (body.logIds || []).map((logId) => ({
          id: `manual-${logId}`,
          title: '关联日志',
          severity: '',
          relation: '人工关联',
          core: false,
          entry: true,
          started_at: now,
        })),
        graph: { nodes: [], edges: [] },
        entities: { hosts: [], ips: [], accounts: [], files: [] },
      };
      await indexDocument('incident-index', id, incidentDoc);
      insertAuditLog({ action: 'create', targetType: 'incident', targetId: id, ipAddress: clientIp });
      return json(res, 201, mapIncidentToFrontend(incidentDoc));
    }

    if (pathname === '/api/security/incidents/table-fields' && method === 'GET') {
      return json(res, 200, tableFields);
    }

    const incidentMatch = pathname.match(/^\/api\/security\/incidents\/([^/]+)(?:\/([^/]+))?$/);
    if (incidentMatch && method === 'GET') {
      const incidentId = incidentMatch[1];
      const incident = await getIncidentFromEs(incidentId);
      if (!incident) return json(res, 404, { message: '安全事件不存在' });
      const section = incidentMatch[2];
      if (!section) return json(res, 200, incident);

      if (section === 'overview') {
        const alertCount = incident.alerts.length;
        const coreCount = incident.alerts.filter((a) => a.core).length;
        const entryCount = incident.alerts.filter((a) => a.entry).length;
        return json(res, 200, {
          phases: {
            reconnaissance: alertCount > 0 ? 1 : 0,
            delivery: entryCount > 0 ? 1 : 0,
            installation: coreCount > 0 ? 1 : 0,
            exploitation: 0,
            command: coreCount > 0 ? 1 : 0,
            lateralMovement: 0,
            exfiltration: 0
          },
          phaseLabels: {
            reconnaissance: '侦查',
            delivery: '投递',
            installation: '安装',
            exploitation: '利用',
            command: '命令控制',
            lateralMovement: '横向移动',
            exfiltration: '数据窃取'
          },
          alertCount: alertCount,
          pendingAlertCount: alertCount,
          coreAlertCount: coreCount,
          entryAlertCount: entryCount,
          entities: incident.entities,
          attack: {
            tactics: [
              { id: 'TA0001', name: '初始访问', count: entryCount || 0 },
              { id: 'TA0002', name: '执行', count: coreCount || 0 },
              { id: 'TA0003', name: '持久化', count: 0 },
              { id: 'TA0004', name: '权限提升', count: 0 },
              { id: 'TA0005', name: '防御规避', count: 0 },
              { id: 'TA0006', name: '凭证访问', count: 0 },
              { id: 'TA0007', name: '发现', count: 0 },
              { id: 'TA0008', name: '横向移动', count: 0 },
              { id: 'TA0009', name: '采集', count: 0 },
              { id: 'TA0010', name: '渗出', count: 0 },
              { id: 'TA0011', name: '命令与控制', count: coreCount || 0 },
              { id: 'TA0040', name: '影响', count: 0 },
              { id: 'TA0042', name: '资源开发', count: 0 },
              { id: 'TA0043', name: '侦察', count: alertCount || 0 }
            ],
            tacticCount: [entryCount, coreCount].filter(Boolean).length || 0,
            techniqueCount: alertCount
          },
          evidence: {
            intelligence: incident.alerts.length > 0 ? Math.min(incident.alerts.length, 3) : 0,
            malware: coreCount > 0 ? coreCount : 0,
            suspiciousFiles: incident.alerts.length * 5
          }
        });
      }

      if (section === 'alerts') {
        return json(res, 200, { items: incident.alerts, total: incident.alerts.length });
      }

      if (section === 'graph') {
        // Prefer stored graph from searcher if available
        if (incident.graph && incident.graph.nodes && incident.graph.nodes.length > 0) {
          // Convert searcher graph format to frontend format
          const graphNodes = incident.graph.nodes.map((n) => ({
            id: n.id,
            label: n.label || n.id,
            type: n.type || 'unknown',
            risk: n.data?.risk || '未知',
          }));
          const graphEdges = (incident.graph.edges || []).map((e) => ({
            from: e.source || e.from,
            to: e.target || e.to,
            label: e.relationship || e.label || '',
          }));
          return json(res, 200, { nodes: graphNodes, edges: graphEdges });
        }
        // Fallback: build graph from alerts
        const graphNodes = [
          { id: incident.id, label: incident.title, type: '事件', risk: incident.severityLabel }
        ];
        const graphEdges = [];
        const addedIds = new Set([incident.id]);
        const addNode = (id, label, type, risk) => {
          if (!addedIds.has(id)) { addedIds.add(id); graphNodes.push({ id, label, type, risk }); }
        };
        incident.alerts.forEach((alert) => {
          addNode(alert.id, alert.title, '告警', SEVERITY_LABEL_MAP[alert.severity] || alert.severity || '');
          graphEdges.push({ from: incident.id, to: alert.id, label: alert.relation });
        });
        const alertVictims = [...new Set(incident.alerts.map((a) => a.victim).filter(Boolean))];
        const alertAttackers = [...new Set(incident.alerts.map((a) => a.attacker).filter(Boolean))];
        alertVictims.forEach((ip) => {
          const hostId = `host-${ip}`;
          addNode(hostId, `主机 ${ip}`, '主机', incident.severityLabel);
          incident.alerts.filter((a) => a.victim === ip).forEach((a) => {
            graphEdges.push({ from: a.id, to: hostId, label: '受害主机' });
          });
          const ipId = `ip-${ip}`;
          addNode(ipId, ip, '内网IP', '中风险');
          graphEdges.push({ from: hostId, to: ipId, label: '绑定' });
        });
        alertAttackers.filter((ip) => ip && ip !== '-').forEach((ip) => {
          const extId = `ext-${ip}`;
          addNode(extId, ip, '外网IP', '高风险');
          incident.alerts.filter((a) => a.attacker === ip).forEach((a) => {
            graphEdges.push({ from: extId, to: a.id, label: '攻击来源' });
          });
        });
        return json(res, 200, { nodes: graphNodes, edges: graphEdges });
      }

      if (section === 'evidence') {
        // Query entity-index for real entities related to this incident
        const entityResult = await searchIndex('entity-index', {
          query: { term: { incident_id: incidentId } },
          size: 100,
        });
        const entityHits = entityResult.hits?.hits || [];
        const severityLabel = (s) => SEVERITY_LABEL_MAP[s] || s || '未知';

        const fileEntities = entityHits
          .filter((h) => h._source.type === 'file')
          .map((h) => ({
            md5: h._source.name,
            name: h._source.name?.slice(0, 20) || 'unknown',
            type: '文件',
            risk: severityLabel(incident.severity),
            detectedAt: h._source.first_seen || incident.startTime,
            source: incident.dataSource,
          }));

        const ipEntities = entityHits
          .filter((h) => h._source.type === 'ip')
          .map((h) => ({
            id: h._id,
            indicator: h._source.name,
            type: 'IP',
            source: '系统检测',
            confidence: '高',
            matchedAt: h._source.first_seen || incident.startTime,
          }));

        return json(res, 200, {
          malware: fileEntities.length > 0 ? fileEntities : [],
          intelligence: ipEntities.length > 0 ? ipEntities : [],
          suspiciousFiles: fileEntities,
        });
      }

      if (section === 'impact') {
        // Query entity-index for real entities related to this incident
        const entityResult = await searchIndex('entity-index', {
          query: { term: { incident_id: incidentId } },
          size: 100,
        });
        const entityHits = entityResult.hits?.hits || [];

        const hostEntities = entityHits
          .filter((h) => h._source.type === 'host')
          .map((h) => ({
            id: h._id,
            name: h._source.name,
            ip: h._source.name,
            os: 'Unknown',
            risk: h._source.risk || 'unknown',
            compromised: h._source.compromised || 'unknown',
            exposure: '-',
            count: 1,
            firstSeen: h._source.first_seen || incident.startTime,
            lastSeen: h._source.last_seen || incident.endTime,
          }));

        const ipEntities = entityHits
          .filter((h) => h._source.type === 'ip')
          .map((h) => ({
            id: h._id,
            ip: h._source.name,
            type: 'IP',
            risk: h._source.risk || 'unknown',
            owner: incident.organization || '-',
            firstSeen: h._source.first_seen || incident.startTime,
            lastSeen: h._source.last_seen || incident.endTime,
            count: 1,
          }));

        const accountEntities = entityHits
          .filter((h) => h._source.type === 'account')
          .map((h) => ({
            id: h._id,
            name: h._source.name,
            domain: '',
            risk: h._source.risk || 'unknown',
            compromised: h._source.compromised || 'unknown',
            lastSeen: h._source.last_seen || incident.endTime,
            count: 1,
          }));

        return json(res, 200, {
          hosts: hostEntities,
          ips: ipEntities,
          accounts: accountEntities,
        });
      }
    }

    // ── M3: Logs search (ES-backed) ─────────────────────────────────────
    if (pathname === '/api/security/logs/search' && method === 'POST') {
      const body = await parseBody(req);
      const keyword = body.keyword || body.hql || '';
      const must = [];
      if (keyword) {
        must.push({
          multi_match: {
            query: keyword,
            fields: ['event_name^2', 'source_address', 'destination_address', 'organization', 'raw'],
          },
        });
      }
      const esBody = {
        query: must.length ? { bool: { must } } : { match_all: {} },
        sort: [{ occurred_at: { order: 'desc' } }],
        size: 20,
      };
      const result = await searchIndex('log-index', esBody);
      const hits = result.hits?.hits || [];
      const items = hits.map((h) => ({
        id: h._source.id,
        occurredAt: h._source.occurred_at || '',
        eventName: h._source.event_name || '',
        eventLevel: h._source.event_level || '',
        organization: h._source.organization || '',
        sourceAddress: h._source.source_address || '',
        destinationAddress: h._source.destination_address || '',
        sourcePort: h._source.source_port || '',
        destinationPort: h._source.destination_port || '',
        raw: h._source.raw || '',
      }));
      return json(res, 200, { items, total: result.hits?.total?.value || items.length });
    }

    if (pathname === '/api/security/logs/templates' && method === 'GET') {
      return json(res, 200, [
        { id: 'default', name: '日志检索模板', fields: ['occurredAt', 'eventName', 'eventLevel', 'organization', 'sourceAddress', 'destinationAddress'] }
      ]);
    }

    // ── Static files & SPA fallback ────────────────────────────────────────
    return sendStatic(req, res, pathname);
  } catch (error) {
    console.error(error);
    return json(res, 500, { message: error.message });
  }
};

// =============================================================================
// INITIALIZATION & STARTUP
// =============================================================================

async function start() {
  try {
    // 1. Initialize PostgreSQL (create tables, seed data)
    console.log('[server] Initializing database...');
    await initDb();

    // 2. Initialize Elasticsearch (create indices)
    console.log('[server] Initializing Elasticsearch...');
    try {
      await initEs();
    } catch (err) {
      console.error('[server] Elasticsearch init failed (non-fatal):', err.message);
    }

    // 3. Ensure Kafka topics exist
    console.log('[server] Ensuring Kafka topics...');
    try {
      await ensureTopics();
    } catch (err) {
      console.error('[server] Kafka topic creation failed (non-fatal):', err.message);
    }

    // 4. Start event aggregator (Kafka consumer)
    try {
      await startAggregator();
      console.log('[server] Aggregator started');
    } catch (err) {
      console.error('[server] Aggregator start failed (non-fatal):', err.message);
    }

    // 5. Start log searcher (Kafka consumer)
    try {
      await startSearcher();
      console.log('[server] Searcher started');
    } catch (err) {
      console.error('[server] Searcher start failed (non-fatal):', err.message);
    }

    // 6. Start HTTP server
    http.createServer(router).listen(port, host, () => {
      console.log(`[server] event-security listening on http://${host}:${port}`);
    });
  } catch (err) {
    console.error('[server] Fatal startup error:', err);
    process.exit(1);
  }
}

start();
