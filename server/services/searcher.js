/**
 * searcher.js – Async Correlation Search Service
 *
 * Consumes tasks from Kafka topic 'nsm-incident-task', loads the model DSL
 * from PG (ice_rule.statement), replaces variable placeholders, compiles to ES
 * queries via ./dsl.js, executes searches, and updates incidents with
 * related alerts, graph data, and entity information.
 */

import yaml from 'yaml';
import { createConsumer } from '../kafka.js';
import { query } from '../db.js';
import { searchIndex, indexDocument, bulkIndex } from '../es.js';
import { validateDsl, extractVariables } from './dsl.js';

// ── Constants ───────────────────────────────────────────────────────────────

const CONSUMER_GROUP = 'nsm-incident-searcher';
const TASK_TOPIC = 'nsm-incident-task';

// ── Variable Replacement ────────────────────────────────────────────────────

/**
 * Replace ${variable} placeholders in a string with actual values.
 * @param {string} str
 * @param {Record<string, string|number>} variables
 * @returns {string}
 */
function replaceVariables(str, variables) {
  if (!str || typeof str !== 'string') return str;
  let result = str;
  for (const [key, value] of Object.entries(variables)) {
    result = result.replaceAll(`\${${key}}`, String(value));
  }
  return result;
}

// ── Model DSL Loading ───────────────────────────────────────────────────────

/**
 * Load the DSL YAML string from PG (ice_rule.statement).
 * NOTE: `raw` stores entryAlerts JSON (for aggregator matching),
 *       `statement` stores the DSL YAML (for searcher execution).
 * @param {string} modelId
 * @returns {Promise<string>}
 */
async function loadModelDsl(modelId) {
  const { rows } = await query(
    'SELECT statement FROM ice_rule WHERE id = $1',
    [modelId],
  );
  if (!rows.length || !rows[0].statement) {
    throw new Error(`Model DSL not found for modelId: ${modelId}`);
  }
  return rows[0].statement;
}

// ── Compiled-Step Execution ─────────────────────────────────────────────────

/**
 * Recursively execute compiled DSL steps, collecting related alerts/logs.
 * @param {Array} compiledSteps – output of validateDsl().compiled
 * @param {object} context – accumulator { relatedAlerts: [] }
 */
async function executeCompiledSteps(compiledSteps, context) {
  if (!compiledSteps || !Array.isArray(compiledSteps)) return;

  for (const step of compiledSteps) {
    const response = await searchIndex(step.index, {
      size: 500,
      query: step.query,
    });

    const hits = response.hits?.hits || [];

    for (const hit of hits) {
      context.relatedAlerts.push({
        ...hit._source,
        _index: step.index,
        _id: hit._id,
        relation: step.relationship,
        essential: Boolean(step.essential),
      });
    }

    // Recurse into processUnit if present
    if (step.processUnit && Array.isArray(step.processUnit)) {
      await executeCompiledSteps(step.processUnit, context);
    }
  }
}

// ── Graph Generation ────────────────────────────────────────────────────────

/**
 * Generate graph nodes and edges from collected results.
 * Nodes: incident (root), alerts, IPs, hosts, accounts, files.
 * Edges: incident→alert, alert→entity with relationship labels.
 */
function generateGraph(relatedAlerts, incidentId) {
  const nodes = new Map();
  const edges = [];

  // Root node – the incident itself
  const rootId = `incident:${incidentId}`;
  nodes.set(rootId, {
    id: rootId,
    type: 'incident',
    label: `Incident ${incidentId}`,
    data: { incidentId },
  });

  for (const alert of relatedAlerts) {
    const alertNodeId = `alert:${alert.id || alert._id}`;
    if (!nodes.has(alertNodeId)) {
      nodes.set(alertNodeId, {
        id: alertNodeId,
        type: 'alert',
        label: alert.title || alert._id,
        data: { relation: alert.relation },
      });
      edges.push({
        source: rootId,
        target: alertNodeId,
        relationship: alert.relation || 'related',
      });
    }

    // IP / address entities
    for (const field of ['attacker', 'victim', 'source_address', 'destination_address']) {
      const value = alert[field];
      if (value && value !== '-') {
        const ipNodeId = `ip:${value}`;
        if (!nodes.has(ipNodeId)) {
          nodes.set(ipNodeId, { id: ipNodeId, type: 'ip', label: value });
        }
        edges.push({ source: alertNodeId, target: ipNodeId, relationship: 'associated_ip' });
      }
    }

    // Host entities
    const host = alert.host || alert.hostname;
    if (host && host !== '-') {
      const hostNodeId = `host:${host}`;
      if (!nodes.has(hostNodeId)) {
        nodes.set(hostNodeId, { id: hostNodeId, type: 'host', label: host });
      }
      edges.push({ source: alertNodeId, target: hostNodeId, relationship: 'hosted_on' });
    }

    // Account entities
    const account = alert.account || alert.user;
    if (account && account !== '-') {
      const acctNodeId = `account:${account}`;
      if (!nodes.has(acctNodeId)) {
        nodes.set(acctNodeId, { id: acctNodeId, type: 'account', label: account });
      }
      edges.push({ source: alertNodeId, target: acctNodeId, relationship: 'used_by' });
    }

    // File / hash entities
    const fileHash = alert.hash?.md5;
    if (fileHash) {
      const fileNodeId = `file:${fileHash}`;
      if (!nodes.has(fileNodeId)) {
        nodes.set(fileNodeId, { id: fileNodeId, type: 'file', label: fileHash });
      }
      edges.push({ source: alertNodeId, target: fileNodeId, relationship: 'involves_file' });
    }
  }

  return { nodes: [...nodes.values()], edges };
}

// ── Entity Extraction ───────────────────────────────────────────────────────

/**
 * Deduplicate entities (hosts, IPs, accounts, files) from related results.
 */
function extractEntities(relatedAlerts) {
  const hosts = new Set();
  const ips = new Set();
  const accounts = new Set();
  const files = new Set();

  for (const alert of relatedAlerts) {
    if (alert.attacker && alert.attacker !== '-') ips.add(alert.attacker);
    if (alert.victim && alert.victim !== '-') ips.add(alert.victim);
    if (alert.source_address) ips.add(alert.source_address);
    if (alert.destination_address) ips.add(alert.destination_address);
    if (alert.host || alert.hostname) hosts.add(alert.host || alert.hostname);
    if (alert.account || alert.user) accounts.add(alert.account || alert.user);
    if (alert.hash?.md5) files.add(alert.hash.md5);
  }

  return {
    hosts: [...hosts],
    ips: [...ips],
    accounts: [...accounts],
    files: [...files],
  };
}

// ── Incident Update ─────────────────────────────────────────────────────────

/**
 * Update the incident document in ES (incident-index) by merging new
 * related alerts, graph data, and entity information.
 */
async function updateIncident(incidentId, { relatedAlerts, graph, entities }) {
  let existing = {};
  try {
    const res = await searchIndex('incident-index', {
      query: { term: { id: incidentId } },
    });
    existing = res.hits?.hits?.[0]?._source || {};
  } catch {
    // Incident may not exist yet – create from scratch
  }

  // Merge related alerts (deduplicate by id)
  const existingAlertIds = new Set(
    (existing.related_alerts || []).map((a) => a.id),
  );
  const newAlerts = relatedAlerts
    .filter((a) => !existingAlertIds.has(a.id || a._id))
    .map((a) => ({
      id: a.id || a._id,
      title: a.title,
      severity: a.severity,
      type: a.type,
      attacker: a.attacker,
      victim: a.victim,
      relation: a.relation,
      started_at: a.started_at,
      essential: a.essential,
    }));

  await indexDocument('incident-index', incidentId, {
    ...existing,
    id: incidentId,
    related_alerts: [...(existing.related_alerts || []), ...newAlerts],
    graph,
    entities,
    update_time: new Date().toISOString(),
  });
}

// ── Entity Document Creation ────────────────────────────────────────────────

/**
 * Create individual entity documents in entity-index.
 */
async function createEntities(entities, incidentId) {
  const docs = [];
  const now = new Date().toISOString();

  for (const ip of entities.ips) {
    docs.push({
      _id: `ip:${ip}:${incidentId}`,
      type: 'ip',
      name: ip,
      risk: 'unknown',
      compromised: 'unknown',
      incident_id: incidentId,
      first_seen: now,
      last_seen: now,
    });
  }

  for (const host of entities.hosts) {
    docs.push({
      _id: `host:${host}:${incidentId}`,
      type: 'host',
      name: host,
      risk: 'unknown',
      compromised: 'unknown',
      incident_id: incidentId,
      first_seen: now,
      last_seen: now,
    });
  }

  for (const account of entities.accounts) {
    docs.push({
      _id: `account:${account}:${incidentId}`,
      type: 'account',
      name: account,
      risk: 'unknown',
      compromised: 'unknown',
      incident_id: incidentId,
      first_seen: now,
      last_seen: now,
    });
  }

  for (const file of entities.files) {
    docs.push({
      _id: `file:${file}:${incidentId}`,
      type: 'file',
      name: file,
      risk: 'unknown',
      compromised: 'unknown',
      incident_id: incidentId,
      first_seen: now,
      last_seen: now,
    });
  }

  if (docs.length > 0) {
    await bulkIndex('entity-index', docs);
    console.log(`[searcher] Created ${docs.length} entity documents`);
  }
}

// ── Analysis Task Progress ──────────────────────────────────────────────────

/**
 * Update analysis task progress in PG (ice_analysis_task).
 * Finds the task by its relative_ids containing the incidentId.
 * @param {string} incidentId
 * @param {number} progress – 0-100
 * @param {number} status – 0=idle/completed, 1=running, 2=error
 */
async function updateTaskProgress(incidentId, progress, status = 1) {
  try {
    await query(
      `UPDATE ice_analysis_task
       SET progress = $1, status = $2, update_time = NOW()
       WHERE relative_ids LIKE $3`,
      [progress, status, `%${incidentId}%`],
    );
  } catch (err) {
    console.error(`[searcher] Failed to update task progress for ${incidentId}:`, err.message);
  }
}

// ── Task Handler ────────────────────────────────────────────────────────────

/**
 * Build a variables map from a task message.
 * Supports two formats:
 *   - Spec:   { variables: { key: value } }
 *   - Actual: { victim, attacker, ... } — mapped to common DSL variable names
 */
function buildVariables(task) {
  // If the task carries an explicit variables map, use it directly
  if (task.variables && typeof task.variables === 'object') {
    return { ...task.variables };
  }

  // Otherwise derive variables from common alert fields
  const variables = {};
  if (task.victim) {
    variables['受害者'] = task.victim;
    variables['源地址'] = task.victim;
    variables['目的地址'] = task.victim;
    variables['主机IP'] = task.victim;
  }
  if (task.attacker) {
    variables['攻击者'] = task.attacker;
    variables['源地址'] = task.attacker;
  }
  return variables;
}

/**
 * Process a single correlation search task end-to-end:
 *   1. Load & compile DSL
 *   2. Replace variables & execute searches
 *   3. Generate graph + entities
 *   4. Update incident in ES
 *   5. Create entity documents
 *   6. Update task progress in PG
 */
async function handleTask(task) {
  // Support both spec format (modelId) and aggregator format (iceRuleId)
  const incidentId = task.incidentId;
  const alertId = task.alertId;
  const modelId = task.modelId || task.iceRuleId;
  const variables = buildVariables(task);

  console.log(`[searcher] Processing task: incident=${incidentId}, alert=${alertId}, model=${modelId}`);

  try {
    // ── 1. Load raw DSL YAML from PG ────────────────────────────────────
    await updateTaskProgress(incidentId, 5, 1);

    const rawDsl = await loadModelDsl(modelId);

    // ── 2. Replace ${variable} placeholders ─────────────────────────────
    const resolvedDsl = replaceVariables(rawDsl, variables);

    // ── 3. Validate & compile DSL ───────────────────────────────────────
    const validation = validateDsl(resolvedDsl);
    if (!validation.valid) {
      console.error(`[searcher] DSL validation failed: ${validation.errors.join('; ')}`);
      await updateTaskProgress(incidentId, 0, 2);
      return;
    }

    await updateTaskProgress(incidentId, 20, 1);

    // ── 4. Execute compiled search steps ────────────────────────────────
    const context = { relatedAlerts: [] };
    await executeCompiledSteps(validation.compiled, context);

    await updateTaskProgress(incidentId, 60, 1);

    console.log(`[searcher] Found ${context.relatedAlerts.length} related results for incident ${incidentId}`);

    // ── 5. Generate graph ───────────────────────────────────────────────
    const graph = generateGraph(context.relatedAlerts, incidentId);

    // ── 6. Extract entities ─────────────────────────────────────────────
    const entities = extractEntities(context.relatedAlerts);

    // ── 7. Update incident in ES ────────────────────────────────────────
    await updateIncident(incidentId, {
      relatedAlerts: context.relatedAlerts,
      graph,
      entities,
    });

    await updateTaskProgress(incidentId, 85, 1);

    // ── 8. Create entity documents in ES ────────────────────────────────
    await createEntities(entities, incidentId);

    // ── 9. Mark analysis task complete in PG ────────────────────────────
    await updateTaskProgress(incidentId, 100, 0);

    console.log(`[searcher] Task completed: incident=${incidentId}, alerts=${context.relatedAlerts.length}, entities=${entities.ips.length + entities.hosts.length + entities.accounts.length + entities.files.length}`);

  } catch (err) {
    console.error(`[searcher] Error processing incident=${incidentId}:`, err.message);
    await updateTaskProgress(incidentId, 0, 2).catch(() => {});
  }
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Start the correlation search service.
 * Subscribes to Kafka topic 'nsm-incident-task' and processes each task.
 */
export async function startSearcher() {
  console.log('[searcher] Starting correlation search service…');

  await createConsumer(TASK_TOPIC, CONSUMER_GROUP, async (message) => {
    if (!message.value) {
      console.warn('[searcher] Received empty message, skipping');
      return;
    }
    await handleTask(message.value);
  });

  console.log(`[searcher] Listening on topic "${TASK_TOPIC}" (group=${CONSUMER_GROUP})`);
}
