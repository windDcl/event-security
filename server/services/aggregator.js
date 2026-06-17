/**
 * Auto-Aggregation Service (M21)
 *
 * Consumes alerts from Kafka topic 'nsm-original-alert', matches them against
 * active detection models (ice_rule) loaded from PostgreSQL, and creates or
 * updates incidents in Elasticsearch. Produces follow-up tasks to
 * 'nsm-incident-task' for async search enrichment.
 */

import { searchIndex, indexDocument } from '../es.js';
import { query } from '../db.js';
import { createConsumer, sendMessage } from '../kafka.js';
import { randomUUID } from 'node:crypto';

// ── Constants ──────────────────────────────────────────────────────────────

const ALERT_TOPIC = 'nsm-original-alert';
const INCIDENT_INDEX = 'incident-index';
const ALERT_INDEX = 'alert-index';
const TASK_TOPIC = 'nsm-incident-task';
const CONSUMER_GROUP = 'aggregator-group';

/** How often (ms) to refresh the active model cache */
const MODEL_REFRESH_INTERVAL = 30_000;

/** Incident TTL — if no new alerts arrive within this window, consider stale */
const INCIDENT_STALE_HOURS = 24;

// ── Model Cache ────────────────────────────────────────────────────────────

/**
 * In-memory cache of active models keyed by id.
 * Refreshed periodically from PG so we don't query on every alert.
 */
let activeModels = new Map();
let lastModelRefresh = 0;

/**
 * Load all active (running, not logically deleted) models from ice_rule.
 * Parses the `raw` JSON column to populate entryAlerts on each model.
 */
async function refreshModels() {
  try {
    const { rows } = await query(
      `SELECT id, name, description, advice, scene_type, notifier,
              status, source, statement, raw, system
       FROM ice_rule
       WHERE status = 'running' AND logic_delete = false`
    );

    const next = new Map();
    for (const row of rows) {
      let entryAlerts = [];
      try {
        entryAlerts = row.raw ? JSON.parse(row.raw) : [];
      } catch { /* malformed JSON — skip entry_alerts */ }

      let statement = null;
      try {
        statement = row.statement ? JSON.parse(row.statement) : null;
      } catch { /* statement may be raw YAML string, leave as-is */ }

      next.set(row.id, {
        id: row.id,
        name: row.name || '',
        description: row.description || '',
        advice: row.advice || '',
        sceneType: row.scene_type || '',
        source: row.source || 'custom',
        entryAlerts,
        statement,
        notifier: row.notifier || '',
      });
    }

    activeModels = next;
    lastModelRefresh = Date.now();
    console.log(`[aggregator] refreshed ${next.size} active model(s)`);
  } catch (err) {
    console.error('[aggregator] failed to refresh models:', err.message);
  }
}

// ── Alert ↔ Model Matching ────────────────────────────────────────────────

/**
 * Check whether an incoming alert matches one of a model's entry-alerts.
 *
 * Each entry-alert in the array is an object with optional fields:
 *   name   — expected rule_name (exact match)
 *   title  — expected title    (exact or wildcard via %)
 *   type   — expected type     (exact match)
 *   severity — expected severity (exact match)
 *
 * Returns true when at least one entry-alert criterion fully matches.
 * If the model has no entry-alerts defined, it matches *every* alert
 * (open model).
 */
function matchesEntryAlerts(alert, entryAlerts) {
  // No entry-alerts defined → model accepts all alerts
  if (!Array.isArray(entryAlerts) || entryAlerts.length === 0) {
    return true;
  }

  return entryAlerts.some((entry) => {
    // Each field present in the entry must match the corresponding alert field
    if (entry.name && entry.name !== alert.rule_name) return false;
    if (entry.type && entry.type !== alert.type) return false;
    if (entry.severity && entry.severity !== alert.severity) return false;
    if (entry.title) {
      // Support simple wildcard: % acts as *
      if (entry.title.includes('%')) {
        const pattern = entry.title.replace(/%/g, '.*');
        const regex = new RegExp(`^${pattern}$`, 'i');
        if (!regex.test(alert.title || '')) return false;
      } else if (entry.title !== alert.title) {
        return false;
      }
    }
    return true;
  });
}

/**
 * Find all models that match a given alert.
 * Returns an array of model objects.
 */
function findMatchingModels(alert) {
  const matched = [];
  for (const model of activeModels.values()) {
    if (matchesEntryAlerts(alert, model.entryAlerts)) {
      matched.push(model);
    }
  }
  return matched;
}

// ── Incident Helpers ───────────────────────────────────────────────────────

/**
 * Build an incident document from an alert + matched model.
 */
function buildIncident(alert, model) {
  const now = new Date().toISOString();
  const id = `inc-${randomUUID().slice(0, 8)}`;

  return {
    id,
    title: alert.title || model.name || '未命名事件',
    severity: alert.severity || 'unknown',
    attack_result: alert.result || 'unknown',
    scene_type: model.sceneType || '',
    ice_rule_id: model.id,
    data_source: model.source || '',
    organization: '',
    advice: model.advice || '',
    start_time: alert.started_at || now,
    end_time: alert.started_at || now,
    update_time: now,
    attacker_array: parseEntityArray(alert.attacker),
    victim_array: parseEntityArray(alert.victim),
    priority: severityToPriority(alert.severity),
    threat_confidence: severityToPriority(alert.severity),
    related_alerts: [alert],
  };
}

/**
 * Parse an attacker/victim string into the nested array format ES expects.
 * Handles comma-separated IPs, single IPs, or hostnames.
 */
function parseEntityArray(value) {
  if (!value || value === '-') return [];
  return value
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
    .map((v) => {
      const ipLike = /^\d{1,3}(\.\d{1,3}){3}$/.test(v);
      return ipLike ? { ip: v, name: '' } : { ip: '', name: v };
    });
}

/**
 * Map severity string to numeric priority.
 */
function severityToPriority(severity) {
  const map = { critical: 4, high: 3, medium: 2, low: 1 };
  return map[severity] || 0;
}

// ── ES Operations ──────────────────────────────────────────────────────────

/**
 * Search for an existing incident that matches by ice_rule_id + victim.
 * Returns the incident document or null.
 */
async function findExistingIncident(iceRuleId, victim) {
  const result = await searchIndex(INCIDENT_INDEX, {
    query: {
      bool: {
        must: [
          { term: { ice_rule_id: iceRuleId } },
          {
            nested: {
              path: 'victim_array',
              query: {
                bool: {
                  should: [
                    { term: { 'victim_array.ip': victim } },
                    { term: { 'victim_array.name': victim } },
                  ],
                  minimum_should_match: 1,
                },
              },
            },
          },
        ],
      },
    },
    size: 1,
    sort: [{ update_time: { order: 'desc' } }],
  });

  const hits = result.hits?.hits || [];
  return hits.length > 0 ? hits[0] : null;
}

/**
 * Create a new incident in ES.
 */
async function createIncident(incidentDoc) {
  await indexDocument(INCIDENT_INDEX, incidentDoc.id, incidentDoc);
  console.log(`[aggregator] created incident ${incidentDoc.id}`);
  return incidentDoc;
}

/**
 * Update an existing incident: append the new alert and bump the timestamp.
 */
async function updateIncident(existingHit, alert) {
  const incident = existingHit._source;
  const existingAlerts = incident.related_alerts || [];

  // Avoid duplicate alert references
  if (!existingAlerts.some((a) => a.id === alert.id)) {
    existingAlerts.push(alert);
  }

  // Expand attacker/victim arrays with any new entities
  const newAttackers = parseEntityArray(alert.attacker);
  const newVictims = parseEntityArray(alert.victim);

  incident.attacker_array = mergeEntityArrays(incident.attacker_array || [], newAttackers);
  incident.victim_array = mergeEntityArrays(incident.victim_array || [], newVictims);

  // Update severity if new alert is more severe
  const newPriority = severityToPriority(alert.severity);
  if (newPriority > (incident.priority || 0)) {
    incident.severity = alert.severity;
    incident.priority = newPriority;
    incident.threat_confidence = newPriority;
  }

  incident.end_time = alert.started_at || new Date().toISOString();
  incident.update_time = new Date().toISOString();
  incident.related_alerts = existingAlerts;

  await indexDocument(INCIDENT_INDEX, existingHit._id, incident);
  console.log(`[aggregator] updated incident ${existingHit._id} (now ${existingAlerts.length} alerts)`);
  return incident;
}

/**
 * Merge two entity arrays, deduplicating by ip or name.
 */
function mergeEntityArrays(existing, incoming) {
  const seen = new Set();
  const result = [...existing];

  for (const e of existing) {
    const key = e.ip || e.name;
    if (key) seen.add(key);
  }

  for (const e of incoming) {
    const key = e.ip || e.name;
    if (key && !seen.has(key)) {
      result.push(e);
      seen.add(key);
    }
  }

  return result;
}

// ── Core Processing ────────────────────────────────────────────────────────

/**
 * Normalize alert fields from Flink engine output format to aggregator format.
 * Flink uses: src_ip, dst_ip, alarm_name, rule_id, user, alarm_content, original_alert_level, suggest
 * Aggregator expects: attacker, victim, title, type, severity, rule_name, started_at
 */
function normalizeFlinkAlert(alert) {
  const a = { ...alert };
  // Flink engine drops the original id — generate one if missing
  if (!a.id) {
    a.id = `flink-${a.rule_id || 'unknown'}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  }
  // Flink src_ip → attacker
  if (a.src_ip && !a.attacker) a.attacker = a.src_ip;
  // Flink dst_ip → victim
  if (a.dst_ip && !a.victim) a.victim = a.dst_ip;
  // Flink alarm_name → title
  if (a.alarm_name && !a.title) a.title = a.alarm_name;
  // Flink rule_id → rule_name
  if (a.rule_id && !a.rule_name) a.rule_name = a.rule_id;
  // Flink alarm_content → description
  if (a.alarm_content && !a.description) a.description = a.alarm_content;
  // Flink original_alert_level → severity mapping (0=unknown, 1=low, 2=medium, 3=high, 4=critical)
  if (!a.severity && a.original_alert_level != null) {
    const lvl = Number(a.original_alert_level);
    a.severity = lvl >= 4 ? 'critical' : lvl >= 3 ? 'high' : lvl >= 2 ? 'medium' : lvl >= 1 ? 'low' : 'unknown';
  }
  // Flink start_time → started_at
  if (a.start_time && !a.started_at) {
    const ts = typeof a.start_time === 'number' ? new Date(a.start_time).toISOString() : a.start_time;
    a.started_at = ts;
  }
  // Flink user → account
  if (a.user && !a.account) a.account = a.user;
  // Default type
  if (!a.type) a.type = a.sae_template_id || 'unknown';
  // Default severity
  if (!a.severity) a.severity = 'medium';
  return a;
}

/**
 * Process a single alert message.
 */
async function processAlert(alert) {
  if (!alert || !alert.id) {
    console.warn('[aggregator] skipping alert with no id');
    return;
  }

  // Normalize Flink engine format to standard fields
  const normalizedAlert = normalizeFlinkAlert(alert);

  // Refresh model cache if stale
  if (Date.now() - lastModelRefresh > MODEL_REFRESH_INTERVAL) {
    await refreshModels();
  }

  // Find matching models
  const matchedModels = findMatchingModels(normalizedAlert);
  if (matchedModels.length === 0) {
    console.log(`[aggregator] alert ${normalizedAlert.id} matched no models — skipping`);
    return;
  }

  console.log(`[aggregator] alert ${normalizedAlert.id} matched ${matchedModels.length} model(s)`);

  for (const model of matchedModels) {
    try {
      let incidentDoc;

      // Check for existing incident by ice_rule_id + victim
      const existing = await findExistingIncident(model.id, normalizedAlert.victim);

      if (existing) {
        // Update existing incident
        incidentDoc = await updateIncident(existing, normalizedAlert);
      } else {
        // Create new incident
        incidentDoc = buildIncident(normalizedAlert, model);
        await createIncident(incidentDoc);
      }

      // Also index the raw alert into alert-index with a reference to the incident
      await indexAlert(normalizedAlert, incidentDoc.id);

      // Produce async search task
      await sendIncidentTask(incidentDoc, normalizedAlert, model);
    } catch (err) {
      console.error(
        `[aggregator] error processing alert ${normalizedAlert.id} with model ${model.id}:`,
        err.message
      );
    }
  }
}

/**
 * Index the raw alert into alert-index with a reference to the incident.
 */
async function indexAlert(alert, incidentId) {
  const doc = {
    id: alert.id,
    title: alert.title || '',
    severity: alert.severity || '',
    type: alert.type || '',
    attacker: alert.attacker || '',
    victim: alert.victim || '',
    tactic: alert.tactic || '',
    result: alert.result || '',
    incident_id: incidentId,
    core: false,
    entry: true,
    started_at: alert.started_at || new Date().toISOString(),
    relation: '入口告警',
  };

  await indexDocument(ALERT_INDEX, alert.id, doc);
}

// ── Kafka Task Production ──────────────────────────────────────────────────

/**
 * Send a message to the 'nsm-incident-task' topic so the async search
 * enrichment pipeline can pick it up.
 */
async function sendIncidentTask(incident, alert, model) {
  const task = {
    type: 'incident_search',
    incidentId: incident.id,
    iceRuleId: model.id,
    modelDsl: model.statement || null,
    alertId: alert.id,
    victim: alert.victim || '',
    attacker: alert.attacker || '',
    startTime: alert.started_at || new Date().toISOString(),
    endTime: new Date().toISOString(),
    createdAt: new Date().toISOString(),
  };

  await sendMessage(TASK_TOPIC, task);
  console.log(`[aggregator] sent incident task for ${incident.id} → ${TASK_TOPIC}`);
}

// ── Entry Point ────────────────────────────────────────────────────────────

/**
 * Start the aggregator service.
 * Initializes the model cache, then subscribes to the alert topic.
 */
export async function startAggregator() {
  console.log('[aggregator] starting…');

  // Initial model load
  await refreshModels();

  // Start consuming alerts
  const consumer = await createConsumer(
    ALERT_TOPIC,
    CONSUMER_GROUP,
    async ({ value }) => {
      if (!value) {
        console.warn('[aggregator] received empty message — skipping');
        return;
      }

      try {
        await processAlert(value);
      } catch (err) {
        console.error('[aggregator] unhandled error processing message:', err.message);
      }
    }
  );

  console.log('[aggregator] started — listening on topic:', ALERT_TOPIC);
  return consumer;
}
