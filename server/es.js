import { Client } from '@elastic/elasticsearch';

// ── Client ───────────────────────────────────────────────────────────────────
const client = new Client({ node: 'http://localhost:9200' });

// ── Index definitions ────────────────────────────────────────────────────────

const incidentIndex = {
  index: 'incident-index',
  body: {
    mappings: {
      properties: {
        id:               { type: 'keyword' },
        title:            { type: 'text', fields: { keyword: { type: 'keyword' } } },
        severity:         { type: 'keyword' },
        attack_result:    { type: 'keyword' },
        scene_type:       { type: 'keyword' },
        ice_rule_id:      { type: 'keyword' },
        data_source:      { type: 'keyword' },
        organization:     { type: 'keyword' },
        advice:           { type: 'text' },
        start_time:       { type: 'date' },
        end_time:         { type: 'date' },
        update_time:      { type: 'date' },
        attacker_array: {
          type: 'nested',
          properties: {
            ip:   { type: 'keyword' },
            name: { type: 'keyword' }
          }
        },
        victim_array: {
          type: 'nested',
          properties: {
            ip:   { type: 'keyword' },
            name: { type: 'keyword' }
          }
        },
        priority:         { type: 'integer' },
        threat_confidence:{ type: 'integer' }
      }
    }
  }
};

const alertIndex = {
  index: 'alert-index',
  body: {
    mappings: {
      properties: {
        id:          { type: 'keyword' },
        title:       { type: 'keyword' },
        severity:    { type: 'keyword' },
        type:        { type: 'keyword' },
        attacker:    { type: 'keyword' },
        victim:      { type: 'keyword' },
        tactic:      { type: 'keyword' },
        result:      { type: 'keyword' },
        incident_id: { type: 'keyword' },
        core:        { type: 'boolean' },
        entry:       { type: 'boolean' },
        started_at:  { type: 'date' },
        relation:    { type: 'text' }
      }
    }
  }
};

const logIndex = {
  index: 'log-index',
  body: {
    mappings: {
      properties: {
        id:                  { type: 'keyword' },
        event_name:          { type: 'keyword' },
        event_level:         { type: 'keyword' },
        organization:        { type: 'keyword' },
        source_address:      { type: 'keyword' },
        destination_address: { type: 'keyword' },
        source_port:         { type: 'keyword' },
        destination_port:    { type: 'keyword' },
        occurred_at:         { type: 'date' },
        raw:                 { type: 'text' }
      }
    }
  }
};

const entityIndex = {
  index: 'entity-index',
  body: {
    mappings: {
      properties: {
        id:            { type: 'keyword' },
        type:          { type: 'keyword' },
        name:          { type: 'keyword' },
        risk:          { type: 'keyword' },
        compromised:   { type: 'keyword' },
        incident_id:   { type: 'keyword' },
        first_seen:    { type: 'date' },
        last_seen:     { type: 'date' }
      }
    }
  }
};

const indices = [incidentIndex, alertIndex, logIndex, entityIndex];

// ── Initialisation ───────────────────────────────────────────────────────────

/**
 * Create every index that does not already exist.
 * Uses ES 7.x / 8.x compatible createIndex API.
 */
export async function initEs() {
  for (const def of indices) {
    const exists = await client.indices.exists({ index: def.index });
    if (!exists) {
      await client.indices.create(def);
      console.log(`[es] created index "${def.index}"`);
    }
  }
}

// ── CRUD helpers ─────────────────────────────────────────────────────────────

/**
 * Search documents in the given index.
 * @param {string} index
 * @param {object} body  ES query DSL
 * @returns {Promise<object>} ES search response
 */
export async function searchIndex(index, body) {
  return client.search({ index, body });
}

/**
 * Index (create or update) a single document with an explicit id.
 * @param {string} index
 * @param {string} id
 * @param {object} doc
 * @returns {Promise<object>}
 */
export async function indexDocument(index, id, doc) {
  return client.index({ index, id, body: doc, refresh: true });
}

/**
 * Bulk-index an array of documents.
 * Each element should be an object with at least an `_id` field.
 * @param {string} index
 * @param {Array<object>} docs
 * @returns {Promise<object>}
 */
export async function bulkIndex(index, docs) {
  const body = docs.flatMap((doc) => {
    const { _id, ...source } = doc;
    return [{ index: { _index: index, _id: _id || undefined } }, source];
  });
  return client.bulk({ body, refresh: true });
}

/**
 * Delete the given index entirely.
 * @param {string} index
 * @returns {Promise<object>}
 */
export async function deleteIndex(index) {
  const exists = await client.indices.exists({ index });
  if (exists) {
    return client.indices.delete({ index });
  }
  return { acknowledged: true };
}

// ── Exports ──────────────────────────────────────────────────────────────────
export { client };
