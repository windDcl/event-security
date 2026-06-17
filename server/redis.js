import Redis from 'ioredis';

// --- Redis Client -----------------------------------------------------------

const client = new Redis({
  host: 'localhost',
  port: 7001,
  retryStrategy(times) {
    const delay = Math.min(times * 200, 5000);
    console.warn(`[redis] reconnect attempt #${times} in ${delay}ms`);
    return delay;
  },
  maxRetriesPerRequest: 3,
});

client.on('error', (err) => {
  console.error('[redis] connection error:', err.message);
});

client.on('connect', () => {
  console.log('[redis] connected to localhost:7001');
});

// --- Helpers ----------------------------------------------------------------

/**
 * General-purpose cache get / set
 */

async function getCache(key) {
  try {
    const raw = await client.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    console.error('[redis] getCache error:', err.message);
    return null;
  }
}

async function setCache(key, val, ttl = 3600) {
  try {
    const payload = JSON.stringify(val);
    if (ttl && ttl > 0) {
      await client.set(key, payload, 'EX', ttl);
    } else {
      await client.set(key, payload);
    }
  } catch (err) {
    console.error('[redis] setCache error:', err.message);
  }
}

/**
 * Whitelist helpers  – keys are stored as "whitelist:{type}"
 */

function whitelistKey(type) {
  return `whitelist:${type}`;
}

async function getWhitelist(type) {
  try {
    const raw = await client.get(whitelistKey(type));
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    console.error('[redis] getWhitelist error:', err.message);
    return [];
  }
}

async function setWhitelist(type, vals) {
  try {
    await client.set(whitelistKey(type), JSON.stringify(vals));
  } catch (err) {
    console.error('[redis] setWhitelist error:', err.message);
  }
}

/**
 * Aggregation-state helpers  – keys are stored as "agg:{key}"
 */

function aggKey(key) {
  return `agg:${key}`;
}

async function getAggregationState(key) {
  try {
    const raw = await client.get(aggKey(key));
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    console.error('[redis] getAggregationState error:', err.message);
    return null;
  }
}

async function setAggregationState(key, state, ttl = 3600) {
  try {
    const payload = JSON.stringify(state);
    if (ttl && ttl > 0) {
      await client.set(aggKey(key), payload, 'EX', ttl);
    } else {
      await client.set(aggKey(key), payload);
    }
  } catch (err) {
    console.error('[redis] setAggregationState error:', err.message);
  }
}

/**
 * Graph-cache helpers  – keys are stored as "graph:{id}"
 */

function graphKey(id) {
  return `graph:${id}`;
}

async function getGraphCache(id) {
  try {
    const raw = await client.get(graphKey(id));
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    console.error('[redis] getGraphCache error:', err.message);
    return null;
  }
}

async function setGraphCache(id, data, ttl = 1800) {
  try {
    const payload = JSON.stringify(data);
    if (ttl && ttl > 0) {
      await client.set(graphKey(id), payload, 'EX', ttl);
    } else {
      await client.set(graphKey(id), payload);
    }
  } catch (err) {
    console.error('[redis] setGraphCache error:', err.message);
  }
}

// --- Exports ----------------------------------------------------------------

export {
  client,
  getCache,
  setCache,
  getWhitelist,
  setWhitelist,
  getAggregationState,
  setAggregationState,
  getGraphCache,
  setGraphCache,
};

export default client;
