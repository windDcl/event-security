/**
 * M16: DSL Parser, Validator, and ES Query Compiler
 *
 * Parses YAML-based model DSL, validates structure and variables,
 * and compiles to Elasticsearch queries.
 */
import yaml from 'yaml';

// ── DSL Structure Validation ────────────────────────────────────────────────

/**
 * Validate a DSL string. Returns { valid: true, compiled } or { valid: false, errors }.
 */
export function validateDsl(dslString) {
  const errors = [];

  if (!dslString || typeof dslString !== 'string') {
    return { valid: false, errors: ['DSL 为空'] };
  }

  let parsed;
  try {
    parsed = yaml.parse(dslString);
  } catch (e) {
    return { valid: false, errors: [`YAML 解析失败: ${e.message}`] };
  }

  if (!parsed || typeof parsed !== 'object') {
    return { valid: false, errors: ['DSL 格式错误：顶层必须是对象'] };
  }

  // Must have processList
  if (!Array.isArray(parsed.processList)) {
    return { valid: false, errors: ['DSL 必须包含 processList 数组'] };
  }

  if (parsed.processList.length === 0) {
    return { valid: false, errors: ['processList 不能为空'] };
  }

  // Validate each process step
  const variables = new Set();
  const seenVariables = new Set();

  for (let i = 0; i < parsed.processList.length; i++) {
    const step = parsed.processList[i];
    const prefix = `processList[${i}]`;

    if (!step.condition || typeof step.condition !== 'string') {
      errors.push(`${prefix}: 必须包含 condition 字符串`);
      continue;
    }

    if (!step.source || typeof step.source !== 'string') {
      errors.push(`${prefix}: 必须包含 source 字符串`);
    } else if (!['告警', '日志', 'alert', 'log'].includes(step.source)) {
      errors.push(`${prefix}: source 必须是 "告警" 或 "日志"`);
    }

    if (!Array.isArray(step.time) || step.time.length !== 2) {
      errors.push(`${prefix}: time 必须是 [起始, 结束] 格式`);
    } else {
      for (const t of step.time) {
        if (typeof t !== 'string' || !/^[+-]?\d+[smhd]$/.test(t)) {
          errors.push(`${prefix}: time 格式错误 "${t}"，应如 "-1h", "+30m", "1h"`);
        }
      }
    }

    if (!step.relationship || typeof step.relationship !== 'string') {
      errors.push(`${prefix}: 必须包含 relationship 字符串`);
    }

    // Extract variables from condition
    const vars = extractVariables(step.condition);
    for (const v of vars) {
      seenVariables.add(v);
    }

    // Validate processUnit if present
    if (step.processUnit) {
      if (step.processUnit.processList && Array.isArray(step.processUnit.processList)) {
        for (let j = 0; j < step.processUnit.processList.length; j++) {
          const sub = step.processUnit.processList[j];
          const subPrefix = `${prefix}.processUnit.processList[${j}]`;

          if (!sub.condition) errors.push(`${subPrefix}: 必须包含 condition`);
          if (!sub.source) errors.push(`${subPrefix}: 必须包含 source`);
          if (!sub.relationship) errors.push(`${subPrefix}: 必须包含 relationship`);

          const subVars = extractVariables(sub.condition || '');
          for (const v of subVars) seenVariables.add(v);
        }
      } else {
        errors.push(`${prefix}: processUnit 必须包含 processList`);
      }
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  // Compile to ES queries
  const compiled = compileDsl(parsed);

  return {
    valid: true,
    compiled,
    variables: [...seenVariables],
    stepCount: parsed.processList.length
  };
}

// ── Variable Extraction ─────────────────────────────────────────────────────

/**
 * Extract ${变量} references from a condition string.
 */
export function extractVariables(condition) {
  const matches = condition.match(/\$\{([^}]+)\}/g) || [];
  return matches.map((m) => m.slice(2, -1));
}

// ── DSL Compilation to ES Queries ───────────────────────────────────────────

/**
 * Compile parsed DSL to an array of ES query steps.
 */
function compileDsl(parsed) {
  return parsed.processList.map((step, index) => {
    const esQuery = conditionToEsQuery(step.condition);
    const timeWindow = parseTimeWindow(step.time);

    return {
      index: step.source === '日志' || step.source === 'log' ? 'log-index' : 'alert-index',
      query: {
        bool: {
          must: esQuery,
          filter: [
            { range: { started_at: timeWindow } }
          ]
        }
      },
      relationship: step.relationship,
      essential: Boolean(step.essential),
      variables: extractVariables(step.condition),
      processUnit: step.processUnit ? compileDsl(step.processUnit) : null
    };
  });
}

/**
 * Convert HQL-style condition to ES query clause.
 * Supports: field = "value", field != "value", field like "pattern",
 *           field1 = "v1" and field2 = "v2", field1 = "v1" or field2 = "v2"
 */
function conditionToEsQuery(condition) {
  if (!condition) return [{ match_all: {} }];

  // Handle AND
  const andParts = splitCondition(condition, ' and ');
  if (andParts.length > 1) {
    return [{ bool: { must: andParts.flatMap((p) => conditionToEsQuery(p)) } }];
  }

  // Handle OR
  const orParts = splitCondition(condition, ' or ');
  if (orParts.length > 1) {
    return [{ bool: { should: orParts.flatMap((p) => conditionToEsQuery(p)), minimum_should_match: 1 } }];
  }

  // Single condition
  return [parseSingleCondition(condition.trim())];
}

function splitCondition(condition, separator) {
  // Simple split that respects quotes
  const parts = [];
  let current = '';
  let inQuote = false;
  let i = 0;

  while (i < condition.length) {
    if (condition[i] === '"') {
      inQuote = !inQuote;
      current += condition[i];
      i++;
    } else if (!inQuote && condition.substring(i, i + separator.length) === separator) {
      parts.push(current);
      current = '';
      i += separator.length;
    } else {
      current += condition[i];
      i++;
    }
  }
  if (current) parts.push(current);
  return parts;
}

function parseSingleCondition(cond) {
  // Match: field like "value" or field = "value" or field != "value"
  const likeMatch = cond.match(/^(\S+)\s+like\s+"([^"]*)"$/i);
  if (likeMatch) {
    const [, field, value] = likeMatch;
    const fieldName = mapFieldToEs(field);
    // Convert like pattern to wildcard: % → *
    const wildcard = value.replace(/%/g, '*');
    return { wildcard: { [fieldName]: { value: wildcard, case_insensitive: true } } };
  }

  const neqMatch = cond.match(/^(\S+)\s*!=\s*"([^"]*)"$/);
  if (neqMatch) {
    const [, field, value] = neqMatch;
    const fieldName = mapFieldToEs(field);
    return { bool: { must_not: [{ term: { [fieldName]: value } }] } };
  }

  const eqMatch = cond.match(/^(\S+)\s*=\s*"([^"]*)"$/);
  if (eqMatch) {
    const [, field, value] = eqMatch;
    const fieldName = mapFieldToEs(field);
    return { term: { [fieldName]: value } };
  }

  // Fallback: match as text
  return { match_phrase: { _all: cond } };
}

/**
 * Map HQL field names to ES field names.
 */
function mapFieldToEs(field) {
  const fieldMap = {
    '主机IP': 'attacker.ip',
    '源地址': 'source_address',
    '目的地址': 'destination_address',
    '源端口': 'source_port',
    '目的端口': 'destination_port',
    '事件名称': 'event_name',
    '事件级别': 'event_level',
    '组织机构': 'organization',
    '告警名称': 'title',
    '告警类型': 'type',
    '攻击者': 'attacker',
    '受害者': 'victim',
    '文件MD5': 'hash.md5',
    '进程pid': 'process.pid',
    '关联分析规则名称': 'rule_name',
    '威胁鉴定结果': 'threat_result',
  };
  return fieldMap[field] || field;
}

/**
 * Parse time window like ["-1h", "+1h"] to ES range format.
 */
function parseTimeWindow(time) {
  if (!Array.isArray(time) || time.length !== 2) {
    return { gte: 'now-1h', lte: 'now' };
  }

  const parseRelative = (t) => {
    if (typeof t !== 'string') return 'now';
    const match = t.match(/^([+-])(\d+)([smhd])$/);
    if (!match) return 'now';
    const [, sign, num, unit] = match;
    const ms = { s: 1000, m: 60000, h: 3600000, d: 86400000 }[unit] || 3600000;
    const offset = parseInt(num) * ms;
    return sign === '-' ? `now-${num}${unit}` : `now+${num}${unit}`;
  };

  return {
    gte: parseRelative(time[0]),
    lte: parseRelative(time[1])
  };
}

// ── DSL Compilation for ES Statement ────────────────────────────────────────

/**
 * Compile DSL to a "statement" that can be stored in PG ice_rule.statement.
 * This is the executable form used by the aggregation engine.
 */
export function compileToStatement(parsed) {
  const steps = compiledStepsToStatement(compileDsl(parsed));
  return JSON.stringify(steps);
}

function compiledStepsToStatement(compiledSteps) {
  return compiledSteps.map((step) => ({
    index: step.index,
    query: step.query,
    relationship: step.relationship,
    essential: step.essential,
    variables: step.variables,
    processUnit: step.processUnit ? compiledStepsToStatement(step.processUnit) : null
  }));
}
