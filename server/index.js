import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const publicDir = path.join(rootDir, 'public');
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || '127.0.0.1';

const now = Date.now();

const attackScenes = [
  { id: 'scan', parentId: null, name: '扫描探测', sceneType: 'ndr', sceneModel: 'scenario' },
  { id: 'host-abnormal', parentId: null, name: '主机异常', sceneType: 'xdr', sceneModel: 'scenario' },
  { id: 'abnormal-comm', parentId: null, name: '异常通信', sceneType: 'xdr', sceneModel: 'scenario' },
  { id: 'vuln-attack', parentId: null, name: '漏洞攻击', sceneType: 'ndr', sceneModel: 'scenario' },
  { id: 'remote-control', parentId: null, name: '远控操控', sceneType: 'xdr', sceneModel: 'scenario' },
  { id: 'web-attack', parentId: null, name: 'Web攻击', sceneType: 'ndr', sceneModel: 'scenario' },
  { id: 'network-attack', parentId: null, name: '网络攻击', sceneType: 'ndr', sceneModel: 'scenario' },
  { id: 'account-abnormal', parentId: null, name: '账号异常', sceneType: 'xdr', sceneModel: 'scenario' },
  { id: 'threat-intel', parentId: null, name: '威胁情报', sceneType: 'xdr', sceneModel: 'scenario' },
  { id: 'mail-attack', parentId: null, name: '邮件攻击', sceneType: 'xdr', sceneModel: 'scenario' },
  { id: 'multi-correlation', parentId: null, name: '多维关联', sceneType: 'xdr', sceneModel: 'scenario' },
  { id: 'content-security', parentId: null, name: '内容安全', sceneType: 'xdr', sceneModel: 'scenario' },
  { id: 'malware', parentId: null, name: '恶意程序', sceneType: 'xdr', sceneModel: 'scenario' }
];

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

const defaultDsl = `processList:
  - condition: 主机IP = "\${主机IP}" and 文件MD5 = "\${文件MD5}"
    source: "告警"
    time: ["-5h", "1h"]
    relationship: "相同的病毒"
  - condition: 目的地址 = "\${源地址}" or 主机IP = "\${主机IP}"
    source: "日志"
    time: ["-1h", "12h"]
    relationship: "相同的受害者地址"`;

let models = [
  {
    id: 'model-001',
    name: '安全设备检测到主机上登录异常',
    description: '将主机异常登录相关告警聚合为安全事件。',
    sceneId: 'host-abnormal',
    sceneName: '主机异常',
    source: 'custom',
    sourceLabel: '自定义模型',
    status: 'running',
    entryAlerts: [
      { key: 'A', condition: '关联分析规则名称 = "安全设备检测到主机上登录异常"' }
    ],
    dsl: defaultDsl,
    active: true,
    notifier: '',
    useEntryAlertNameAsTitle: false,
    updatedAt: '2026-06-09 15:33:43',
    history: [
      { time: '2026-06-09 15:33:43', content: '模型更新' },
      { time: '2026-05-29 09:20:12', content: '模型创建' }
    ]
  },
  {
    id: 'model-002',
    name: '[场景模型]主机上大量文件感染病毒_优化',
    description: '发现主机大量文件感染病毒时聚合相关告警和证据。',
    sceneId: 'malware',
    sceneName: '恶意程序',
    source: 'custom',
    sourceLabel: '自定义模型',
    status: 'running',
    entryAlerts: [
      { key: 'A', condition: '告警名称 like "病毒爆发" and 威胁鉴定结果 != "无风险"' }
    ],
    dsl: defaultDsl,
    active: true,
    notifier: '',
    useEntryAlertNameAsTitle: true,
    updatedAt: '2026-06-15 12:33:51',
    history: [
      { time: '2026-06-15 12:33:51', content: '入口告警更新' }
    ]
  }
];

let logs = Array.from({ length: 36 }).map((_, index) => ({
  id: `log-${String(index + 1).padStart(3, '0')}`,
  occurredAt: new Date(now - index * 60_000).toISOString().slice(0, 19).replace('T', ' '),
  eventName: index % 5 === 0 ? '补丁推送' : 'web访问',
  eventLevel: index % 7 === 0 ? '警告' : '信息',
  organization: '总公司全局',
  sourceAddress: index % 3 === 0 ? '22.200.35.185' : `113.84.209.${228 - index}`,
  destinationAddress: index % 4 === 0 ? '11.120.12.8' : `11.120.25.${139 + index}`,
  sourcePort: String(49000 + index),
  destinationPort: index % 2 === 0 ? '80' : '443',
  raw: `raw log sample ${index + 1}`
}));

let incidents = [
  {
    id: '633593',
    title: '病毒爆发-主机10.239.194.26上大量文件感染病毒_更新',
    severity: 'high',
    severityLabel: '严重',
    attackResult: 'unknown',
    attackResultLabel: '未知',
    category: '恶意程序',
    dataSource: '天擎V10(奇安信)',
    organization: '总公司全局',
    updatedAt: '2026-06-15 12:33:51',
    startTime: '2026-06-15 12:33:23',
    endTime: '2026-06-15 12:33:51',
    owner: '-',
    device: '21.208.3.56',
    modelId: 'model-002',
    modelName: '[场景模型]主机上大量文件感染病毒_优化',
    advice: '隔离主机并对恶意样本进行处置。',
    relatedLogIds: ['log-001'],
    entities: { ip: 1, host: 1, account: 1 },
    alerts: [
      {
        id: 'alert-001',
        startedAt: '2026-06-15 12:33:51',
        severityLabel: '严重',
        title: '检测到病毒 commonRisk/LRS.Autorun.1',
        relation: '相同的病毒',
        type: '恶意程序/其他恶意程序',
        attacker: '-',
        victim: '10.239.194.26',
        tactic: '',
        resultLabel: '未知',
        core: true,
        entry: false
      },
      {
        id: 'alert-002',
        startedAt: '2026-06-15 12:33:23',
        severityLabel: '警告',
        title: '病毒爆发-主机10.239.194.26上大量文件感染病毒_更新',
        relation: '入口告警',
        type: '恶意程序/其他恶意程序',
        attacker: '-',
        victim: '10.239.194.26',
        tactic: '',
        resultLabel: '未知',
        core: false,
        entry: true
      }
    ]
  },
  {
    id: '4142188',
    title: '阿测试编辑',
    severity: 'high',
    severityLabel: '严重',
    attackResult: 'unknown',
    attackResultLabel: '未知',
    category: '主机异常',
    dataSource: 'SIEM',
    organization: '总公司全局',
    updatedAt: '2026-06-09 14:15:28',
    startTime: '2026-06-09 14:15:28',
    endTime: '2026-06-09 14:15:28',
    owner: '-',
    device: '21.208.3.56',
    modelId: 'model-001',
    modelName: '安全设备检测到主机上登录异常',
    advice: '',
    relatedLogIds: [],
    entities: { ip: 1, host: 0, account: 1 },
    alerts: []
  }
];

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

const getScene = (sceneId) => attackScenes.find((scene) => scene.id === sceneId);
const getSeverity = (severity) => dictionaries.severities.find((item) => item.value === severity);

const listModels = (query) => {
  return models.filter((model) => {
    if (query.sceneId && model.sceneId !== query.sceneId) return false;
    if (query.status && model.status !== query.status) return false;
    if (query.source && model.source !== query.source) return false;
    if (query.keyword && !`${model.name} ${model.description}`.includes(query.keyword)) return false;
    return true;
  });
};

const listIncidents = (query) => {
  return incidents.filter((incident) => {
    if (query.keyword && !`${incident.title} ${incident.id}`.includes(query.keyword)) return false;
    if (query.severity && incident.severity !== query.severity) return false;
    if (query.category && incident.category !== query.category) return false;
    return true;
  });
};

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

const router = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const query = Object.fromEntries(url.searchParams.entries());

  try {
    if (pathname === '/api/security/dictionaries' && req.method === 'GET') {
      return json(res, 200, dictionaries);
    }
    if (pathname === '/api/security/attack-scenes/tree' && req.method === 'GET') {
      return json(res, 200, attackScenes);
    }
    if (pathname === '/api/security/models' && req.method === 'GET') {
      return json(res, 200, { items: listModels(query), total: listModels(query).length });
    }
    if (pathname === '/api/security/models' && req.method === 'POST') {
      const body = await parseBody(req);
      const scene = getScene(body.sceneId);
      const model = {
        id: randomUUID(),
        name: body.name,
        description: body.description || '',
        sceneId: body.sceneId,
        sceneName: scene?.name || '',
        source: 'custom',
        sourceLabel: '自定义模型',
        status: body.active ? 'running' : 'stopped',
        entryAlerts: body.entryAlerts || [],
        dsl: body.dsl || '',
        active: Boolean(body.active),
        notifier: body.notifier || '',
        useEntryAlertNameAsTitle: Boolean(body.useEntryAlertNameAsTitle),
        updatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
        history: [{ time: new Date().toISOString().slice(0, 19).replace('T', ' '), content: '模型创建' }]
      };
      models.unshift(model);
      return json(res, 201, model);
    }
    const modelMatch = pathname.match(/^\/api\/security\/models\/([^/]+)$/);
    if (modelMatch && req.method === 'GET') {
      const model = models.find((item) => item.id === modelMatch[1]);
      return model ? json(res, 200, model) : json(res, 404, { message: '模型不存在' });
    }
    if (modelMatch && req.method === 'PUT') {
      const body = await parseBody(req);
      const index = models.findIndex((item) => item.id === modelMatch[1]);
      if (index === -1) return json(res, 404, { message: '模型不存在' });
      const scene = getScene(body.sceneId);
      models[index] = {
        ...models[index],
        ...body,
        sceneName: scene?.name || models[index].sceneName,
        status: body.active ? 'running' : 'stopped',
        updatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
        history: [{ time: new Date().toISOString().slice(0, 19).replace('T', ' '), content: '模型更新' }, ...models[index].history]
      };
      return json(res, 200, models[index]);
    }
    if (modelMatch && req.method === 'DELETE') {
      models = models.filter((item) => item.id !== modelMatch[1]);
      return json(res, 200, { ok: true });
    }
    const modelActionMatch = pathname.match(/^\/api\/security\/models\/([^/]+)\/(enable|disable|history)$/);
    if (modelActionMatch) {
      const model = models.find((item) => item.id === modelActionMatch[1]);
      if (!model) return json(res, 404, { message: '模型不存在' });
      if (modelActionMatch[2] === 'history' && req.method === 'GET') return json(res, 200, model.history);
      if (req.method === 'POST') {
        model.status = modelActionMatch[2] === 'enable' ? 'running' : 'stopped';
        model.active = model.status === 'running';
        model.updatedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
        return json(res, 200, model);
      }
    }
    if (pathname === '/api/security/models/validate' && req.method === 'POST') {
      const body = await parseBody(req);
      const ok = Boolean(body.dsl && body.dsl.includes('processList'));
      return json(res, ok ? 200 : 400, ok ? { ok: true } : { message: 'DSL 必须包含 processList' });
    }
    if (pathname === '/api/security/incidents' && req.method === 'GET') {
      const items = listIncidents(query);
      const stats = dictionaries.severities.reduce((acc, severity) => {
        acc[severity.value] = incidents.filter((incident) => incident.severity === severity.value).length;
        return acc;
      }, { total: incidents.length });
      return json(res, 200, { items, total: items.length, stats });
    }
    if (pathname === '/api/security/incidents' && req.method === 'POST') {
      const body = await parseBody(req);
      const scene = getScene(body.sceneId);
      const severity = getSeverity(body.severity);
      const incident = {
        id: String(Math.floor(100000 + Math.random() * 900000)),
        title: body.title,
        severity: body.severity,
        severityLabel: severity?.label || '提醒',
        attackResult: 'unknown',
        attackResultLabel: '未知',
        category: scene?.name || '',
        dataSource: '人工创建',
        organization: '总公司全局',
        updatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
        startTime: new Date().toISOString().slice(0, 19).replace('T', ' '),
        endTime: new Date().toISOString().slice(0, 19).replace('T', ' '),
        owner: body.owner || '-',
        device: '-',
        modelId: null,
        modelName: '人工创建',
        advice: body.advice || '',
        relatedLogIds: body.logIds || [],
        entities: { ip: 0, host: 0, account: 0 },
        alerts: (body.logIds || []).map((logId) => {
          const log = logs.find((item) => item.id === logId);
          return {
            id: `manual-${logId}`,
            startedAt: log?.occurredAt || '',
            severityLabel: body.severity,
            title: log?.eventName || '关联日志',
            relation: '人工关联',
            type: log?.eventLevel || '',
            attacker: log?.sourceAddress || '',
            victim: log?.destinationAddress || '',
            tactic: '',
            resultLabel: '未知',
            core: false,
            entry: true
          };
        })
      };
      incidents.unshift(incident);
      return json(res, 201, incident);
    }
    if (pathname === '/api/security/incidents/table-fields' && req.method === 'GET') {
      return json(res, 200, tableFields);
    }
    const incidentMatch = pathname.match(/^\/api\/security\/incidents\/([^/]+)(?:\/([^/]+))?$/);
    if (incidentMatch && req.method === 'GET') {
      const incident = incidents.find((item) => item.id === incidentMatch[1]);
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
            suspiciousFile: incident.alerts.length * 5
          }
        });
      }
      if (section === 'alerts') return json(res, 200, { items: incident.alerts, total: incident.alerts.length });
      if (section === 'graph') {
        const graphNodes = [
          { id: incident.id, label: incident.title, type: '事件', risk: incident.severityLabel }
        ];
        const graphEdges = [];
        const addedIds = new Set([incident.id]);
        const addNode = (id, label, type, risk) => {
          if (!addedIds.has(id)) { addedIds.add(id); graphNodes.push({ id, label, type, risk }); }
        };
        incident.alerts.forEach((alert) => {
          addNode(alert.id, alert.title, '告警', alert.severityLabel);
          graphEdges.push({ from: incident.id, to: alert.id, label: alert.relation });
        });
        const alertVictims = [...new Set(incident.alerts.map((a) => a.victim).filter(Boolean))];
        const alertAttackers = [...new Set(incident.alerts.map((a) => a.attacker).filter(Boolean))];
        alertVictims.forEach((ip, i) => {
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
        if (incident.alerts.length > 0 && incident.alerts[0].victim) {
          const accId = `acc-${incident.id}`;
          addNode(accId, `admin_${incident.id.slice(-3)}`, '账号', '高风险');
          graphEdges.push({ from: `ip-${incident.alerts[0].victim}`, to: accId, label: '登录' });
        }
        if (incident.alerts.some((a) => a.core)) {
          const fileId = `file-${incident.id}`;
          addNode(fileId, 'malware_sample.exe', '文件', '严重');
          graphEdges.push({ from: `host-${(alertVictims[0] || 'unknown')}`, to: fileId, label: '感染' });
        }
        return json(res, 200, { nodes: graphNodes, edges: graphEdges });
      }
      if (section === 'evidence') {
        const hasAlerts = incident.alerts.length > 0;
        return json(res, 200, {
          malware: hasAlerts ? incident.alerts.filter((a) => a.core).map((a, i) => ({
            md5: `e3b0c44298fc1c149${String(i + 1).padStart(2, '0')}a7a3c6aa06a00ce43800${String(50 + i).padStart(2, '0')}8b0c64b50d05237e9c9fe6f3fb4274f9`,
            name: a.title.replace(/检测到|病毒/g, '').trim().slice(0, 20) || `malware_${i + 1}.exe`,
            type: a.type || '恶意程序',
            risk: a.severityLabel || '严重',
            detectedAt: a.startedAt,
            source: incident.dataSource
          })) : [{ md5: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', name: 'sample.exe', type: '其他', risk: '未知', detectedAt: incident.startTime, source: incident.dataSource }],
          intelligence: hasAlerts ? [
            { id: `intel-${incident.id}-1`, indicator: incident.alerts[0]?.victim || '10.0.0.1', type: 'IP', source: '微步在线', confidence: '高', matchedAt: incident.startTime },
            { id: `intel-${incident.id}-2`, indicator: `malware_hash_${incident.id}`, type: '文件哈希', source: 'VirusTotal', confidence: '中', matchedAt: incident.startTime }
          ] : [],
          suspiciousFiles: hasAlerts ? [
            { path: 'C:\\Windows\\Temp\\update.exe', md5: 'a1b2c3d4e5f678901234567890123456', size: '245KB', risk: '可疑', matchedAt: incident.startTime },
            { path: 'C:\\Users\\Public\\svchost.exe', md5: 'f6e5d4c3b2a109876543210987654321', size: '1.2MB', risk: '高危', matchedAt: incident.startTime }
          ] : []
        });
      }
      if (section === 'impact') {
        const alertVictims = [...new Set(incident.alerts.map((a) => a.victim).filter(Boolean))];
        const alertAttackers = [...new Set(incident.alerts.map((a) => a.attacker).filter(Boolean))];
        return json(res, 200, {
          hosts: alertVictims.length > 0 ? alertVictims.map((ip, i) => ({
            id: `host-${String(i + 1).padStart(4, '0')}`,
            name: `win-pc-${ip.split('.').pop()}`,
            ip: ip,
            os: 'Windows 10',
            risk: incident.severity === 'critical' || incident.severity === 'high' ? '高风险' : '中风险',
            compromised: i === 0 ? '已失陷' : '疑似失陷',
            exposure: i === 0 ? '72小时' : '24小时',
            count: 50 + i * 30,
            firstSeen: incident.startTime,
            lastSeen: incident.endTime
          })) : [{ id: '894856-97cf', name: 'win7-2022moqete', ip: '10.239.194.26', os: 'Windows 7', risk: '无风险', compromised: '正常', exposure: '无', count: 191, firstSeen: '2026-05-28 08:51:54', lastSeen: incident.endTime }],
          ips: alertVictims.length > 1 ? alertVictims.slice(1).map((ip, i) => ({
            id: `ip-${String(i + 1).padStart(4, '0')}`,
            ip: ip,
            type: '内网IP',
            risk: '中风险',
            owner: '总公司全局',
            firstSeen: incident.startTime,
            lastSeen: incident.endTime,
            count: 20 + i * 10
          })) : [],
          accounts: incident.alerts.length > 0 ? [
            { id: `acc-${incident.id}-1`, name: `admin_${incident.id.slice(-3)}`, domain: 'PSBC', risk: '高风险', compromised: '已失陷', lastSeen: incident.endTime, count: 5 },
            { id: `acc-${incident.id}-2`, name: `svc_backup`, domain: 'PSBC', risk: '中风险', compromised: '疑似失陷', lastSeen: incident.endTime, count: 2 }
          ] : []
        });
      }
    }
    if (pathname === '/api/security/logs/search' && req.method === 'POST') {
      const body = await parseBody(req);
      const keyword = body.keyword || body.hql || '';
      const items = logs.filter((log) => !keyword || JSON.stringify(log).includes(keyword.replaceAll('"', '')));
      return json(res, 200, { items: items.slice(0, 20), total: items.length });
    }
    if (pathname === '/api/security/logs/templates' && req.method === 'GET') {
      return json(res, 200, [
        { id: 'default', name: '日志检索模板', fields: ['occurredAt', 'eventName', 'eventLevel', 'organization', 'sourceAddress', 'destinationAddress'] }
      ]);
    }
    return sendStatic(req, res, pathname);
  } catch (error) {
    console.error(error);
    return json(res, 500, { message: error.message });
  }
};

http.createServer(router).listen(port, host, () => {
  console.log(`event-security listening on http://${host}:${port}`);
});
