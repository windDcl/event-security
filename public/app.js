const state = {
  route: location.hash || '#/incidents',
  dictionaries: null,
  scenes: [],
  selectedSceneId: '',
  incidents: [],
  incidentStats: {},
  models: [],
  auditLogs: [],
  auditTotal: 0,
  auditPage: 1,
  toast: ''
};

const app = document.querySelector('#app');

const api = async (path, options = {}) => {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || '请求失败');
  return data;
};

const h = (strings, ...values) => strings.reduce((acc, item, index) => acc + item + (values[index] ?? ''), '');
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[char]));

const toast = (message) => {
  state.toast = message;
  render();
  setTimeout(() => {
    state.toast = '';
    render();
  }, 1800);
};

const loadBase = async () => {
  if (!state.dictionaries) {
    const [dict, scenes] = await Promise.all([
      api('/api/security/dictionaries'),
      api('/api/security/attack-scenes/tree')
    ]);
    state.dictionaries = dict;
    state.scenes = scenes;
  }
};

const setRoute = (route) => {
  location.hash = route;
};

window.addEventListener('hashchange', () => {
  state.route = location.hash || '#/incidents';
  render();
});

const shell = (content) => h`
  <div class="app-shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark"></div>
        <div>
          <strong>网络安全大数据</strong>
          <span>POSTAL SAVINGS BANK OF CHINA</span>
        </div>
      </div>
      <nav class="top-nav">
        ${['首页', '数据接入', '数据存储', '数据计算', '安全引擎', '智能检索', '服务接口', '系统管理', '分析报表', '用户异常行为分析'].map((item) => `<a class="${item === '安全引擎' ? 'active' : ''}">${item}</a>`).join('')}
      </nav>
      <div class="user-pill"></div>
    </header>
    <div class="layout">
      <aside class="sidebar">
        <p class="side-title">安全引擎</p>
        <div class="side-group">
          <div class="side-group-title">资源分析引擎</div>
          <div class="side-group-title">实体分析引擎</div>
          <div class="side-group-title">XDR关联分析引擎</div>
          <div class="side-group-title">事件聚合分析引擎</div>
          <a href="#/incidents" class="side-link ${state.route.startsWith('#/incidents') ? 'active' : ''}">安全事件</a>
          <a href="#/models" class="side-link ${state.route.startsWith('#/models') ? 'active' : ''}">安全事件模型</a>
          <a href="#/audit" class="side-link ${state.route.startsWith('#/audit') ? 'active' : ''}">审计日志</a>
          <div class="side-group-title">历史回溯分析</div>
          <div class="side-group-title">运维监控</div>
        </div>
      </aside>
      <main class="content">${content}</main>
    </div>
  </div>
  ${state.toast ? `<div class="toast">${esc(state.toast)}</div>` : ''}
`;

const options = (items, selected = '') => items.map((item) => `<option value="${esc(item.value ?? item.id)}" ${(item.value ?? item.id) === selected ? 'selected' : ''}>${esc(item.label ?? item.name)}</option>`).join('');
const sceneOptions = (selected = '') => `<option value="">请选择</option>${state.scenes.map((item) => `<option value="${esc(item.id)}" ${item.id === selected ? 'selected' : ''}>${esc(item.name)}</option>`).join('')}`;

const renderIncidents = async () => {
  await loadBase();
  const keyword = document.querySelector('[data-incident-keyword]')?.value || '';
  const severity = document.querySelector('[data-incident-severity]')?.value || '';
  const params = new URLSearchParams();
  if (keyword) params.set('keyword', keyword);
  if (severity) params.set('severity', severity);
  const data = await api(`/api/security/incidents?${params}`);
  state.incidents = data.items;
  state.incidentStats = data.stats;

  const visibleCols = getVisibleColumns() || ['id','title','severityLabel','attackResultLabel','entities','organization','updatedAt'];
  return h`
    <div class="page-head">
      <h1>安全事件</h1>
      <div class="actions">
        <button class="btn primary" data-create-incident>+ 创建安全事件</button>
        <button class="btn" data-table-fields>⚙ 配置表格字段</button>
      </div>
    </div>
    <section class="panel">
      <div class="filter-grid">
        <div class="field">
          <label>时间范围</label>
          <select><option>最近1年</option><option>最近15分钟</option></select>
        </div>
        <div class="field">
          <label>标题 / 编号</label>
          <input data-incident-keyword placeholder="输入标题或编号">
        </div>
        <div class="field">
          <label>严重等级</label>
          <select data-incident-severity><option value="">全部</option>${options(state.dictionaries.severities, severity)}</select>
        </div>
        <div class="actions">
          <button class="btn primary" data-search-incidents>搜索</button>
          <button class="btn" data-open-hql>HQL</button>
          <button class="btn ghost" data-reset-incidents>清空</button>
        </div>
      </div>
      <div class="stats">
        <div class="stat"><strong>${data.stats.total}</strong><span>总数</span></div>
        <div class="stat"><strong>${data.stats.critical}</strong><span>紧急</span></div>
        <div class="stat"><strong>${data.stats.high}</strong><span>严重</span></div>
        <div class="stat"><strong>${data.stats.medium}</strong><span>警告</span></div>
        <div class="stat"><strong>${data.stats.low}</strong><span>提醒</span></div>
      </div>
    </section>
    <section class="panel table-wrap">
      <table>
        <thead>
          <tr>
            <th><input type="checkbox"></th>
            ${visibleCols.includes('id') ? '<th>编号</th>' : ''}
            ${visibleCols.includes('title') ? '<th>标题</th>' : ''}
            ${visibleCols.includes('severityLabel') ? '<th>严重等级</th>' : ''}
            ${visibleCols.includes('attackResultLabel') ? '<th>攻击结果</th>' : ''}
            ${visibleCols.includes('category') ? '<th>分类</th>' : ''}
            ${visibleCols.includes('dataSource') ? '<th>数据源</th>' : ''}
            ${visibleCols.includes('entities') ? '<th>影响实体</th>' : ''}
            ${visibleCols.includes('organization') ? '<th>组织机构</th>' : ''}
            ${visibleCols.includes('updatedAt') ? '<th>更新时间</th>' : ''}
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          ${data.items.map((item) => `
            <tr>
              <td><input type="checkbox"></td>
              ${visibleCols.includes('id') ? `<td>#${esc(item.id)}</td>` : ''}
              ${visibleCols.includes('title') ? `<td>${esc(item.title)}</td>` : ''}
              ${visibleCols.includes('severityLabel') ? `<td><span class="tag ${esc(item.severity)}">${esc(item.severityLabel)}</span></td>` : ''}
              ${visibleCols.includes('attackResultLabel') ? `<td><span class="tag">${esc(item.attackResultLabel)}</span></td>` : ''}
              ${visibleCols.includes('category') ? `<td>${esc(item.category)}</td>` : ''}
              ${visibleCols.includes('dataSource') ? `<td>${esc(item.dataSource)}</td>` : ''}
              ${visibleCols.includes('entities') ? `<td>IP ${item.entities.ip}　主机 ${item.entities.host}　账号 ${item.entities.account}</td>` : ''}
              ${visibleCols.includes('organization') ? `<td>${esc(item.organization)}</td>` : ''}
              ${visibleCols.includes('updatedAt') ? `<td>${esc(item.updatedAt)}</td>` : ''}
              <td><button class="link-btn" data-incident-detail="${esc(item.id)}">详情</button>　<button class="link-btn" data-incident-graph="${esc(item.id)}">攻击图谱</button></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </section>
  `;
};

const renderModels = async () => {
  await loadBase();
  const sceneId = state.selectedSceneId;
  const params = new URLSearchParams();
  if (sceneId) params.set('sceneId', sceneId);
  const data = await api(`/api/security/models?${params}`);
  state.models = data.items;

  return h`
    <div class="page-head">
      <h1>安全事件模型</h1>
      <div class="actions">
        <button class="btn primary" data-model-new>+ 新建</button>
        <button class="btn" data-model-import>导入</button>
        <button class="btn" data-model-export-all>导出</button>
      </div>
    </div>
    <div class="split">
      <section class="panel">
        <strong>模型分类</strong>
        <div class="category-list" style="margin-top:10px">
          <button class="${!sceneId ? 'active' : ''}" data-scene="">全部</button>
          ${state.scenes.map((scene) => `<button class="${sceneId === scene.id ? 'active' : ''}" data-scene="${esc(scene.id)}">${esc(scene.name)}</button>`).join('')}
        </div>
      </section>
      <section class="panel table-wrap">
        <div class="filter-grid" style="margin-bottom:12px">
          <div class="field"><label>模型名称</label><input placeholder="输入模型名称"></div>
          <div class="field"><label>模型来源</label><select><option>全部</option>${options(state.dictionaries.modelSources)}</select></div>
          <div class="field"><label>运行状态</label><select><option>全部</option>${options(state.dictionaries.modelStatuses)}</select></div>
          <div class="actions"><button class="btn primary">搜索</button></div>
        </div>
        <table>
          <thead><tr><th><input type="checkbox"></th><th>模型名称</th><th>攻击场景</th><th>状态</th><th>模型来源</th><th>更新时间</th><th>操作</th></tr></thead>
          <tbody>
            ${data.items.map((item) => `
              <tr>
                <td><input type="checkbox"></td>
                <td>${esc(item.name)}</td>
                <td>${esc(item.sceneName)}</td>
                <td><span class="tag ${esc(item.status)}">${item.status === 'running' ? '运行' : '停用'}</span></td>
                <td>${esc(item.sourceLabel)}</td>
                <td>${esc(item.updatedAt)}</td>
                <td>
                  <button class="link-btn" data-model-detail="${esc(item.id)}">详情</button>　
                  <button class="link-btn" data-model-edit="${esc(item.id)}">编辑</button>　
                  <button class="link-btn" data-model-toggle="${esc(item.id)}" data-status="${esc(item.status)}">${item.status === 'running' ? '停用' : '启用'}</button>　
                  <button class="link-btn" data-model-export="${esc(item.id)}">导出</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </section>
    </div>
  `;
};

const modelFormHtml = (model = {}) => h`
  <div class="page-head">
    <h1>${model.id ? '编辑模型' : '新建模型'}</h1>
    <div class="actions">
      <button class="btn ghost" data-model-cancel>取消</button>
      <button class="btn primary" data-model-save="${esc(model.id || '')}">保存</button>
    </div>
  </div>
  <section class="panel">
    <div class="form-grid">
      <div class="field wide"><label>模型名称 *</label><input data-form-name value="${esc(model.name || '')}"></div>
      <div class="field wide"><label><input type="checkbox" data-form-use-title ${model.useEntryAlertNameAsTitle ? 'checked' : ''}> 使用入口告警名称替代模型名称作为安全事件标题</label></div>
      <div class="field wide"><label>模型描述</label><textarea data-form-description>${esc(model.description || '')}</textarea></div>
      <div class="field"><label>攻击场景 *</label><select data-form-scene>${sceneOptions(model.sceneId || '')}</select></div>
      <div class="field"><label>模型来源</label><input value="${esc(model.sourceLabel || '自定义模型')}" disabled></div>
      <div class="field wide">
        <label>入口告警 *</label>
        <div data-entry-list>
          ${(model.entryAlerts?.length ? model.entryAlerts : [{ key: 'A', condition: '' }]).map((entry, index) => `
            <div class="entry-alert">
              <strong>${String.fromCharCode(65 + index)}</strong>
              <input data-entry-condition value="${esc(entry.condition)}" placeholder="输入 HQL 检索语句或关联分析规则表达式">
              <button class="btn ghost" data-remove-entry>删除</button>
            </div>
          `).join('')}
        </div>
        <button class="btn" data-add-entry>添加</button>
      </div>
      <div class="field wide"><label>模型 DSL *</label><textarea class="code-editor" data-form-dsl>${esc(model.dsl || 'processList:\\n  - condition: 主机IP = \"${主机IP}\"\\n    source: \"告警\"\\n    time: [\"-1h\", \"1h\"]\\n    relationship: \"相同的主机\"')}</textarea></div>
      <div class="field"><label>激活</label><select data-form-active><option value="true" ${model.active !== false ? 'selected' : ''}>是</option><option value="false" ${model.active === false ? 'selected' : ''}>否</option></select></div>
      <div class="field"><label>通知对象</label><input data-form-notifier value="${esc(model.notifier || '')}"></div>
    </div>
  </section>
`;

const renderModelForm = async (id) => {
  await loadBase();
  const model = id ? await api(`/api/security/models/${id}`) : {};
  return modelFormHtml(model);
};

const renderModelDetail = async (id) => {
  const model = await api(`/api/security/models/${id}`);
  const history = await api(`/api/security/models/${id}/history`);
  return h`
    <div class="page-head">
      <h1>[场景模型]${esc(model.name)}</h1>
      <div class="actions"><button class="btn primary" data-model-edit="${esc(model.id)}">编辑</button><button class="btn ghost" data-back-models>返回</button></div>
    </div>
    <section class="panel">
      <div class="form-grid">
        <div><strong>模型名称</strong><p>${esc(model.name)}</p></div>
        <div><strong>攻击场景</strong><p>${esc(model.sceneName)}</p></div>
        <div><strong>模型来源</strong><p>${esc(model.sourceLabel)}</p></div>
        <div><strong>激活</strong><p>${model.active ? '是' : '否'}</p></div>
        <div class="wide"><strong>模型描述</strong><p>${esc(model.description)}</p></div>
        <div class="wide"><strong>入口告警</strong><p>${model.entryAlerts.map((entry) => esc(entry.condition)).join('<br>')}</p></div>
        <div class="wide"><strong>模型</strong><textarea class="code-editor" readonly>${esc(model.dsl)}</textarea></div>
      </div>
    </section>
    <section class="panel">
      <h2>模型历史</h2>
      ${history.map((item) => `<p><strong>${esc(item.time)}</strong>　${esc(item.content)}</p>`).join('')}
    </section>
  `;
};

const renderIncidentDetail = async (id, tab = 'overview') => {
  const incident = await api(`/api/security/incidents/${id}`);
  const tabLabels = { overview: '概览', alerts: '告警', graph: '威胁图谱', evidence: '相关证据', impact: '影响面' };
  const detail = await api(`/api/security/incidents/${id}/${tab}`);
  const tabContent = {
    overview: () => {
      const phaseKeys = Object.keys(detail.phases);
      const activePhases = phaseKeys.filter((k) => detail.phases[k] > 0);
      const totalPhases = phaseKeys.length;
      return `
      <div class="cards">
        <div class="card"><strong>${detail.alertCount}</strong><p>告警总量</p></div>
        <div class="card"><strong>${detail.coreAlertCount || 0}</strong><p>核心告警</p></div>
        <div class="card"><strong>${detail.entities.ip}</strong><p>内网 IP</p></div>
        <div class="card"><strong>${detail.entities.host}</strong><p>主机</p></div>
      </div>
      <h3 style="margin:18px 0 10px;font-size:15px">攻击阶段</h3>
      <div class="kill-chain">
        ${phaseKeys.map((key, i) => {
          const label = detail.phaseLabels[key] || key;
          const active = detail.phases[key] > 0;
          return `<div class="kill-phase ${active ? 'active' : ''}">
            <div class="kill-dot"></div>
            <span>${esc(label)}</span>
            ${i < phaseKeys.length - 1 ? '<div class="kill-line"></div>' : ''}
          </div>`;
        }).join('')}
      </div>
      <h3 style="margin:18px 0 10px;font-size:15px">ATT&CK 技战术</h3>
      <div class="attack-grid">
        ${(detail.attack.tactics || []).map((t) => `
          <div class="attack-tactic ${t.count > 0 ? 'active' : ''}">
            <div class="attack-id">${esc(t.id)}</div>
            <div class="attack-name">${esc(t.name)}</div>
            ${t.count > 0 ? `<div class="attack-count">${t.count}</div>` : ''}
          </div>
        `).join('')}
      </div>
      <h3 style="margin:18px 0 10px;font-size:15px">证据概览</h3>
      <div class="cards" style="grid-template-columns:repeat(3,1fr)">
        <div class="card"><strong>${detail.evidence.intelligence}</strong><p>威胁情报</p></div>
        <div class="card"><strong>${detail.evidence.malware}</strong><p>恶意样本</p></div>
        <div class="card"><strong>${detail.evidence.suspiciousFile}</strong><p>可疑文件</p></div>
      </div>
    `;},
    alerts: () => `
      <div class="table-wrap"><table>
        <thead><tr><th>开始时间</th><th>等级</th><th>告警名称</th><th>关联条件</th><th>受害者</th><th>攻击结果</th><th>标识</th></tr></thead>
        <tbody>${detail.items.map((item) => `<tr><td>${esc(item.startedAt)}</td><td><span class="tag high">${esc(item.severityLabel)}</span></td><td>${esc(item.title)}</td><td>${esc(item.relation)}</td><td>${esc(item.victim)}</td><td>${esc(item.resultLabel)}</td><td>${item.core ? '核心告警' : ''} ${item.entry ? '入口告警' : ''}</td></tr>`).join('')}</tbody>
      </table></div>
    `,
    graph: () => {
      const nodeTypes = [...new Set(detail.nodes.map((n) => n.type))];
      return `
      <div class="graph-controls">
        <span class="graph-label">节点筛选：</span>
        ${nodeTypes.map((t) => `<button class="graph-filter active" data-graph-filter="${esc(t)}">${esc(t)}</button>`).join('')}
        <span class="graph-stats">${detail.nodes.length} 个节点、${detail.edges.length} 条关系</span>
      </div>
      <div id="threat-graph" style="height:480px;border:1px solid var(--line);border-radius:8px;background:#fbfcfd"></div>
      <script>window.__graphData=${JSON.stringify(detail)};</script>
    `;},
    evidence: () => {
      const evidenceTab = state.evidenceTab || 'malware';
      const tabs = [
        { key: 'intelligence', label: '威胁情报', count: detail.intelligence.length },
        { key: 'malware', label: '恶意样本', count: detail.malware.length },
        { key: 'suspiciousFiles', label: '可疑文件', count: detail.suspiciousFiles.length }
      ];
      const intelTable = detail.intelligence.length > 0
        ? `<div class="table-wrap"><table><thead><tr><th>指标</th><th>类型</th><th>来源</th><th>置信度</th><th>匹配时间</th><th>操作</th></tr></thead><tbody>${detail.intelligence.map((item) => `<tr><td>${esc(item.indicator)}</td><td>${esc(item.type)}</td><td>${esc(item.source)}</td><td>${esc(item.confidence)}</td><td>${esc(item.matchedAt)}</td><td><button class="link-btn">查看告警</button></td></tr>`).join('')}</tbody></table></div>`
        : '<div class="empty">暂无威胁情报数据</div>';
      const malwareTable = detail.malware.length > 0
        ? `<div class="table-wrap"><table><thead><tr><th>文件MD5</th><th>文件名称</th><th>恶意类型</th><th>风险等级</th><th>检测时间</th><th>数据源</th><th>操作</th></tr></thead><tbody>${detail.malware.map((item) => `<tr><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(item.md5)}">${esc(item.md5)}</td><td>${esc(item.name)}</td><td>${esc(item.type)}</td><td><span class="tag ${esc(item.risk) === '严重' ? 'high' : esc(item.risk) === '警告' ? 'medium' : ''}">${esc(item.risk)}</span></td><td>${esc(item.detectedAt)}</td><td>${esc(item.source)}</td><td><button class="link-btn" data-evidence-alert>查看告警</button>　<button class="link-btn" data-evidence-download>下载</button></td></tr>`).join('')}</tbody></table></div>`
        : '<div class="empty">暂无恶意样本数据</div>';
      const suspiciousTable = detail.suspiciousFiles.length > 0
        ? `<div class="table-wrap"><table><thead><tr><th>文件路径</th><th>MD5</th><th>文件大小</th><th>风险等级</th><th>匹配时间</th><th>操作</th></tr></thead><tbody>${detail.suspiciousFiles.map((item) => `<tr><td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(item.path)}">${esc(item.path)}</td><td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(item.md5)}</td><td>${esc(item.size)}</td><td><span class="tag ${esc(item.risk) === '高危' ? 'high' : 'medium'}">${esc(item.risk)}</span></td><td>${esc(item.matchedAt)}</td><td><button class="link-btn" data-evidence-download>下载</button></td></tr>`).join('')}</tbody></table></div>`
        : '<div class="empty">暂无可疑文件数据</div>';
      const contentMap = { intelligence: intelTable, malware: malwareTable, suspiciousFiles: suspiciousTable };
      return `
      <div class="evidence-tabs">${tabs.map((t) => `<button class="evidence-tab ${evidenceTab === t.key ? 'active' : ''}" data-evidence-tab="${t.key}">${esc(t.label)} (${t.count})</button>`).join('')}</div>
      <div style="margin-top:12px">${contentMap[evidenceTab]}</div>
    `;},
    impact: () => {
      const impactTab = state.impactTab || 'hosts';
      const tabs = [
        { key: 'hosts', label: '主机', count: detail.hosts.length },
        { key: 'ips', label: '内网IP', count: detail.ips.length },
        { key: 'accounts', label: '账号', count: detail.accounts.length }
      ];
      const hostTable = detail.hosts.length > 0
        ? `<div class="table-wrap"><table><thead><tr><th>主机标识</th><th>主机名称</th><th>IP地址</th><th>操作系统</th><th>风险等级</th><th>是否失陷</th><th>持续暴露期</th><th>出现次数</th><th>首次发现</th><th>最近发现</th><th>操作</th></tr></thead><tbody>${detail.hosts.map((item) => `<tr><td>${esc(item.id)}</td><td>${esc(item.name)}</td><td>${esc(item.ip)}</td><td>${esc(item.os)}</td><td><span class="tag ${esc(item.risk) === '高风险' ? 'high' : esc(item.risk) === '中风险' ? 'medium' : 'low'}">${esc(item.risk)}</span></td><td><span class="tag ${esc(item.compromised) === '已失陷' ? 'critical' : esc(item.compromised) === '疑似失陷' ? 'high' : 'low'}">${esc(item.compromised)}</span></td><td>${esc(item.exposure)}</td><td>${esc(item.count)}</td><td>${esc(item.firstSeen)}</td><td>${esc(item.lastSeen)}</td><td><button class="link-btn" data-impact-detail>查看详情</button>　<button class="link-btn" data-impact-alerts>查看告警</button></td></tr>`).join('')}</tbody></table></div>`
        : '<div class="empty">暂无受影响主机</div>';
      const ipTable = detail.ips.length > 0
        ? `<div class="table-wrap"><table><thead><tr><th>IP地址</th><th>类型</th><th>风险等级</th><th>所属组织</th><th>首次发现</th><th>最近发现</th><th>出现次数</th><th>操作</th></tr></thead><tbody>${detail.ips.map((item) => `<tr><td>${esc(item.ip)}</td><td>${esc(item.type)}</td><td><span class="tag medium">${esc(item.risk)}</span></td><td>${esc(item.owner)}</td><td>${esc(item.firstSeen)}</td><td>${esc(item.lastSeen)}</td><td>${esc(item.count)}</td><td><button class="link-btn" data-impact-detail>查看详情</button>　<button class="link-btn" data-impact-alerts>查看告警</button></td></tr>`).join('')}</tbody></table></div>`
        : '<div class="empty">暂无受影响内网IP</div>';
      const accountTable = detail.accounts.length > 0
        ? `<div class="table-wrap"><table><thead><tr><th>账号</th><th>域</th><th>风险等级</th><th>是否失陷</th><th>最近活跃</th><th>操作次数</th><th>操作</th></tr></thead><tbody>${detail.accounts.map((item) => `<tr><td>${esc(item.name)}</td><td>${esc(item.domain)}</td><td><span class="tag ${esc(item.risk) === '高风险' ? 'high' : 'medium'}">${esc(item.risk)}</span></td><td><span class="tag ${esc(item.compromised) === '已失陷' ? 'critical' : 'high'}">${esc(item.compromised)}</span></td><td>${esc(item.lastSeen)}</td><td>${esc(item.count)}</td><td><button class="link-btn" data-impact-detail>查看详情</button>　<button class="link-btn" data-impact-alerts>查看告警</button></td></tr>`).join('')}</tbody></table></div>`
        : '<div class="empty">暂无受影响账号</div>';
      const contentMap = { hosts: hostTable, ips: ipTable, accounts: accountTable };
      return `
      <div class="evidence-tabs">${tabs.map((t) => `<button class="evidence-tab ${impactTab === t.key ? 'active' : ''}" data-impact-tab="${t.key}">${esc(t.label)} (${t.count})</button>`).join('')}</div>
      <div style="margin-top:12px">${contentMap[impactTab]}</div>
    `;}
  }[tab];
  return h`
    <div class="detail-head panel">
      <div>
        <div class="detail-title"><span class="tag ${esc(incident.severity)}">${esc(incident.severityLabel)}</span><h1>#${esc(incident.id)}　${esc(incident.title)}</h1></div>
        <div class="meta-row">
          <span>开始时间：<strong>${esc(incident.startTime)}</strong></span>
          <span>结束时间：<strong>${esc(incident.endTime)}</strong></span>
          <span>责任人：<strong>${esc(incident.owner)}</strong></span>
          <span>数据源：<strong>${esc(incident.dataSource)}</strong></span>
          <span>安全事件模型：<strong>${esc(incident.modelName)}</strong></span>
        </div>
      </div>
      <div class="actions"><button class="btn">编辑</button><button class="btn primary">+ 添加日志/告警</button></div>
    </div>
    <div class="tabs">
      ${Object.entries(tabLabels).map(([key, label]) => `<button class="tab ${tab === key ? 'active' : ''}" data-incident-tab="${key}" data-id="${esc(id)}">${label}</button>`).join('')}
    </div>
    <section class="panel">${tabContent()}</section>
  `;
};

const openLogModal = ({ createMode = false } = {}) => {
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal large">
      <div class="modal-head"><h2>${createMode ? '创建安全事件 - 选择日志/事件' : '日志查询'}</h2><button class="btn ghost" data-close-modal>关闭</button></div>
      <div class="log-layout">
        <aside class="panel">
          <strong>字段模板</strong>
          <div class="field-list" style="margin-top:10px">
            ${['发生时间', '事件名称', '事件级别', '组织机构', '源地址', '目的地址', '源端口', '目的端口', '数据源', '原始日志'].map((field, index) => `<label><input type="checkbox" ${index < 6 ? 'checked' : ''}>${field}</label>`).join('')}
          </div>
        </aside>
        <div>
          <div class="filter-grid">
            <div class="field"><label>时间范围</label><select data-log-time><option>最近15分钟</option><option>最近1小时</option></select></div>
            <div class="field wide"><label>HQL</label><input data-log-hql placeholder='源地址 like "21.9.197.42"'></div>
            <div class="actions"><button class="btn primary" data-log-search>搜索</button><button class="btn ghost" data-log-clear>清空</button></div>
          </div>
          <div class="table-wrap" style="margin-top:12px" data-log-results></div>
          <div class="actions" style="justify-content:flex-end;margin-top:12px">${createMode ? '<button class="btn primary" data-log-next>下一步</button>' : ''}</div>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);

  const search = async () => {
    const hql = modal.querySelector('[data-log-hql]').value;
    const data = await api('/api/security/logs/search', { method: 'POST', body: JSON.stringify({ hql }) });
    modal.querySelector('[data-log-results]').innerHTML = `
      <table><thead><tr><th><input type="checkbox"></th><th>发生时间</th><th>事件名称</th><th>事件级别</th><th>组织机构</th><th>源地址</th><th>目的地址</th><th>操作</th></tr></thead>
      <tbody>${data.items.map((item) => `<tr><td><input type="checkbox" data-log-check="${esc(item.id)}"></td><td>${esc(item.occurredAt)}</td><td>${esc(item.eventName)}</td><td>${esc(item.eventLevel)}</td><td>${esc(item.organization)}</td><td>${esc(item.sourceAddress)}</td><td>${esc(item.destinationAddress)}</td><td><button class="link-btn">详情</button></td></tr>`).join('')}</tbody></table>
    `;
  };
  modal.addEventListener('click', async (event) => {
    const target = event.target;
    if (target.matches('[data-close-modal]')) modal.remove();
    if (target.matches('[data-log-search]')) search();
    if (target.matches('[data-log-clear]')) {
      modal.querySelector('[data-log-hql]').value = '';
      search();
    }
    if (target.matches('[data-log-next]')) {
      const logIds = [...modal.querySelectorAll('[data-log-check]:checked')].map((item) => item.dataset.logCheck);
      if (!logIds.length) return toast('请至少选择一条日志或事件');
      modal.innerHTML = createIncidentForm(logIds);
    }
    if (target.matches('[data-create-submit]')) {
      const payload = {
        logIds: JSON.parse(target.dataset.logIds),
        title: modal.querySelector('[data-create-title]').value,
        sceneId: modal.querySelector('[data-create-scene]').value,
        owner: modal.querySelector('[data-create-owner]').value,
        severity: modal.querySelector('[data-create-severity]').value,
        advice: modal.querySelector('[data-create-advice]').value
      };
      if (!payload.title || !payload.sceneId) return toast('请补全事件名称和攻击场景');
      const created = await api('/api/security/incidents', { method: 'POST', body: JSON.stringify(payload) });
      modal.remove();
      toast('安全事件创建成功');
      setRoute(`#/incidents/${created.id}/alerts`);
    }
    if (target.matches('[data-create-back]')) openLogModal({ createMode: true });
  });
  search();
};

const createIncidentForm = (logIds) => `
  <div class="modal">
    <div class="modal-head"><h2>创建安全事件</h2><button class="btn ghost" data-close-modal>关闭</button></div>
    <p style="text-align:center;color:var(--muted)">你已经选择 ${logIds.length} 条日志查询来创建事件，请补全以下信息</p>
    <section class="panel" style="max-width:520px;margin:0 auto">
      <div class="form-grid">
        <div class="field wide"><label>事件名称 *</label><input data-create-title></div>
        <div class="field wide"><label>攻击场景 *</label><select data-create-scene>${sceneOptions()}</select></div>
        <div class="field wide"><label>责任人</label><input data-create-owner></div>
        <div class="field wide"><label>严重等级</label><select data-create-severity>${options(state.dictionaries.severities, 'high')}</select></div>
        <div class="field wide"><label>解决办法</label><textarea data-create-advice></textarea></div>
      </div>
    </section>
    <div class="actions" style="justify-content:flex-end;margin-top:12px">
      <button class="btn ghost" data-close-modal>返回</button>
      <button class="btn primary" data-create-submit data-log-ids='${JSON.stringify(logIds)}'>确认</button>
    </div>
  </div>
`;

const openTableFieldsConfig = async () => {
  const fields = await api('/api/security/incidents/table-fields');
  const saved = JSON.parse(localStorage.getItem('incidentTableFields') || 'null');
  const currentFields = saved || fields;
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal" style="max-width:480px">
      <div class="modal-head"><h2>配置表格字段</h2><button class="btn ghost" data-close-modal>关闭</button></div>
      <div class="field-config-list">
        ${currentFields.map((f) => `
          <label class="field-toggle">
            <input type="checkbox" data-field-key="${esc(f.key)}" ${f.visible ? 'checked' : ''}>
            <span>${esc(f.label)}</span>
          </label>
        `).join('')}
      </div>
      <div class="actions" style="justify-content:flex-end;margin-top:16px">
        <button class="btn ghost" data-fields-reset>恢复默认</button>
        <button class="btn primary" data-fields-save>保存</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.addEventListener('click', async (e) => {
    const t = e.target;
    if (t.matches('[data-close-modal]')) modal.remove();
    if (t.matches('[data-fields-reset]')) {
      localStorage.removeItem('incidentTableFields');
      modal.remove();
      toast('已恢复默认字段配置');
      render();
    }
    if (t.matches('[data-fields-save]')) {
      const checkboxes = modal.querySelectorAll('[data-field-key]');
      const config = [...checkboxes].map((cb) => ({ key: cb.dataset.fieldKey, label: cb.nextElementSibling.textContent, visible: cb.checked }));
      localStorage.setItem('incidentTableFields', JSON.stringify(config));
      modal.remove();
      toast('字段配置已保存');
      render();
    }
  });
};

const getVisibleColumns = () => {
  const saved = JSON.parse(localStorage.getItem('incidentTableFields') || 'null');
  if (!saved) return null;
  return saved.filter((f) => f.visible).map((f) => f.key);
};

const loadAuditLogs = async (page = 1) => {
  const data = await api(`/api/security/audit-logs?page=${page}&pageSize=20`);
  state.auditLogs = data.items;
  state.auditTotal = data.total;
  state.auditPage = page;
  return data;
};

const renderAuditLogs = async () => {
  await loadAuditLogs(state.auditPage);
  const totalPages = Math.max(1, Math.ceil(state.auditTotal / 20));
  return h`
    <div class="page-head">
      <h1>审计日志</h1>
    </div>
    <section class="panel table-wrap">
      <table>
        <thead>
          <tr>
            <th>时间</th>
            <th>操作</th>
            <th>目标类型</th>
            <th>目标ID</th>
            <th>详情</th>
            <th>用户</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          ${state.auditLogs.map((item) => `
            <tr>
              <td>${esc(item.time)}</td>
              <td>${esc(item.action)}</td>
              <td>${esc(item.targetType)}</td>
              <td>${esc(item.targetId)}</td>
              <td>${esc(item.detail)}</td>
              <td>${esc(item.user)}</td>
              <td>${esc(item.ip)}</td>
            </tr>
          `).join('')}
          ${state.auditLogs.length === 0 ? '<tr><td colspan="7" class="empty">暂无审计日志</td></tr>' : ''}
        </tbody>
      </table>
      <div class="actions" style="justify-content:center;margin-top:12px">
        <button class="btn" data-audit-prev ${state.auditPage <= 1 ? 'disabled' : ''}>上一页</button>
        <span style="line-height:2">第 ${state.auditPage} / ${totalPages} 页（共 ${state.auditTotal} 条）</span>
        <button class="btn" data-audit-next ${state.auditPage >= totalPages ? 'disabled' : ''}>下一页</button>
      </div>
    </section>
  `;
};

const exportModel = async (id) => {
  const response = await fetch(`/api/security/models/export?id=${id}`);
  if (!response.ok) { toast('导出失败'); return; }
  const blob = await response.blob();
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename\*?=(?:UTF-8''|"?)([^";]+)/i);
  const filename = match ? decodeURIComponent(match[1]) : `model-${id}.json`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast('导出成功');
};

const openImportModal = () => {
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal" style="max-width:440px">
      <div class="modal-head"><h2>导入模型</h2><button class="btn ghost" data-close-modal>关闭</button></div>
      <section class="panel" style="margin:16px">
        <div class="field wide">
          <label>选择 JSON 文件</label>
          <input type="file" data-import-file accept=".json">
        </div>
      </section>
      <div class="actions" style="justify-content:flex-end;padding:0 16px 16px">
        <button class="btn ghost" data-close-modal>取消</button>
        <button class="btn primary" data-import-submit>导入</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.addEventListener('click', async (e) => {
    const t = e.target;
    if (t.matches('[data-close-modal]')) modal.remove();
    if (t.matches('[data-import-submit]')) {
      const fileInput = modal.querySelector('[data-import-file]');
      const file = fileInput?.files[0];
      if (!file) { toast('请选择文件'); return; }
      try {
        const text = await file.text();
        JSON.parse(text);
        await api('/api/security/models/import', { method: 'POST', body: text, headers: { 'Content-Type': 'application/json' } });
        modal.remove();
        toast('导入成功');
        render();
      } catch (err) {
        toast('导入失败：' + err.message);
      }
    }
  });
};

const bindEvents = () => {
  app.onclick = async (event) => {
    const target = event.target;
    if (target.matches('[data-search-incidents]')) render();
    if (target.matches('[data-reset-incidents]')) {
      document.querySelector('[data-incident-keyword]').value = '';
      document.querySelector('[data-incident-severity]').value = '';
      render();
    }
    if (target.matches('[data-open-hql]')) openLogModal();
    if (target.matches('[data-create-incident]')) openLogModal({ createMode: true });
    if (target.matches('[data-table-fields]')) openTableFieldsConfig();
    if (target.matches('[data-incident-detail]')) setRoute(`#/incidents/${target.dataset.incidentDetail}/overview`);
    if (target.matches('[data-incident-graph]')) setRoute(`#/incidents/${target.dataset.incidentGraph}/graph`);
    if (target.matches('[data-scene]')) {
      state.selectedSceneId = target.dataset.scene;
      render();
    }
    if (target.matches('[data-model-new]')) setRoute('#/models/new');
    if (target.matches('[data-model-edit]')) setRoute(`#/models/${target.dataset.modelEdit}/edit`);
    if (target.matches('[data-model-detail]')) setRoute(`#/models/${target.dataset.modelDetail}`);
    if (target.matches('[data-back-models], [data-model-cancel]')) setRoute('#/models');
    if (target.matches('[data-model-toggle]')) {
      const action = target.dataset.status === 'running' ? 'disable' : 'enable';
      await api(`/api/security/models/${target.dataset.modelToggle}/${action}`, { method: 'POST' });
      toast('模型状态已更新');
      render();
    }
    if (target.matches('[data-add-entry]')) {
      const list = document.querySelector('[data-entry-list]');
      const index = list.children.length;
      list.insertAdjacentHTML('beforeend', `<div class="entry-alert"><strong>${String.fromCharCode(65 + index)}</strong><input data-entry-condition placeholder="输入 HQL 检索语句或关联分析规则表达式"><button class="btn ghost" data-remove-entry>删除</button></div>`);
    }
    if (target.matches('[data-remove-entry]')) target.closest('.entry-alert').remove();
    if (target.matches('[data-model-save]')) {
      const payload = {
        name: document.querySelector('[data-form-name]').value,
        useEntryAlertNameAsTitle: document.querySelector('[data-form-use-title]').checked,
        description: document.querySelector('[data-form-description]').value,
        sceneId: document.querySelector('[data-form-scene]').value,
        entryAlerts: [...document.querySelectorAll('[data-entry-condition]')].map((input, index) => ({ key: String.fromCharCode(65 + index), condition: input.value })),
        dsl: document.querySelector('[data-form-dsl]').value,
        active: document.querySelector('[data-form-active]').value === 'true',
        notifier: document.querySelector('[data-form-notifier]').value
      };
      if (!payload.name || !payload.sceneId || !payload.entryAlerts[0]?.condition || !payload.dsl) return toast('请补全必填项');
      await api('/api/security/models/validate', { method: 'POST', body: JSON.stringify({ dsl: payload.dsl }) });
      const id = target.dataset.modelSave;
      const saved = await api(id ? `/api/security/models/${id}` : '/api/security/models', { method: id ? 'PUT' : 'POST', body: JSON.stringify(payload) });
      toast('模型已保存');
      setRoute(`#/models/${saved.id}`);
    }
    if (target.matches('[data-incident-tab]')) setRoute(`#/incidents/${target.dataset.id}/${target.dataset.incidentTab}`);
    if (target.matches('[data-evidence-tab]')) {
      state.evidenceTab = target.dataset.evidenceTab;
      render();
    }
    if (target.matches('[data-impact-tab]')) {
      state.impactTab = target.dataset.impactTab;
      render();
    }
    if (target.matches('[data-evidence-alert]')) toast('查看告警功能将在后续版本完善');
    if (target.matches('[data-evidence-download]')) toast('下载功能将在后续版本完善');
    if (target.matches('[data-impact-detail]')) toast('实体详情将在后续版本完善');
    if (target.matches('[data-impact-alerts]')) toast('实体关联告警将在后续版本完善');
    if (target.matches('[data-graph-filter]')) {
      const type = target.dataset.graphFilter;
      target.classList.toggle('active');
      const panel = target.closest('.panel');
      const network = panel?.__graphNetwork;
      const allNodes = panel?.__graphNodes;
      if (!network || !allNodes) return;
      const activeTypes = [...panel.querySelectorAll('.graph-filter.active')].map((b) => b.dataset.graphFilter);
      const updates = allNodes.map((n) => ({ id: n.id, hidden: !activeTypes.includes(n._type) }));
      allNodes.update(updates);
    }
    if (target.matches('[data-audit-prev]')) {
      state.auditPage = Math.max(1, state.auditPage - 1);
      render();
    }
    if (target.matches('[data-audit-next]')) {
      state.auditPage++;
      render();
    }
    if (target.matches('[data-model-import]')) openImportModal();
    if (target.matches('[data-model-export-all]')) exportModel('');
    if (target.matches('[data-model-export]')) exportModel(target.dataset.modelExport);
  };
};

const initGraph = () => {
  const container = document.getElementById('threat-graph');
  const data = window.__graphData;
  if (!container || !data || typeof vis === 'undefined') return;

  const riskColor = { '严重': '#bd2d2d', '警告': '#c57b2c', '提醒': '#2f6f9f', '紧急': '#bd2d2d' };
  const typeShape = { '事件': 'diamond', '告警': 'dot' };
  const typeColor = { '事件': '#176b5c', '告警': '#5B8DEF' };

  const nodes = new vis.DataSet(data.nodes.map((n) => ({
    id: n.id,
    label: n.label.length > 24 ? n.label.slice(0, 22) + '…' : n.label,
    shape: typeShape[n.type] || 'dot',
    color: {
      background: typeColor[n.type] || '#999',
      border: riskColor[n.risk] || '#999',
      highlight: { background: typeColor[n.type] || '#999', border: '#111' }
    },
    font: { size: 12, color: '#16212d', strokeWidth: 2, strokeColor: '#fff' },
    size: n.type === '事件' ? 28 : 18,
    title: `${n.type}：${n.label}\n等级：${n.risk}`,
    _type: n.type
  })));

  const edges = new vis.DataSet(data.edges.map((e, i) => ({
    id: `e-${i}`,
    from: e.from,
    to: e.to,
    label: e.label,
    font: { size: 11, color: '#647386', align: 'middle' },
    color: { color: '#b0bec5', highlight: '#176b5c' },
    arrows: 'to',
    smooth: { type: 'cubicBezier', forceDirection: 'none', roundness: 0.4 }
  })));

  const network = new vis.Network(container, { nodes, edges }, {
    physics: { stabilization: { iterations: 120 }, barnesHut: { gravitationalConstant: -3000, springLength: 160 } },
    interaction: { hover: true, tooltipDelay: 200 },
    nodes: { borderWidth: 2 },
    edges: { width: 1.5 }
  });

  container.closest('.panel').__graphNetwork = network;
  container.closest('.panel').__graphNodes = nodes;

  network.on('stabilizationIterationsDone', () => { network.setOptions({ physics: false }); });
};

const render = async () => {
  try {
    let content = '';
    const route = state.route.replace(/^#/, '');
    const parts = route.split('/').filter(Boolean);
    if (parts[0] === 'models' && parts[1] === 'new') content = await renderModelForm();
    else if (parts[0] === 'models' && parts[2] === 'edit') content = await renderModelForm(parts[1]);
    else if (parts[0] === 'models' && parts[1]) content = await renderModelDetail(parts[1]);
    else if (parts[0] === 'models') content = await renderModels();
    else if (parts[0] === 'audit') content = await renderAuditLogs();
    else if (parts[0] === 'incidents' && parts[1]) content = await renderIncidentDetail(parts[1], parts[2] || 'overview');
    else content = await renderIncidents();
    app.innerHTML = shell(content);
    bindEvents();
    if (state.route.includes('/graph')) requestAnimationFrame(initGraph);
  } catch (error) {
    app.innerHTML = shell(`<section class="panel"><h1>页面加载失败</h1><p>${esc(error.message)}</p></section>`);
  }
};

render();
