/* SQLi Auditor dashboard: full-stack results + Chinese/English toggle.
   All dynamic text is rendered with textContent — never innerHTML. */
(function () {
  'use strict';

  var LANG_KEY = 'sqli-auditor.lang';
  var STAGE_ORDER = ['parameter_detection', 'injection_type', 'column_count', 'display_columns', 'databases', 'tables', 'fields', 'data_preview'];

  var currentLang = localStorage.getItem(LANG_KEY) || 'zh';
  if (currentLang !== 'zh' && currentLang !== 'en') currentLang = 'zh';

  var form = document.querySelector('#form');
  var button = document.querySelector('#submit');
  var exportButton = document.querySelector('#export');
  var langToggle = document.querySelector('#lang-toggle');
  var resultsRoot = document.querySelector('#results');
  var stagesRoot = document.querySelector('#stages');
  var titleEl = document.querySelector('#title');
  var partialBadge = document.querySelector('#partial-badge');
  var confirmInput = document.querySelector('#confirm');
  var metricRequests = document.querySelector('#metric-requests');
  var metricBudget = document.querySelector('#metric-budget');
  var metricDuration = document.querySelector('#metric-duration');

  var token = '';
  var lastReport = null;

  function t(key) {
    var dict = window.I18N && window.I18N[currentLang];
    return (dict && dict[key]) || key;
  }

  function applyLanguage() {
    document.documentElement.lang = currentLang === 'zh' ? 'zh-CN' : 'en';
    document.title = t('title');
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      el.textContent = t(el.getAttribute('data-i18n'));
    });
    confirmInput.placeholder = t('authPlaceholder');
    stagesRoot.querySelectorAll('li[data-stage]').forEach(function (li) {
      li.querySelector('.stage-name').textContent = t('stage.' + li.getAttribute('data-stage'));
      var status = li.getAttribute('data-status') || 'pending';
      li.querySelector('.stage-status').textContent = t('status.' + status);
    });
    langToggle.textContent = currentLang === 'zh' ? 'English' : '中文';
    langToggle.title = currentLang === 'zh' ? 'English' : '中文';
    if (lastReport) render(lastReport);
  }

  function localizeError(raw) {
    var msg = String(raw || '');
    var map = [
      ['valid target URL is required', 'errTarget'],
      ['only http and https', 'errScheme'],
      ['must contain query parameters', 'errNoParams'],
      ['at most', 'errMaxParams'],
      ['delay must be between', 'errDelay'],
      ['request budget must be between', 'errBudget'],
      ['preview rows must be between', 'errPreview'],
      ['concurrency must be non-negative', 'errConcurrency'],
      ['authorization confirmation exactly', 'errAuth'],
      ['resolve', 'errResolve'],
      ['blocked link-local', 'errBlocked']
    ];
    for (var i = 0; i < map.length; i++) {
      if (msg.indexOf(map[i][0]) !== -1) return t(map[i][1]);
    }
    if (!msg) return t('unknownError');
    return msg + '\n' + t('fixSuggestion');
  }

  function showError(raw) {
    titleEl.textContent = t('stopped');
    resultsRoot.replaceChildren();
    var msg = document.createElement('div');
    msg.className = 'empty error';
    msg.textContent = localizeError(raw);
    resultsRoot.appendChild(msg);
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function renderStages(stages) {
    var byKey = {};
    (stages || []).forEach(function (s) { byKey[s.key] = s; });
    stagesRoot.querySelectorAll('li[data-stage]').forEach(function (li) {
      var key = li.getAttribute('data-stage');
      var stage = byKey[key];
      var status = stage ? stage.status : 'pending';
      li.setAttribute('data-status', status);
      li.querySelector('.stage-status').textContent = t('status.' + status);
      li.className = 'st-' + status;
    });
  }

  function renderParameters(params) {
    if (!params || !params.length) return null;
    var section = el('section', 'result-section');
    section.appendChild(el('h3', 'section-title', t('parameters')));
    params.forEach(function (p) {
      var card = el('article', 'param-card');
      var head = el('div', 'param-head');
      head.appendChild(el('strong', 'param-name', p.name));
      var badge = el('span', 'badge ' + (p.injectable ? 'bad' : 'ok'), p.injectable ? t('injectable') : t('notInjectable'));
      head.appendChild(badge);
      card.appendChild(head);

      var meta = el('dl', 'kv');
      if (p.injection_type) appendKV(meta, t('injectionType'), p.injection_type);
      if (p.column_count) appendKV(meta, t('columnCount'), String(p.column_count));
      if (p.display_columns && p.display_columns.length) appendKV(meta, t('displayColumns'), p.display_columns.join(', '));
      if (p.evidence) appendKV(meta, t('evidence'), p.evidence);
      card.appendChild(meta);
      section.appendChild(card);
    });
    return section;
  }

  function appendKV(dl, label, value) {
    var dt = el('dt', null, label);
    var dd = el('dd', null, value);
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  function renderDatabases(databases, partial) {
    if (!databases || !databases.length) return null;
    var section = el('section', 'result-section');
    section.appendChild(el('h3', 'section-title', t('databases')));
    databases.forEach(function (db) {
      var dbCard = el('div', 'db-card');
      dbCard.appendChild(el('div', 'db-name', db.name));
      (db.tables || []).forEach(function (table) {
        var tableCard = el('div', 'table-card');
        var tableHead = el('div', 'table-head');
        tableHead.appendChild(el('strong', 'table-name', table.name));
        tableHead.appendChild(el('span', 'field-count', (table.columns || []).length + ' ' + t('fields')));
        tableCard.appendChild(tableHead);

        if (table.columns && table.columns.length) {
          var chips = el('div', 'chips');
          table.columns.forEach(function (c) { chips.appendChild(el('span', 'chip', c)); });
          tableCard.appendChild(chips);
        }

        if (table.rows && table.rows.length) {
          tableCard.appendChild(renderPreview(db.name, table, partial));
        }
        dbCard.appendChild(tableCard);
      });
      section.appendChild(dbCard);
    });
    return section;
  }

  function renderPreview(dbName, table, partial) {
    var wrap = el('div', 'preview');
    wrap.appendChild(el('h4', 'preview-title', t('dataPreview')));

    var meta = el('dl', 'kv preview-meta');
    appendKV(meta, t('currentDb'), dbName);
    appendKV(meta, t('currentTable'), table.name);
    appendKV(meta, t('previewFields'), (table.columns || []).join(', '));
    appendKV(meta, t('previewRowsCount'), String(table.rows.length));
    appendKV(meta, t('truncated'), partial ? t('truncatedYes') : t('truncatedNo'));
    wrap.appendChild(meta);

    var tbl = el('table', 'data-table');
    var thead = el('thead');
    var htr = el('tr');
    table.columns.forEach(function (c) { htr.appendChild(el('th', null, c)); });
    thead.appendChild(htr);
    tbl.appendChild(thead);

    var tbody = el('tbody');
    table.rows.forEach(function (row) {
      var tr = el('tr');
      table.columns.forEach(function (c) {
        tr.appendChild(el('td', null, row[c] !== undefined ? row[c] : ''));
      });
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    return wrap;
  }

  function render(data) {
    lastReport = data;
    titleEl.textContent = data.target || t('ready');
    metricRequests.textContent = data.requests;
    metricBudget.textContent = data.request_budget;
    metricDuration.textContent = data.duration_ms + ' ms';
    partialBadge.hidden = !data.partial;
    renderStages(data.stages);

    resultsRoot.replaceChildren();
    var heuristic = el('p', 'heuristic', t('heuristic'));
    resultsRoot.appendChild(heuristic);

    var hasInjectable = (data.parameters || []).some(function (p) { return p.injectable; });
    var paramsSection = renderParameters(data.parameters);
    var dbSection = renderDatabases(data.databases, data.partial);

    if (paramsSection) resultsRoot.appendChild(paramsSection);
    if (dbSection) resultsRoot.appendChild(dbSection);
    if (!hasInjectable && !dbSection) {
      resultsRoot.appendChild(el('div', 'empty', t('noInjection')));
    }
    if (data.partial) resultsRoot.appendChild(el('p', 'partial-note', t('partialNote')));
    exportButton.hidden = false;
  }

  langToggle.addEventListener('click', function () {
    currentLang = currentLang === 'zh' ? 'en' : 'zh';
    localStorage.setItem(LANG_KEY, currentLang);
    applyLanguage();
  });

  fetch('/api/config')
    .then(function (r) { return r.json(); })
    .then(function (c) { token = c.token; })
    .catch(function () { showError(t('initError')); });

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    button.disabled = true;
    button.textContent = t('scanning');
    exportButton.hidden = true;
    partialBadge.hidden = true;
    resultsRoot.replaceChildren();
    resultsRoot.appendChild(el('div', 'empty', t('scanning')));
    renderStages(null);

    var cookieValue = document.querySelector('#cookie').value;
    fetch('/api/stack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Auditor-Token': token },
      body: JSON.stringify({
        target: document.querySelector('#target').value,
        cookie: cookieValue,
        confirmation: confirmInput.value,
        delay_ms: Number(document.querySelector('#delay').value),
        request_budget: Number(document.querySelector('#budget').value),
        preview_rows: Number(document.querySelector('#preview').value),
        concurrency: Number(document.querySelector('#concurrency').value)
      })
    })
      .then(function (response) { return response.json().then(function (data) { return { ok: response.ok, data: data }; }); })
      .then(function (result) {
        document.querySelector('#cookie').value = '';
        if (!result.ok) throw new Error(result.data.error || 'Audit failed');
        render(result.data);
      })
      .catch(function (error) { showError(error.message); })
      .finally(function () {
        button.disabled = false;
        button.textContent = t('start');
      });
  });

  exportButton.addEventListener('click', function () {
    if (!lastReport) return;
    var blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'sqli-auditor-' + Date.now() + '.json';
    a.click();
    URL.revokeObjectURL(a.href);
  });

  applyLanguage();
})();
