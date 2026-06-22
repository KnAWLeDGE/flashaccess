/* FlashAccess — ai.js
 * OpenRouter BYOK AI layer with 3-mode confirmation system.
 * Loaded on pages that use AI features.
 */

/* ── Settings storage ─────────────────────────────────────── */
var FAI = (function () {
  var STORAGE_KEY = 'fa_ai_settings';

  var defaults = {
    apiKey:       '',
    model:        'openai/gpt-4o-mini',
    confirmMode:  'dialog',     // 'dialog' | 'dialog+passphrase' | 'passphrase'
    passphrase:   '',
    confirmWhen:  'all',        // 'never' | 'big' | 'all' | 'manual'
  };

  function loadSettings() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      if (raw) return Object.assign({}, defaults, JSON.parse(raw));
    } catch (_) {}
    return Object.assign({}, defaults);
  }

  function saveSettings(s) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
  }

  /* ── Modal helpers ───────────────────────────────────────── */
  function createModal(id) {
    var existing = document.getElementById(id);
    if (existing) existing.remove();
    var el = document.createElement('div');
    el.id = id;
    el.className = 'ai-modal-overlay';
    document.body.appendChild(el);
    return el;
  }

  function removeModal(id) {
    var el = document.getElementById(id);
    if (el) el.remove();
  }

  /* ── Confirmation system ─────────────────────────────────── */
  // Returns a Promise that resolves true (confirmed) or false (cancelled).
  function confirm(title, body) {
    var settings = loadSettings();
    var mode = settings.confirmMode;

    return new Promise(function (resolve) {
      var overlay = createModal('fa-confirm-modal');
      var needDialog = (mode === 'dialog' || mode === 'dialog+passphrase');
      var needPassphrase = (mode === 'dialog+passphrase' || mode === 'passphrase');

      var passphraseField = needPassphrase
        ? '<div class="ai-modal-field"><label class="ai-modal-label">Confirmation passphrase</label>' +
          '<input type="password" id="fa-confirm-passphrase" class="field-input ai-modal-passphrase" placeholder="Enter passphrase…" autocomplete="off"></div>' +
          '<div id="fa-confirm-passphrase-err" class="ai-modal-err" style="display:none">Incorrect passphrase.</div>'
        : '';

      overlay.innerHTML =
        '<div class="ai-modal">' +
          '<div class="ai-modal-hd">' + escHtml(title) + '</div>' +
          '<div class="ai-modal-bd">' +
            '<div class="ai-modal-body-text">' + body + '</div>' +
            passphraseField +
          '</div>' +
          '<div class="ai-modal-ft">' +
            '<button class="btn btn-secondary" id="fa-confirm-cancel">Cancel</button>' +
            '<button class="btn btn-danger" id="fa-confirm-ok">Apply</button>' +
          '</div>' +
        '</div>';

      function dismiss(result) {
        removeModal('fa-confirm-modal');
        resolve(result);
      }

      document.getElementById('fa-confirm-cancel').addEventListener('click', function () { dismiss(false); });

      document.getElementById('fa-confirm-ok').addEventListener('click', function () {
        if (needPassphrase) {
          var entered = document.getElementById('fa-confirm-passphrase').value;
          if (entered !== settings.passphrase) {
            document.getElementById('fa-confirm-passphrase-err').style.display = '';
            document.getElementById('fa-confirm-passphrase').focus();
            return;
          }
        }
        dismiss(true);
      });

      // Close on overlay click
      overlay.addEventListener('click', function (e) {
        if (e.target === overlay) dismiss(false);
      });

      // Focus passphrase or OK button
      setTimeout(function () {
        var pp = document.getElementById('fa-confirm-passphrase');
        if (pp) pp.focus();
        else {
          var ok = document.getElementById('fa-confirm-ok');
          if (ok) ok.focus();
        }
      }, 50);
    });
  }

  /* ── OpenRouter API call ─────────────────────────────────── */
  function chat(messages, opts) {
    var settings = loadSettings();
    if (!settings.apiKey) {
      return Promise.reject(new Error('No OpenRouter API key set. Configure it in AI Settings.'));
    }
    var model = (opts && opts.model) || ((settings.customModel && settings.customModel.trim()) ? settings.customModel.trim() : (settings.model || 'openai/gpt-4o-mini'));

    return fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + settings.apiKey,
        'HTTP-Referer': window.location.origin,
        'X-Title': 'FlashAccess',
      },
      body: JSON.stringify({
        model: model,
        messages: messages,
        temperature: 0.2,
      }),
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error('OpenRouter ' + r.status + ': ' + t); });
      return r.json();
    }).then(function (d) {
      if (!d.choices || !d.choices[0]) throw new Error('Unexpected OpenRouter response');
      return d.choices[0].message.content;
    });
  }

  /* ── Execute DDL via server ──────────────────────────────── */
  function executeSQL(db, sql) {
    return fetch('/api/ai/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ db: db, sql: sql }),
    }).then(function (r) { return r.json(); });
  }

  /* ── Fetch schema ────────────────────────────────────────── */
  function fetchSchema(db) {
    return fetch('/api/schema/' + encodeURIComponent(db))
      .then(function (r) {
        if (!r.ok) throw new Error('Schema fetch failed: ' + r.status);
        return r.json();
      });
  }

  /* ── HTML escape ─────────────────────────────────────────── */
  function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  /* ── Loading spinner helper ──────────────────────────────── */
  function setLoading(btn, isLoading, loadingText) {
    if (isLoading) {
      btn.dataset.origText = btn.textContent;
      btn.textContent = loadingText || 'Thinking…';
      btn.disabled = true;
    } else {
      btn.textContent = btn.dataset.origText || btn.textContent;
      btn.disabled = false;
    }
  }

  /* ── Render AI result panel ──────────────────────────────── */
  function showResultPanel(containerId, html) {
    var el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = html;
    el.style.display = '';
  }

  function hideResultPanel(containerId) {
    var el = document.getElementById(containerId);
    if (el) el.style.display = 'none';
  }

  /* ── When-to-confirm gate ───────────────────────────────── */
  // Returns true if this action should be confirmed based on the confirmWhen setting.
  // source: 'ai' (AI-generated) or 'manual' (user-typed query)
  // kind:   'dml', 'ddl', 'other'
  // estimatedRows: number (from preview, -1 if unknown)
  function needsConfirmation(source, kind, estimatedRows) {
    var settings = loadSettings();
    switch (settings.confirmWhen) {
      case 'never':  return false;
      case 'manual': return source === 'manual';
      case 'big':
        // Big = DDL, or DML affecting >100 rows
        if (kind === 'ddl') return true;
        if (kind === 'dml' && (estimatedRows < 0 || estimatedRows > 100)) return true;
        return false;
      case 'all':
      default:
        return kind === 'dml' || kind === 'ddl';
    }
  }

  /* ── Public API ──────────────────────────────────────────── */
  return {
    loadSettings: loadSettings,
    saveSettings: saveSettings,
    confirm: confirm,
    chat: chat,
    executeSQL: executeSQL,
    fetchSchema: fetchSchema,
    escHtml: escHtml,
    setLoading: setLoading,
    showResultPanel: showResultPanel,
    hideResultPanel: hideResultPanel,
    needsConfirmation: needsConfirmation,
  };
})();

/* ── Index Advisor ───────────────────────────────────────── */
function faIndexAdvisor(db) {
  var btn = document.getElementById('fa-index-advisor-btn');
  var panel = document.getElementById('fa-index-advisor-panel');

  FAI.setLoading(btn, true, 'Analyzing…');
  panel.style.display = 'none';

  FAI.fetchSchema(db).then(function (schema) {
    var schemaText = JSON.stringify(schema, null, 2);
    var messages = [
      {
        role: 'system',
        content: 'You are a MySQL database performance expert. Analyze the given schema and suggest CREATE INDEX statements that would improve query performance. Focus on:\n' +
          '- Missing indexes on foreign key columns\n' +
          '- Columns likely used in WHERE, JOIN, ORDER BY clauses based on their names\n' +
          '- Composite indexes where beneficial\n\n' +
          'Return your response as a JSON object with this structure:\n' +
          '{"suggestions": [{"reason": "...", "sql": "CREATE INDEX ..."}]}\n' +
          'Only return the JSON object, no other text.',
      },
      {
        role: 'user',
        content: 'Database schema:\n' + schemaText,
      },
    ];

    return FAI.chat(messages);
  }).then(function (raw) {
    FAI.setLoading(btn, false);

    var parsed;
    try {
      // Strip markdown code fences if present
      var clean = raw.replace(/^```[a-z]*\n?/i, '').replace(/\n?```$/i, '').trim();
      parsed = JSON.parse(clean);
    } catch (_) {
      panel.innerHTML = '<div class="ai-error">Could not parse AI response. Raw output:<br><pre class="ai-raw">' + FAI.escHtml(raw) + '</pre></div>';
      panel.style.display = '';
      return;
    }

    var suggestions = parsed.suggestions || [];
    if (suggestions.length === 0) {
      panel.innerHTML = '<div class="ai-empty">No index improvements suggested — your schema looks well-indexed.</div>';
      panel.style.display = '';
      return;
    }

    var html = '<div class="ai-panel-title">Index Suggestions (' + suggestions.length + ')</div>';
    suggestions.forEach(function (s, i) {
      html +=
        '<div class="ai-suggestion" id="fa-sug-' + i + '">' +
          '<div class="ai-suggestion-reason">' + FAI.escHtml(s.reason) + '</div>' +
          '<pre class="ai-sql">' + FAI.escHtml(s.sql) + '</pre>' +
          '<button class="btn btn-primary btn-sm" data-idx="' + i + '" data-db="' + encodeURIComponent(db) + '" data-sql="' + encodeURIComponent(s.sql) + '" onclick="faApplyIndex(this)">Apply</button>' +
          '<span class="ai-apply-result" id="fa-sug-result-' + i + '"></span>' +
        '</div>';
    });

    panel.innerHTML = html;
    panel.style.display = '';
  }).catch(function (err) {
    FAI.setLoading(btn, false);
    panel.innerHTML = '<div class="ai-error">' + FAI.escHtml(err.message) + '</div>';
    panel.style.display = '';
  });
}

function faApplyIndex(btn) {
  var idx = btn.dataset.idx;
  var db  = decodeURIComponent(btn.dataset.db);
  var sql = decodeURIComponent(btn.dataset.sql);
  var resultEl = document.getElementById('fa-sug-result-' + idx);
  var applyBtn = btn;

  FAI.confirm(
    'Apply Index',
    '<p>The following statement will be executed on <strong>' + FAI.escHtml(db) + '</strong>:</p>' +
    '<pre class="ai-sql ai-confirm-sql">' + FAI.escHtml(sql) + '</pre>'
  ).then(function (confirmed) {
    if (!confirmed) return;

    applyBtn.disabled = true;
    applyBtn.textContent = 'Applying…';

    FAI.executeSQL(db, sql).then(function (result) {
      if (result.error) {
        resultEl.className = 'ai-apply-result ai-apply-error';
        resultEl.textContent = '✗ ' + result.error;
      } else {
        resultEl.className = 'ai-apply-result ai-apply-ok';
        resultEl.textContent = '✓ Applied';
        applyBtn.style.display = 'none';
      }
    }).catch(function (err) {
      resultEl.className = 'ai-apply-result ai-apply-error';
      resultEl.textContent = '✗ ' + err.message;
    });
  });
}

/* ── SQL Assistant ───────────────────────────────────────── */
function faSQLAssistant(db) {
  var input = document.getElementById('fa-sql-assistant-input');
  var btn = document.getElementById('fa-sql-assistant-btn');
  var panel = document.getElementById('fa-sql-assistant-panel');
  var prompt = input ? input.value.trim() : '';

  if (!prompt) { input && input.focus(); return; }

  FAI.setLoading(btn, true, 'Generating…');
  panel.style.display = 'none';

  FAI.fetchSchema(db).then(function (schema) {
    var schemaText = JSON.stringify(schema.tables.map(function (t) {
      return {
        name: t.name,
        columns: t.columns.map(function (c) { return c.field + ' ' + c.type; }),
      };
    }), null, 2);

    var messages = [
      {
        role: 'system',
        content: 'You are a MySQL expert. Given a database schema and a natural language request, generate valid MySQL SQL.\n' +
          'Return only JSON: {"sql": "...", "explanation": "..."}\n' +
          'The SQL should be a single statement ready to run.',
      },
      {
        role: 'user',
        content: 'Schema for database `' + db + '`:\n' + schemaText + '\n\nRequest: ' + prompt,
      },
    ];

    return FAI.chat(messages);
  }).then(function (raw) {
    FAI.setLoading(btn, false);

    var parsed;
    try {
      var clean = raw.replace(/^```[a-z]*\n?/i, '').replace(/\n?```$/i, '').trim();
      parsed = JSON.parse(clean);
    } catch (_) {
      panel.innerHTML = '<div class="ai-error">Parse error. Raw:<br><pre class="ai-raw">' + FAI.escHtml(raw) + '</pre></div>';
      panel.style.display = '';
      return;
    }

    var queryEncoded = encodeURIComponent(parsed.sql || '');
    panel.innerHTML =
      '<div class="ai-panel-title">Generated SQL</div>' +
      '<div class="ai-suggestion-reason">' + FAI.escHtml(parsed.explanation || '') + '</div>' +
      '<pre class="ai-sql">' + FAI.escHtml(parsed.sql || '') + '</pre>' +
      '<a class="btn btn-primary btn-sm" href="/dashboard/' + encodeURIComponent(db) + '/query?q=' + queryEncoded + '">Run in Query →</a>';
    panel.style.display = '';
  }).catch(function (err) {
    FAI.setLoading(btn, false);
    panel.innerHTML = '<div class="ai-error">' + FAI.escHtml(err.message) + '</div>';
    panel.style.display = '';
  });
}

/* ── Schema Explainer ────────────────────────────────────── */
function faSchemaExplainer(db, table) {
  var btn = document.getElementById('fa-explainer-btn');
  var panel = document.getElementById('fa-explainer-panel');

  FAI.setLoading(btn, true, 'Explaining…');
  panel.style.display = 'none';

  FAI.fetchSchema(db).then(function (schema) {
    var tableData = schema.tables.find(function (t) { return t.name === table; });
    if (!tableData) throw new Error('Table not found in schema');

    var messages = [
      {
        role: 'system',
        content: 'You are a database expert. Explain a MySQL table in plain English for a developer. ' +
          'Cover: what the table likely represents, what each column stores, relationships implied by foreign key naming, and any concerns about the schema. ' +
          'Be concise but thorough. Use plain text, not markdown.',
      },
      {
        role: 'user',
        content: 'Explain this table:\n' + JSON.stringify(tableData, null, 2),
      },
    ];

    return FAI.chat(messages);
  }).then(function (text) {
    FAI.setLoading(btn, false);
    panel.innerHTML =
      '<div class="ai-panel-title">Schema Explanation</div>' +
      '<div class="ai-explanation">' + FAI.escHtml(text).replace(/\n/g, '<br>') + '</div>';
    panel.style.display = '';
  }).catch(function (err) {
    FAI.setLoading(btn, false);
    panel.innerHTML = '<div class="ai-error">' + FAI.escHtml(err.message) + '</div>';
    panel.style.display = '';
  });
}

/* ── Query Optimizer ─────────────────────────────────────── */
function faQueryOptimizer(db, sql) {
  var btn = document.getElementById('fa-optimizer-btn');
  var panel = document.getElementById('fa-optimizer-panel');

  if (!sql || !sql.trim()) {
    panel.innerHTML = '<div class="ai-error">Run a query first, then click Optimize.</div>';
    panel.style.display = '';
    return;
  }

  FAI.setLoading(btn, true, 'Optimizing…');
  panel.style.display = 'none';

  FAI.fetchSchema(db).then(function (schema) {
    var schemaText = JSON.stringify(schema, null, 2);

    var messages = [
      {
        role: 'system',
        content: 'You are a MySQL query optimization expert. Analyze the given query and schema, then suggest improvements.\n' +
          'Return JSON: {"issues": ["..."], "optimized_sql": "...", "explanation": "..."}\n' +
          'If the query is already optimal, say so in explanation and set optimized_sql to the original.',
      },
      {
        role: 'user',
        content: 'Database: ' + db + '\nSchema:\n' + schemaText + '\n\nQuery to optimize:\n' + sql,
      },
    ];

    return FAI.chat(messages);
  }).then(function (raw) {
    FAI.setLoading(btn, false);

    var parsed;
    try {
      var clean = raw.replace(/^```[a-z]*\n?/i, '').replace(/\n?```$/i, '').trim();
      parsed = JSON.parse(clean);
    } catch (_) {
      panel.innerHTML = '<div class="ai-error">Parse error. Raw:<br><pre class="ai-raw">' + FAI.escHtml(raw) + '</pre></div>';
      panel.style.display = '';
      return;
    }

    var issueHtml = '';
    if (parsed.issues && parsed.issues.length) {
      issueHtml = '<ul class="ai-issues">' +
        parsed.issues.map(function (i) { return '<li>' + FAI.escHtml(i) + '</li>'; }).join('') +
        '</ul>';
    }

    var queryEncoded = encodeURIComponent(parsed.optimized_sql || '');
    panel.innerHTML =
      '<div class="ai-panel-title">Query Optimizer</div>' +
      (issueHtml || '<p class="ai-empty">No issues found.</p>') +
      '<div class="ai-suggestion-reason">' + FAI.escHtml(parsed.explanation || '') + '</div>' +
      (parsed.optimized_sql && parsed.optimized_sql !== sql
        ? '<pre class="ai-sql">' + FAI.escHtml(parsed.optimized_sql) + '</pre>' +
          '<a class="btn btn-primary btn-sm" href="/dashboard/' + encodeURIComponent(db) + '/query?q=' + queryEncoded + '">Run Optimized →</a>'
        : ''
      );
    panel.style.display = '';
  }).catch(function (err) {
    FAI.setLoading(btn, false);
    panel.innerHTML = '<div class="ai-error">' + FAI.escHtml(err.message) + '</div>';
    panel.style.display = '';
  });
}
