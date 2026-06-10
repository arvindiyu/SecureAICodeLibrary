// yaml-loader.js — ?yaml=path SPA mode for Secure AI Code Library
// Parses YAML rule/spec/subagent files and renders them via the shared marked.js pipeline.

(function () {
  'use strict';

  var SUBAGENT_RE = /registry\/subagents\//;

  /* ── Script loader (memoized) ─────────────────────────────────────────── */
  function loadScript(url) {
    if (loadScript._cache[url]) return loadScript._cache[url];
    var p = new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = url;
      s.onload = resolve;
      s.onerror = function () { reject(new Error('Failed to load: ' + url)); };
      document.head.appendChild(s);
    });
    loadScript._cache[url] = p;
    return p;
  }
  loadScript._cache = {};

  /* ── Helpers ──────────────────────────────────────────────────────────── */
  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function dig(obj, dotPath) {
    if (obj == null) return null;
    var parts = dotPath.split('.');
    var cur = obj;
    for (var i = 0; i < parts.length; i++) {
      if (cur == null || typeof cur !== 'object') return null;
      cur = cur[parts[i]];
    }
    return cur !== undefined ? cur : null;
  }

  function row(label, value) {
    if (value == null || value === '') return '';
    return '**' + label + ':** ' + String(value) + '  \n';
  }

  /* ── Rule / spec renderer ─────────────────────────────────────────────── */
  function renderRuleYaml(data, rawPath) {
    var name = dig(data, 'metadata.name') || dig(data, 'id') || rawPath.split('/').pop();
    var md = '# ' + name + '\n\n';

    md += row('Category',       dig(data, 'category'));
    md += row('Severity',       dig(data, 'severity'));
    md += row('Alignment pillar', dig(data, 'mythos_alignment.pillar'));
    md += row('Substantiation',    dig(data, 'mythos_alignment.substantiation'));
    md += '\n';

    var summary = dig(data, 'summary');
    if (summary) md += '> **Summary:** ' + summary + '\n\n';

    var content = dig(data, 'content');
    if (content) md += content + '\n\n';

    md += '---\n## References\n';

    var sources = dig(data, 'sources.primary');
    if (Array.isArray(sources) && sources.length) {
      md += '- **Sources:** ' + sources.join(', ') + '\n';
    }

    var refs = [];
    var asvs  = dig(data, 'asvs_controls');
    var cwe   = dig(data, 'cwe');
    var iso   = dig(data, 'iso42001_controls');
    var atlas = dig(data, 'mitre_atlas');
    if (asvs)  refs.push('**ASVS:** ' + asvs);
    if (cwe)   refs.push('**CWE:** ' + cwe);
    if (iso)   refs.push('**ISO 42001:** ' + iso);
    if (atlas) refs.push('**MITRE ATLAS:** ' + atlas);
    if (refs.length) md += '- ' + refs.join(', ') + '\n';

    md += '- <a href="' + esc(rawPath) + '" target="_blank">View raw YAML</a>\n';
    return md;
  }

  /* ── Subagent renderer ────────────────────────────────────────────────── */
  function renderSubagentYaml(data, rawPath) {
    var name = dig(data, 'metadata.name') || dig(data, 'id') || rawPath.split('/').pop();
    var md = '# ' + name + '\n\n';

    var summary = dig(data, 'summary');
    if (summary) md += '> ' + summary + '\n\n';

    var content = dig(data, 'content');
    if (content) md += content + '\n\n';

    md += '---\n';

    var tiers = dig(data, 'tiers');
    if (tiers && typeof tiers === 'object') {
      md += '## Execution Tiers\n';
      if (tiers.native)   md += '- **Native:** '   + tiers.native   + '\n';
      if (tiers.headless) md += '- **Headless:** ' + tiers.headless + '\n';
      md += '\n';
    }

    var budget = dig(data, 'token_budget');
    if (budget != null) md += '**Token budget:** ' + budget + ' tokens  \n\n';

    var audit = dig(data, 'audit_log');
    if (audit != null) {
      var auditStr = typeof audit === 'object' ? JSON.stringify(audit) : String(audit);
      md += '**Audit log:** ' + auditStr + '  \n\n';
    }

    var scope = dig(data, 'tool_scope');
    if (Array.isArray(scope) && scope.length) {
      md += '**Tool scope:** ' + scope.join(', ') + '  \n\n';
    }

    var refRules = dig(data, 'references.rules');
    if (Array.isArray(refRules) && refRules.length) {
      md += '## Referenced Rules\n';
      refRules.forEach(function (r) { md += '- `' + r + '`\n'; });
      md += '\n';
    }

    md += '---\n';
    md += '- <a href="' + esc(rawPath) + '" target="_blank">View raw YAML</a>\n';
    return md;
  }

  /* ── Breadcrumb builder ───────────────────────────────────────────────── */
  function makeBreadcrumbs(path) {
    var parts = path.replace(/^\.\//, '').split('/');
    var html = '<a href="index.html"><i class="fas fa-home"></i> Home</a>';
    parts.forEach(function (part) {
      var display = part
        .replace(/\.(rule|spec|subagent)\.yaml$/, '')
        .replace(/\.yaml$/, '')
        .split(/[-_]/)
        .map(function (w) { return w.charAt(0).toUpperCase() + w.slice(1); })
        .join(' ');
      html += ' <i class="fas fa-chevron-right"></i> <span>' + esc(display) + '</span>';
    });
    return html;
  }

  /* ── Core render ──────────────────────────────────────────────────────── */
  function renderYamlContent(path) {
    var contentContainer = document.getElementById('content-container');
    var mainContent      = document.getElementById('main-content');
    if (!contentContainer) return;

    contentContainer.innerHTML =
      '<div class="loading"><i class="fas fa-circle-notch fa-spin"></i> Loading YAML\u2026</div>';
    contentContainer.style.display = 'block';
    if (mainContent) mainContent.style.display = 'none';

    // Update page title
    var baseName = path.split('/').pop().replace(/\.(rule|spec|subagent)?\.yaml$/i, '');
    document.title = baseName
      .split('-')
      .map(function (w) { return w.charAt(0).toUpperCase() + w.slice(1); })
      .join(' ') + ' \u2014 Secure AI Code Library';

    var cdnBase = window.__SECUREAI_CDN || {};
    var jsyamlUrl = cdnBase.jsyaml ||
      'https://cdn.jsdelivr.net/npm/js-yaml@4.1.0/dist/js-yaml.min.js';

    fetch(path)
      .then(function (resp) {
        if (!resp.ok) throw new Error('HTTP ' + resp.status + ': ' + path);
        return resp.text();
      })
      .then(function (text) {
        return loadScript(jsyamlUrl).then(function () { return text; });
      })
      .then(function (text) {
        var data = window.jsyaml.load(text);
        var isSubagent = SUBAGENT_RE.test(path);
        var markdown   = isSubagent ? renderSubagentYaml(data, path) : renderRuleYaml(data, path);

        var html = (typeof marked !== 'undefined')
          ? marked.parse(markdown)
          : '<pre>' + esc(markdown) + '</pre>';

        contentContainer.innerHTML =
          '<div class="breadcrumbs">' + makeBreadcrumbs(path) + '</div>' +
          '<div class="markdown-content">' + html + '</div>' +
          '<div class="back-link">' +
            '<a href="javascript:history.back()" class="btn-back">' +
              '<i class="fas fa-arrow-left"></i> Back</a>' +
            '<a href="index.html" class="btn-home">' +
              '<i class="fas fa-home"></i> Home</a>' +
          '</div>';

        // Hand off to postRenderMarkdown if markdown-loader has registered it
        if (typeof window.__postRenderMarkdown === 'function') {
          window.__postRenderMarkdown(contentContainer);
        } else if (typeof Prism !== 'undefined') {
          Prism.highlightAll();
        }
      })
      .catch(function (err) {
        contentContainer.innerHTML =
          '<div class="error-container">' +
            '<h3><i class="fas fa-exclamation-triangle"></i> Error Loading YAML</h3>' +
            '<p>Could not load: <code>' + esc(path) + '</code></p>' +
            '<pre>' + esc(err.message) + '</pre>' +
            '<a href="index.html" class="btn-home">' +
              '<i class="fas fa-home"></i> Return to Home</a>' +
          '</div>';
      });
  }

  /* ── SPA routing ──────────────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    var params = new URLSearchParams(window.location.search);
    var yamlPath = params.get('yaml');
    if (yamlPath) renderYamlContent(yamlPath);
  });

  window.addEventListener('popstate', function () {
    var params = new URLSearchParams(window.location.search);
    var yamlPath = params.get('yaml');
    if (yamlPath) {
      renderYamlContent(yamlPath);
    } else {
      var contentContainer = document.getElementById('content-container');
      var mainContent      = document.getElementById('main-content');
      if (contentContainer) contentContainer.style.display = 'none';
      if (mainContent)      mainContent.style.display      = 'block';
    }
  });

  // Intercept ?yaml= href clicks anywhere in the document
  document.addEventListener('click', function (e) {
    var link = e.target.closest('a');
    if (!link) return;
    var href = link.getAttribute('href') || '';
    if (href.startsWith('?yaml=')) {
      e.preventDefault();
      var yamlPath = decodeURIComponent(href.slice(6));
      window.history.pushState({}, '', href);
      renderYamlContent(yamlPath);
    }
  });

  // Expose for use by yaml-loader.js itself and markdown-loader extensions
  window.__yamlLoader = { render: renderYamlContent };

}());
