// search.js — Lunr-powered search with category filter
// Lazy-loads Lunr and search-index.json on first focus of the search input.
// Falls back to DOM text-filter if index is unavailable.

(function () {
  'use strict';

  var lunrIndex   = null;
  var indexData   = null;
  var indexLoaded = false;
  var indexLoading = false;

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

  /* ── Init: fetch index + load Lunr ───────────────────────────────────── */
  function initSearch() {
    if (indexLoading) return;
    indexLoading = true;

    var cdn = window.__SECUREAI_CDN || {};
    var lunrUrl = cdn.lunr || 'https://cdn.jsdelivr.net/npm/lunr@2.3.9/lunr.min.js';

    Promise.all([
      loadScript(lunrUrl),
      fetch('js/search-index.json').then(function (r) {
        if (!r.ok) throw new Error('search-index.json not found (HTTP ' + r.status + ')');
        return r.json();
      })
    ]).then(function (results) {
      indexData = results[1];

      lunrIndex = lunr(function () {
        this.ref('id');
        this.field('name',     { boost: 10 });
        this.field('category', { boost: 5  });
        this.field('summary',  { boost: 3  });
        this.field('content');

        indexData.forEach(function (doc) {
          // lunr requires string fields
          this.add({
            id:       String(doc.id       || ''),
            name:     String(doc.name     || ''),
            category: String(doc.category || ''),
            summary:  String(doc.summary  || ''),
            content:  String(doc.content  || '')
          });
        }, this);
      });

      indexLoaded = true;
      setStatus('');
    }).catch(function () {
      indexLoaded = false;
      setStatus('Search index unavailable \u2014 using category filter only.');
    });
  }

  /* ── DOM helpers ──────────────────────────────────────────────────────── */
  function setStatus(msg) {
    var el = document.getElementById('search-status');
    if (el) el.textContent = msg;
  }

  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /* ── Render Lunr results ──────────────────────────────────────────────── */
  function renderResults(hits) {
    var container = document.getElementById('lunr-results');
    if (!container) return;

    if (!hits || hits.length === 0) {
      container.innerHTML =
        '<p class="search-result" style="color:#586069;padding:10px 14px;">No results found.</p>';
      return;
    }

    var html = '<div class="search-results">';
    hits.slice(0, 20).forEach(function (hit) {
      var doc = indexData.find(function (d) { return d.id === hit.ref; });
      if (!doc) return;
      var url = (doc.type === 'yaml')
        ? ('?yaml=' + encodeURIComponent(doc.id))
        : ('?md='   + encodeURIComponent(doc.id));
      var excerpt = String(doc.summary || '').slice(0, 120);
      html += '<div class="search-result">';
      html += '<span class="category-tag">' + esc(doc.category || 'doc') + '</span>';
      html += '<a href="' + esc(url) + '">' + esc(doc.name || doc.id) + '</a>';
      if (excerpt) {
        html += '<p style="font-size:0.85em;color:#586069;margin:4px 0 0">' +
                esc(excerpt) + '</p>';
      }
      html += '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
  }

  /* ── DOM category filter (fallback + combined) ─────────────────────────── */
  function filterCategoryCards(query, category) {
    var items      = document.querySelectorAll('.category-item');
    var categories = document.querySelectorAll('.category');
    var q          = query.trim().toLowerCase();

    if (!q && (!category || category === 'all')) {
      categories.forEach(function (c) { c.style.display = 'block'; });
      items.forEach(function (i)      { i.style.display = 'block'; });
      return;
    }

    categories.forEach(function (c) { c.style.display = 'none'; });

    items.forEach(function (item) {
      var titleEl = item.querySelector('a');
      var subEl   = item.querySelector('.subcategory');
      var title   = titleEl ? titleEl.textContent.toLowerCase() : '';
      var desc    = subEl   ? subEl.textContent.toLowerCase()   : '';
      var textMatch = !q || title.includes(q) || desc.includes(q);

      if (textMatch) {
        item.style.display = 'block';
        var parent = item.closest('.category');
        if (parent) parent.style.display = 'block';
      } else {
        item.style.display = 'none';
      }
    });
  }

  /* ── Main query handler ───────────────────────────────────────────────── */
  function runQuery(query, category) {
    var lunrContainer = document.getElementById('lunr-results');
    category = category || 'all';

    if (!query.trim() && category === 'all') {
      if (lunrContainer) lunrContainer.innerHTML = '';
      filterCategoryCards('', 'all');
      return;
    }

    if (indexLoaded && lunrIndex) {
      var hits = [];
      if (query.trim()) {
        try {
          hits = lunrIndex.search(query + '*');
        } catch (e1) {
          try { hits = lunrIndex.search(query); } catch (e2) { hits = []; }
        }
      } else {
        hits = indexData.map(function (d) { return { ref: d.id, score: 1 }; });
      }

      if (category !== 'all') {
        hits = hits.filter(function (h) {
          var doc = indexData.find(function (d) { return d.id === h.ref; });
          return doc && doc.category === category;
        });
      }

      renderResults(hits);
    } else if (lunrContainer) {
      lunrContainer.innerHTML = '';
    }

    // Always update the DOM card filter in parallel
    filterCategoryCards(query, category);
  }

  /* ── Wire up on DOMContentLoaded ──────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    var searchInput    = document.getElementById('search-input');
    var categoryFilter = document.getElementById('category-filter');

    if (!searchInput) return;

    // Mark as active so inline script skips its own handler
    window.__SECUREAI_SEARCH_ACTIVE = true;

    // Lazy-load on first focus
    searchInput.addEventListener('focus', function () {
      if (!indexLoading) initSearch();
    }, { once: true });

    searchInput.addEventListener('input', function () {
      var cat = categoryFilter ? categoryFilter.value : 'all';
      runQuery(searchInput.value, cat);
    });

    if (categoryFilter) {
      categoryFilter.addEventListener('change', function () {
        runQuery(searchInput.value, categoryFilter.value);
      });
    }
  });

}());
