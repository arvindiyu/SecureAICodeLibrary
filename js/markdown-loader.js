// Markdown rendering library - Using marked.js
// This script handles loading and rendering markdown files within the site template
// Extended: lazy Mermaid post-render, YAML-link rewriting, lazy Prism highlighting.

/* ── Source-aware relative-path resolution ─────────────────────────────────
   Rendered markdown documents commonly use sibling-relative links like
   `./SOURCES.md`, `../adr/0004-...md`, or `../../THREAT_MODEL.md`. The SPA
   serves them all under a single URL (index.html?md=...), so the browser
   resolves those relative paths against the SPA root, not the source
   markdown's directory — producing 404s. resolveSourceRelative() normalizes
   them against the currently-rendered source file's directory before fetch.
*/
function getCurrentSourcePath() {
    var params = new URLSearchParams(window.location.search);
    return params.get('md') || params.get('yaml') || '';
}

function resolveSourceRelative(currentSource, target) {
    if (!target) return target;
    if (target.charAt(0) === '/') return target.replace(/^\/+/, '');
    var currentDir = String(currentSource || '').replace(/[^/]*$/, '');
    if (!currentDir) return target; // no source context = treat as repo-rooted
    var parts = (currentDir + target).split('/');
    var out = [];
    for (var i = 0; i < parts.length; i++) {
        var seg = parts[i];
        if (seg === '' || seg === '.') continue;
        if (seg === '..') { out.pop(); continue; }
        out.push(seg);
    }
    return out.join('/');
}

/* ── Lazy script loader (memoized) ─────────────────────────────────────── */
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

/* ── Post-render hook: Mermaid, YAML links, Prism ───────────────────────── */
function postRenderMarkdown(container) {
    var cdn = window.__SECUREAI_CDN || {};

    // 1. Rewrite .yaml AND .md links → SPA form, resolving relative paths
    //    against the currently-rendered source file's directory.
    var currentSource = getCurrentSourcePath();
    var anchors = container.querySelectorAll('a[href]');
    anchors.forEach(function (a) {
        var href = a.getAttribute('href');
        if (!href) return;
        if (href.startsWith('?') || href.startsWith('http') || href.startsWith('#')) return;
        if (href.startsWith('mailto:') || href.startsWith('javascript:')) return;
        if (/\.(rule\.yaml|spec\.yaml|subagent\.yaml|yaml)$/i.test(href)) {
            var resolved = resolveSourceRelative(currentSource, href);
            a.setAttribute('href', '?yaml=' + encodeURIComponent(resolved));
        } else if (/\.(md|markdown)(#[^?]*)?$/i.test(href)) {
            // Split fragment so it's preserved in the SPA URL.
            var hashIdx = href.indexOf('#');
            var pathPart = hashIdx >= 0 ? href.substring(0, hashIdx) : href;
            var hashPart = hashIdx >= 0 ? href.substring(hashIdx) : '';
            var resolvedMd = resolveSourceRelative(currentSource, pathPart);
            a.setAttribute('href', '?md=' + encodeURIComponent(resolvedMd) + hashPart);
        }
    });

    // 2. Mermaid: lazy-load and render if language-mermaid blocks present.
    //    marked.js HTML-escapes <pre><code> content (<br/> → &lt;br/&gt; etc.),
    //    so we must transform to <div class="mermaid"> with decoded textContent
    //    BEFORE Mermaid runs. We also lift accTitle:/accDescr: directives to
    //    ARIA attributes on the wrapper because they tend to trip the v10 parser
    //    when descriptions contain commas, em-dashes, or parentheses.
    var mermaidBlocks = container.querySelectorAll('pre > code.language-mermaid');
    if (mermaidBlocks.length > 0) {
        mermaidBlocks.forEach(function (codeEl) {
            var source = codeEl.textContent;  // decoded source (entities → chars)
            // Extract accTitle / accDescr for ARIA and strip them from source.
            var accTitle = '';
            var accDescr = '';
            var cleaned = source.split('\n').filter(function (line) {
                var m = line.match(/^\s*accTitle:\s*(.*)$/);
                if (m) { accTitle = m[1].trim(); return false; }
                m = line.match(/^\s*accDescr:\s*(.*)$/);
                if (m) { accDescr = m[1].trim(); return false; }
                return true;
            }).join('\n');

            var wrapper = document.createElement('div');
            wrapper.className = 'mermaid mermaid-scroll';
            if (accTitle) wrapper.setAttribute('aria-label', accTitle);
            if (accDescr) wrapper.setAttribute('aria-description', accDescr);
            wrapper.textContent = cleaned;  // textContent assignment is safe
            // Replace the entire <pre> ancestor, not just the <code>.
            var pre = codeEl.closest('pre');
            (pre || codeEl).replaceWith(wrapper);
        });

        var mermaidUrl = cdn.mermaid ||
            'https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js';
        loadScript(mermaidUrl).then(function () {
            if (!window.mermaid) return;
            window.mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });
            window.mermaid.run({
                querySelector: '.mermaid:not([data-processed="true"])',
                suppressErrors: false
            }).catch(function (e) {
                // Render the parse error inline so authors can see what failed.
                console.error('[Mermaid render error]', e && e.message);
            });
        }).catch(function () { /* CDN unavailable; non-fatal */ });
    }

    // 3. Prism: lazy-load core + language modules for yaml/bash/json blocks
    var prismLangs = { yaml: false, bash: false, json: false };
    container.querySelectorAll('pre code').forEach(function (block) {
        var cls = block.className || '';
        if (/language-ya?ml/i.test(cls))   prismLangs.yaml = true;
        if (/language-bash|language-sh/i.test(cls)) prismLangs.bash = true;
        if (/language-json/i.test(cls))    prismLangs.json = true;
    });

    var needsPrism = prismLangs.yaml || prismLangs.bash || prismLangs.json;
    if (needsPrism) {
        var prismCoreUrl = cdn.prismCore ||
            'https://cdn.jsdelivr.net/npm/prismjs@1.29.0/prism.min.js';
        loadScript(prismCoreUrl).then(function () {
            var extras = [];
            if (prismLangs.yaml) {
                extras.push(loadScript(
                    cdn.prismYaml ||
                    'https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-yaml.min.js'
                ));
            }
            if (prismLangs.bash) {
                extras.push(loadScript(
                    cdn.prismBash ||
                    'https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-bash.min.js'
                ));
            }
            if (prismLangs.json) {
                extras.push(loadScript(
                    cdn.prismJson ||
                    'https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-json.min.js'
                ));
            }
            Promise.all(extras).then(function () {
                if (typeof Prism !== 'undefined') Prism.highlightAll();
            }).catch(function () { /* non-fatal */ });
        }).catch(function () { /* non-fatal */ });
    }
}

// Expose for yaml-loader.js
window.__postRenderMarkdown = postRenderMarkdown;

document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on a page that needs to load markdown
    const urlParams = new URLSearchParams(window.location.search);
    const markdownPath = urlParams.get('md');
    
    if (markdownPath) {
        loadMarkdownContent(markdownPath);
    }
});

// Intercept all markdown links and modify them to use our router.
// Handles four href forms:
//   ?md=path/to/file.md          → SPA-style markdown link (nav uses this)
//   ?yaml=path/to/file.yaml      → delegate to yaml-loader (handled there too)
//   raw path/to/file.md          → legacy relative markdown link
//   raw path/to/file.{rule,spec,subagent}.yaml → legacy relative YAML link
document.addEventListener('click', function (event) {
    var link = event.target.closest('a');
    if (!link) return;
    var href = link.getAttribute('href');
    if (!href) return;

    // Skip external, mailto, javascript:, and pure in-page anchors.
    if (/^(https?:|mailto:|javascript:)/i.test(href)) return;
    if (href.charAt(0) === '#') return;

    // ?yaml= links: yaml-loader has its own click handler; don't double-intercept.
    if (href.indexOf('?yaml=') === 0) return;

    var mdPath = null;
    var hashPart = '';
    if (href.indexOf('?md=') === 0) {
        // Strip the ?md= prefix to get the actual file path (already absolute).
        var raw = href.slice(4);
        var qHashIdx = raw.indexOf('#');
        if (qHashIdx >= 0) { hashPart = raw.substring(qHashIdx); raw = raw.substring(0, qHashIdx); }
        mdPath = decodeURIComponent(raw);
    } else if (/\.(md|markdown)(#[^?]*)?$/i.test(href)) {
        // Raw relative .md link (defensive — postRenderMarkdown should rewrite
        // these, but inline-injected links or future code paths may bypass it).
        var hashIdx = href.indexOf('#');
        var pathPart = hashIdx >= 0 ? href.substring(0, hashIdx) : href;
        hashPart = hashIdx >= 0 ? href.substring(hashIdx) : '';
        mdPath = resolveSourceRelative(getCurrentSourcePath(), pathPart);
    }
    if (!mdPath) return;

    event.preventDefault();
    window.history.pushState({}, '', '?md=' + encodeURIComponent(mdPath) + hashPart);
    loadMarkdownContent(mdPath);
    // Scroll to fragment after content paints, if specified.
    if (hashPart && hashPart.length > 1) {
        setTimeout(function () {
            var target = document.getElementById(hashPart.slice(1));
            if (target && target.scrollIntoView) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 50);
    }
});

// Handle browser back/forward navigation
window.addEventListener('popstate', function() {
    const urlParams = new URLSearchParams(window.location.search);
    const markdownPath = urlParams.get('md');
    
    if (markdownPath) {
        loadMarkdownContent(markdownPath);
    } else {
        // If no markdown parameter, we're back to home
        document.getElementById('content-container').style.display = 'none';
        document.getElementById('main-content').style.display = 'block';
    }
});

function loadMarkdownContent(path) {
    // Defensive: strip any stray ?md= / ?yaml= prefix so callers can be sloppy.
    if (typeof path === 'string') {
        if (path.indexOf('?md=') === 0)   path = decodeURIComponent(path.slice(4));
        if (path.indexOf('?yaml=') === 0) path = decodeURIComponent(path.slice(6));
    }

    const contentContainer = document.getElementById('content-container');
    contentContainer.innerHTML = '<div class="loading"><i class="fas fa-circle-notch fa-spin"></i> Loading content...</div>';
    contentContainer.style.display = 'block';
    document.getElementById('main-content').style.display = 'none';

    updatePageTitle(path);
    
    // Fetch the markdown file
    fetch(path)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.text();
        })
        .then(markdown => {
            // Use marked.js to convert markdown to HTML
            const html = marked.parse(markdown);
            
            // Add breadcrumb navigation
            const breadcrumbs = generateBreadcrumbs(path);
            
            // Insert the HTML into the page
            contentContainer.innerHTML = `
                <div class="breadcrumbs">${breadcrumbs}</div>
                <div class="markdown-content">${html}</div>
                <div class="back-link">
                    <a href="javascript:history.back()" class="btn-back">
                        <i class="fas fa-arrow-left"></i> Back
                    </a>
                    <a href="index.html" class="btn-home">
                        <i class="fas fa-home"></i> Home
                    </a>
                </div>
            `;
            
            // Highlight code blocks (existing highlight.js)
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightBlock(block);
            });

            // Extended post-render: Mermaid, YAML link rewriting, Prism
            postRenderMarkdown(contentContainer);
        })
        .catch(error => {
            contentContainer.innerHTML = `
                <div class="error-container">
                    <h3><i class="fas fa-exclamation-triangle"></i> Error Loading Content</h3>
                    <p>Sorry, we couldn't load the requested content:</p>
                    <pre>${error.message}</pre>
                    <a href="index.html" class="btn-home">
                        <i class="fas fa-home"></i> Return to Home
                    </a>
                </div>
            `;
        });
}

function updatePageTitle(path) {
    // Extract a title from the path
    const fileName = path.split('/').pop().replace('.md', '');
    const formattedTitle = fileName
        .split('-')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
    
    document.title = `${formattedTitle} - Secure Code Library`;
}

function generateBreadcrumbs(path) {
    // Defensive: strip any router-prefix and leading ./ before splitting.
    var cleanPath = String(path || '');
    if (cleanPath.indexOf('?md=') === 0)   cleanPath = decodeURIComponent(cleanPath.slice(4));
    if (cleanPath.indexOf('?yaml=') === 0) cleanPath = decodeURIComponent(cleanPath.slice(6));
    cleanPath = cleanPath.replace(/^\.\//, '');
    // Strip query strings and hash fragments from any segment.
    cleanPath = cleanPath.split('?')[0].split('#')[0];
    const parts = cleanPath.split('/').filter(Boolean);
    let breadcrumbHtml = '<a href="index.html"><i class="fas fa-home"></i> Home</a>';
    
    let currentPath = '';
    
    // For each part of the path, create a breadcrumb
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        currentPath += (i === 0 ? '' : '/') + part;
        
        // Skip adding a link for the last item (current page)
        if (i === parts.length - 1) {
            // Format the final breadcrumb name (remove .md and format)
            const displayName = part
                .replace('.md', '')
                .split('-')
                .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                .join(' ');
                
            breadcrumbHtml += ` <i class="fas fa-chevron-right"></i> <span>${displayName}</span>`;
        } else {
            // Format the folder name
            const displayName = part
                .split('-')
                .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                .join(' ');
                
            breadcrumbHtml += ` <i class="fas fa-chevron-right"></i> <span>${displayName}</span>`;
        }
    }
    
    return breadcrumbHtml;
}
