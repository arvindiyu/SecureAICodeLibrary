// Markdown rendering library - Using marked.js
// This script handles loading and rendering markdown files within the site template

document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on a page that needs to load markdown
    const urlParams = new URLSearchParams(window.location.search);
    const markdownPath = urlParams.get('md');
    
    if (markdownPath) {
        loadMarkdownContent(markdownPath);
    }
});

// Intercept all markdown links and modify them to use our router
document.addEventListener('click', function(event) {
    // Check if the clicked element is a link to a markdown file
    const link = event.target.closest('a');
    if (link && link.href.match(/\.(md|markdown)$/i)) {
        event.preventDefault();
        const markdownPath = link.getAttribute('href');
        // Update URL without full page reload
        window.history.pushState({}, '', `?md=${encodeURIComponent(markdownPath)}`);
        loadMarkdownContent(markdownPath);
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
    // Show loading state
    const contentContainer = document.getElementById('content-container');
    contentContainer.innerHTML = '<div class="loading"><i class="fas fa-circle-notch fa-spin"></i> Loading content...</div>';
    contentContainer.style.display = 'block';
    document.getElementById('main-content').style.display = 'none';
    
    // Update the document title with the path
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
            
            // Highlight code blocks
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightBlock(block);
            });
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
    // Remove ./ if it exists
    const cleanPath = path.replace(/^\.\//, '');
    const parts = cleanPath.split('/');
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
