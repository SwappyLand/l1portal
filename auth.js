// --- Local Storage Keys ---
const STORAGE_USERS_KEY = 'l1_portal_users';
const STORAGE_LINKS_KEY = 'l1_portal_links';
const STORAGE_MODES_KEY = 'l1LinkModes';

let users = [];
let links = [];
let currentUser = null;
let linkModes = JSON.parse(localStorage.getItem(STORAGE_MODES_KEY) || '{}');
let csrfToken = '';
let currentCategory = 'Dashboard';
localStorage.removeItem(STORAGE_USERS_KEY);
localStorage.removeItem(STORAGE_LINKS_KEY);
localStorage.removeItem('l1SessionUser');

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[character]);
}

async function apiRequest(url, options = {}) {
    const method = options.method || 'GET';
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }
    if (method !== 'GET' && method !== 'HEAD') {
        if (!csrfToken) {
            const tokenResponse = await fetch('/api/auth/csrf', { credentials: 'same-origin' });
            if (!tokenResponse.ok) throw new Error('Unable to initialize a secure session.');
            csrfToken = (await tokenResponse.json()).csrfToken;
        }
        headers.set('X-CSRF-Token', csrfToken);
    }

    const response = await fetch(url, { ...options, method, headers, credentials: 'same-origin' });
    if (response.status === 204) return null;
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(payload.error || 'The server request failed.');
    }
    return payload;
}

async function loadPortalData() {
    links = await apiRequest('/api/links');
}

// --- Initialization ---
async function initSystem() {
    try {
        const [session, csrf] = await Promise.all([
            apiRequest('/api/auth/me'),
            fetch('/api/auth/csrf', { credentials: 'same-origin' }).then(async response => {
                if (!response.ok) throw new Error('Unable to initialize a secure session.');
                return response.json();
            })
        ]);
        currentUser = session.user;
        csrfToken = csrf.csrfToken;
        if (currentUser) {
            await loadPortalData();
            showPortalInterface();
        } else {
            document.getElementById('auth-overlay')?.classList.remove('hidden');
        }
    } catch (error) {
        const errorBox = document.getElementById('login-error');
        if (errorBox) {
            errorBox.textContent = `Unable to connect to the portal server: ${error.message}`;
            errorBox.classList.remove('hidden');
        }
    }
}

// --- Authentication Handler ---
async function handleLogin(event) {
    event.preventDefault();
    const emailInput = document.getElementById('login-email').value.trim().toLowerCase();
    const passwordInput = document.getElementById('login-password').value;
    const errorBox = document.getElementById('login-error');

    try {
        const result = await apiRequest('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email: emailInput, password: passwordInput })
        });
        currentUser = result.user;
        csrfToken = '';
        await apiRequest('/api/auth/csrf').then(result => { csrfToken = result.csrfToken; });
        await loadPortalData();
        if (errorBox) errorBox.classList.add('hidden');
        showPortalInterface();
    } catch (error) {
        if (errorBox) {
            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
        }
    }
}

async function logoutUser() {
    try {
        await apiRequest('/api/auth/logout', { method: 'POST' });
        currentUser = null;
        users = [];
        links = [];
        csrfToken = '';
        document.getElementById('auth-overlay')?.classList.remove('hidden');
        document.getElementById('portal-wrapper')?.classList.add('hidden');
    } catch (error) {
        showToast(error.message, true);
    }
}

// --- Portal Interface Setup ---
function showPortalInterface() {
    const overlay = document.getElementById('auth-overlay');
    const wrapper = document.getElementById('portal-wrapper');
    if (overlay) overlay.classList.add('hidden');
    if (wrapper) wrapper.classList.remove('hidden');

    // Update user info badges
    const usernameEl = document.getElementById('current-username');
    const roleBadge = document.getElementById('user-role-badge');
    const adminMenuItem = document.getElementById('admin-menu-item');
    const addUrlBtn = document.getElementById('add-url-btn');

    if (usernameEl) usernameEl.textContent = currentUser.email;
    if (roleBadge) {
        roleBadge.textContent = currentUser.role.toUpperCase();
        roleBadge.className = currentUser.role === 'admin' 
            ? "text-[10px] bg-amber-500 text-white px-2 py-0.5 rounded font-bold uppercase"
            : "text-[10px] bg-blue-500 text-white px-2 py-0.5 rounded font-bold uppercase";
    }

    if (currentUser.role === 'admin') {
        if (adminMenuItem) adminMenuItem.classList.remove('hidden');
        if (addUrlBtn) addUrlBtn.classList.remove('hidden');
    } else {
        if (adminMenuItem) adminMenuItem.classList.add('hidden');
        if (addUrlBtn) addUrlBtn.classList.add('hidden');
    }

    renderSidebar();
    renderPortalContent();
}

// --- Sidebar Rendering ---
function renderSidebar() {
    const nav = document.getElementById('sidebar-nav');
    if (!nav) return;

    const categories = ['Dashboard', 'Monitoring', 'Gateway', 'Switch', 'Enterprise', 'SMS', 'Admin', 'Other'];
    
    let html = `
        <button data-category="Dashboard" class="w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-semibold transition-all ${currentCategory === 'Dashboard' ? 'bg-blue-600 text-white shadow-md' : 'text-slate-300 hover:bg-slate-800 hover:text-white'}">
            <div class="flex items-center space-x-3">
                <i class="fa-solid fa-house w-5 text-center"></i>
                <span>Dashboard</span>
            </div>
            <span class="text-xs bg-slate-800 text-slate-300 px-2 py-0.5 rounded-full">${links.length}</span>
        </button>
        <div class="pt-2 pb-1 px-3 text-[10px] font-bold uppercase tracking-wider text-slate-400">Categories</div>
    `;

    categories.filter(c => c !== 'Dashboard').forEach(cat => {
        const count = links.filter(l => l.category === cat).length;
        const isActive = currentCategory === cat;
        html += `
            <button data-category="${escapeHtml(cat)}" class="w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all ${isActive ? 'bg-blue-600 text-white shadow-md' : 'text-slate-300 hover:bg-slate-800 hover:text-white'}">
                <div class="flex items-center space-x-3">
                    <i class="fa-solid ${getCategoryIcon(cat)} w-5 text-center"></i>
                    <span>${cat}</span>
                </div>
                <span class="text-xs ${isActive ? 'bg-blue-700 text-white' : 'bg-slate-800 text-slate-300'} px-2 py-0.5 rounded-full">${count}</span>
            </button>
        `;
    });

    nav.innerHTML = html;
}

function getCategoryIcon(cat) {
    switch(cat) {
        case 'Monitoring': return 'fa-chart-line';
        case 'Gateway': return 'fa-network-wired';
        case 'Switch': return 'fa-right-left';
        case 'Enterprise': return 'fa-building';
        case 'SMS': return 'fa-comment-sms';
        case 'Admin': return 'fa-shield-halved';
        default: return 'fa-folder';
    }
}

function selectCategory(cat) {
    currentCategory = cat;
    renderSidebar();
    renderPortalContent();
}

// --- Content Rendering ---
function renderPortalContent() {
    const titleEl = document.getElementById('section-title');
    const subtitleEl = document.getElementById('section-subtitle');
    const countBadge = document.getElementById('result-count-badge');
    const urlsGrid = document.getElementById('urls-grid');
    const openAllContainer = document.getElementById('open-all-container');

    if (!urlsGrid) return;

    // Filter links by category or search query
    let filtered = links;
    const query = (document.getElementById('global-search')?.value || '').toLowerCase();

    if (query) {
        filtered = links.filter(l => [
            l.title, l.desc, l.tag, l.category, l.dcUrl, l.drUrl
        ].some(value => (value || '').toLowerCase().includes(query)));
        if (titleEl) titleEl.textContent = `Search Results (${filtered.length})`;
        if (subtitleEl) subtitleEl.textContent = `Showing URLs matching "${query}"`;
    } else {
        if (currentCategory === 'Dashboard') {
            if (titleEl) titleEl.textContent = "All Department Portals";
            if (subtitleEl) subtitleEl.textContent = "Showing registered internal operational links";
        } else {
            if (titleEl) titleEl.textContent = `${currentCategory} Portals`;
            if (subtitleEl) subtitleEl.textContent = `Showing operational endpoints under ${currentCategory}`;
            filtered = links.filter(l => l.category === currentCategory);
        }

        // Open All Button for category
        if (currentCategory !== 'Dashboard' && filtered.length > 0 && openAllContainer) {
            openAllContainer.innerHTML = `
                <button data-open-category="${escapeHtml(currentCategory)}" class="text-xs bg-slate-800 hover:bg-slate-900 text-white px-3 py-2 rounded-lg font-semibold transition-all">
                    <i class="fa-solid fa-external-link-alt mr-1"></i> Open All (${filtered.length})
                </button>
            `;
        } else if (openAllContainer) {
            openAllContainer.innerHTML = '';
        }
    }

    if (countBadge) countBadge.textContent = `${filtered.length} URLs`;
    urlsGrid.innerHTML = filtered.map(l => createCardHTML(l)).join('');
}

function createCardHTML(item) {
    const mode = linkModes[item.id] || 'dc';
    const hasDr = item.drUrl && item.drUrl.trim() !== '';
    const activeUrl = (mode === 'dr' && hasDr) ? item.drUrl : item.dcUrl;

    return `
        <div class="bg-white rounded-2xl border border-slate-200/80 p-5 shadow-sm card-hover flex flex-col justify-between transition-all relative">
            <div>
                <div class="flex items-start justify-between gap-2 mb-3">
                    <div class="flex items-center space-x-2.5">
                        <div class="h-9 w-9 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center font-bold flex-shrink-0">
                            <i class="fa-solid ${escapeHtml(item.icon || 'fa-link')}"></i>
                        </div>
                        <div>
                            <span class="text-[10px] font-bold uppercase tracking-wider text-blue-600 bg-blue-50 px-2 py-0.5 rounded">${escapeHtml(item.tag || item.category)}</span>
                            <h3 class="font-bold text-slate-900 text-sm mt-0.5 line-clamp-1">${escapeHtml(item.title)}</h3>
                        </div>
                    </div>
                    <div class="flex items-center space-x-1.5 flex-shrink-0">
                        ${hasDr ? `
                            <div class="inline-flex rounded-lg p-0.5 bg-slate-100 border border-slate-200 text-[10px] font-bold">
                                <button data-link-id="${escapeHtml(item.id)}" data-link-mode="dc" class="px-2 py-1 rounded-md transition-all ${mode === 'dc' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-600 hover:text-slate-900'}">DC</button>
                                <button data-link-id="${escapeHtml(item.id)}" data-link-mode="dr" class="px-2 py-1 rounded-md transition-all ${mode === 'dr' ? 'bg-amber-500 text-white shadow-sm' : 'text-slate-600 hover:text-slate-900'}">DR</button>
                            </div>
                        ` : `<span class="text-[10px] font-bold px-2 py-1 bg-slate-100 text-slate-500 rounded border border-slate-200">DC ONLY</span>`}
                        
                    </div>
                </div>
                <p class="text-xs text-slate-500 line-clamp-2 mb-4">${escapeHtml(item.desc || 'Operational department portal endpoint.')}</p>
            </div>

            <div>
                <div class="bg-slate-50 rounded-xl p-2.5 mb-3 border border-slate-100 flex items-center justify-between">
                    <span class="text-[11px] font-mono text-slate-600 truncate mr-2 select-all">${escapeHtml(activeUrl)}</span>
                    <button data-copy-url="${escapeHtml(activeUrl)}" class="text-slate-400 hover:text-blue-600 p-1 flex-shrink-0 transition-colors" title="Copy URL">
                        <i class="fa-regular fa-copy text-xs"></i>
                    </button>
                </div>
                <div class="flex items-center justify-between pt-2 border-t border-slate-100 text-xs">
                    <span class="text-slate-400 uppercase font-bold text-[10px]">${escapeHtml(item.category)}</span>
                    <a href="${escapeHtml(activeUrl)}" target="_blank" rel="noopener noreferrer" class="inline-flex items-center space-x-1.5 font-semibold text-blue-600 hover:text-blue-700 bg-blue-50 hover:bg-blue-100 px-3 py-1.5 rounded-lg transition-all">
                        <span>Open</span>
                        <i class="fa-solid fa-arrow-up-right-from-square text-[10px]"></i>
                    </a>
                </div>
            </div>
        </div>
    `;
}

// --- Interactive Actions ---
function setLinkMode(id, mode) {
    linkModes[id] = mode;
    localStorage.setItem(STORAGE_MODES_KEY, JSON.stringify(linkModes));
    renderPortalContent();
}

function copyToClipboard(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    try {
        document.execCommand('copy');
        showToast("URL copied to clipboard successfully!");
    } catch (err) {
        showToast("Failed to copy URL.", true);
    }
    document.body.removeChild(textArea);
}

function showToast(message, isError = false) {
    const existing = document.getElementById('toast-notification');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'toast-notification';
    toast.className = `fixed bottom-6 right-6 z-50 px-4 py-3 rounded-xl shadow-xl text-xs font-bold text-white flex items-center space-x-2 transition-all ${isError ? 'bg-red-600' : 'bg-slate-900 border border-slate-700'}`;
    const icon = document.createElement('i');
    icon.className = `fa-solid ${isError ? 'fa-circle-exclamation text-white' : 'fa-circle-check text-blue-400'}`;
    const text = document.createElement('span');
    text.textContent = message;
    toast.append(icon, text);
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('opacity-0');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function openAllCategory(cat) {
    const items = links.filter(l => l.category === cat);
    if (items.length > 5 && !confirm(`You are about to open ${items.length} browser tabs. Proceed?`)) {
        return;
    }
    items.forEach(item => {
        const mode = linkModes[item.id] || 'dc';
        const url = (mode === 'dr' && item.drUrl) ? item.drUrl : item.dcUrl;
        window.open(url, '_blank', 'noopener,noreferrer');
    });
}

// --- Modals & Management ---
function openAddModal() {
    if (currentUser?.role !== 'admin') {
        showToast("Access Denied: Admin privileges required.", true);
        return;
    }
    document.getElementById('add-modal')?.classList.remove('hidden');
}

function closeAddModal() {
    document.getElementById('add-modal')?.classList.add('hidden');
}

function handleAddUrl(event) {
    event.preventDefault();
    if (currentUser?.role !== 'admin') return;

    const newLink = {
        title: document.getElementById('add-title').value,
        category: document.getElementById('add-category').value,
        tag: document.getElementById('add-tag').value || 'Custom',
        dcUrl: document.getElementById('add-dc').value,
        drUrl: document.getElementById('add-dr').value || '',
        desc: "Custom operational link added by administrator.",
        icon: "fa-link"
    };

    apiRequest('/api/links', { method: 'POST', body: JSON.stringify(newLink) })
        .then(link => {
            links.push(link);
            closeAddModal();
            renderSidebar();
            renderPortalContent();
            showToast("Custom URL added successfully!");
            event.target.reset();
        })
        .catch(error => showToast(error.message, true));
}

async function openAdminModal() {
    if (currentUser?.role !== 'admin') {
        showToast("Access Denied.", true);
        return;
    }
    try {
        users = await apiRequest('/api/users');
        renderUsersTable();
        document.getElementById('admin-modal')?.classList.remove('hidden');
    } catch (error) {
        showToast(error.message, true);
    }
}

function closeAdminModal() {
    document.getElementById('admin-modal')?.classList.add('hidden');
}

function renderUsersTable() {
    const tbody = document.getElementById('users-table-body');
    if (!tbody || !currentUser) return;

    tbody.innerHTML = users.map(u => `
        <tr>
            <td class="p-3 font-semibold text-slate-900">${escapeHtml(u.email)}</td>
            <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${u.role === 'admin' ? 'bg-amber-100 text-amber-800' : 'bg-blue-100 text-blue-800'}">${escapeHtml(u.role)}</span></td>
            <td class="p-3 text-right">
                ${u.email !== currentUser.email ? `<button data-delete-user="${escapeHtml(u.id)}" class="text-red-500 hover:text-red-700 font-semibold">Delete</button>` : '<span class="text-slate-400">Current</span>'}
            </td>
        </tr>
    `).join('');
}

async function handleCreateUser(event) {
    event.preventDefault();
    if (currentUser?.role !== 'admin') return;

    const email = document.getElementById('new-user-email').value.trim();
    const password = document.getElementById('new-user-pass').value;
    const role = document.getElementById('new-user-role').value;

    try {
        const newUser = await apiRequest('/api/users', {
            method: 'POST',
            body: JSON.stringify({ email, password, role })
        });
        users.push(newUser);
        renderUsersTable();
        showToast(`User ${email} created successfully!`);
        event.target.reset();
    } catch (error) {
        showToast(error.message, true);
    }
}

async function deleteUser(id) {
    if (currentUser?.role !== 'admin') return;
    try {
        await apiRequest(`/api/users/${id}`, { method: 'DELETE' });
        users = users.filter(user => user.id !== id);
        renderUsersTable();
        showToast("User deleted successfully.");
    } catch (error) {
        showToast(error.message, true);
    }
}

// Search Event Listener
document.addEventListener('DOMContentLoaded', () => {
    initSystem();
    document.addEventListener('click', event => {
        const target = event.target instanceof Element ? event.target : null;
        const button = target?.closest('button');
        if (!button) return;

        const action = button.dataset.action;
        if (action === 'open-admin') openAdminModal();
        if (action === 'close-admin') closeAdminModal();
        if (action === 'open-add') openAddModal();
        if (action === 'close-add') closeAddModal();
        if (action === 'logout') logoutUser();
        if (button.dataset.category) selectCategory(button.dataset.category);
        if (button.dataset.openCategory) openAllCategory(button.dataset.openCategory);
        if (button.dataset.linkId && ['dc', 'dr'].includes(button.dataset.linkMode)) {
            setLinkMode(button.dataset.linkId, button.dataset.linkMode);
        }
        if (button.dataset.deleteUser) deleteUser(button.dataset.deleteUser);

        const copyButton = target.closest('[data-copy-url]');
        if (copyButton) {
            copyToClipboard(copyButton.dataset.copyUrl);
        }
    });
    document.addEventListener('submit', event => {
        if (event.target.id === 'login-form') handleLogin(event);
        if (event.target.id === 'create-user-form') handleCreateUser(event);
        if (event.target.id === 'add-url-form') handleAddUrl(event);
    });
    const searchInput = document.getElementById('global-search');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            renderPortalContent();
        });
    }
});