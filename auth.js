// --- Local Storage Keys ---
const STORAGE_USERS_KEY = 'l1_portal_users';
const STORAGE_LINKS_KEY = 'l1_portal_links';
const STORAGE_SESSION_KEY = 'l1SessionUser';
const STORAGE_MODES_KEY = 'l1LinkModes';

let users = [];
let links = [];
let currentUser = JSON.parse(localStorage.getItem(STORAGE_SESSION_KEY) || 'null');
let linkModes = JSON.parse(localStorage.getItem(STORAGE_MODES_KEY) || '{}');
let currentCategory = 'Dashboard';
let searchQuery = '';

// --- Initialization ---
async function initSystem() {
    // Load Users with localStorage persistence check
    const savedUsers = localStorage.getItem(STORAGE_USERS_KEY);
    if (savedUsers) {
        try {
            users = JSON.parse(savedUsers);
        } catch (e) {
            users = [];
        }
    }

    if (!users || users.length === 0) {
        try {
            const uRes = await fetch('users.json');
            if (uRes.ok) {
                users = await uRes.json();
            } else {
                throw new Error('Failed to load users.json');
            }
        } catch (e) {
            users = [
                { id: 1, email: "admin@sarvatra.in", password: "admin123", role: "admin" },
                { id: 2, email: "viewer@sarvatra.in", password: "viewer123", role: "viewer" }
            ];
        }
        localStorage.setItem(STORAGE_USERS_KEY, JSON.stringify(users));
    }

    // Load Links with localStorage persistence check
    const savedLinks = localStorage.getItem(STORAGE_LINKS_KEY);
    if (savedLinks) {
        try {
            links = JSON.parse(savedLinks);
        } catch (e) {
            links = [];
        }
    }

    if (!links || links.length === 0) {
        try {
            const lRes = await fetch('portal-data.json');
            if (lRes.ok) {
                links = await lRes.json();
            } else {
                throw new Error('Failed to load portal-data.json');
            }
        } catch (e) {
            links = [
                { id: 1, title: "SRVT UPI SMT Monitoring Portal", category: "Monitoring", tag: "UPI", dcUrl: "http://10.61.176.10:9090/smt/#!/srvtupi", drUrl: "", desc: "SRVT UPI SMT Monitoring Portal and service telemetry.", icon: "fa-chart-line" },
                { id: 4, title: "UPI CBSGW", category: "Gateway", tag: "UPI", dcUrl: "https://10.61.159.13:8443/cbsgw/", drUrl: "https://10.158.58.25:8443/cbsgw/#!/station", desc: "UPI Core Banking Switch Gateway with independent DC/DR mapping.", icon: "fa-network-wired" },
                { id: 8, title: "IMPS Switch", category: "Switch", tag: "IMPS", dcUrl: "https://10.61.158.1:8443/jpos/", drUrl: "https://10.158.58.10:8443/jpos/", desc: "IMPS Switch transaction processing interface.", icon: "fa-right-left" },
                { id: 13, title: "UPI Switch", category: "Switch", tag: "UPI", dcUrl: "http://172.21.0.125:9091/srvt-upi/#!/login", drUrl: "http://10.158.172.125:9091/srvt-upi/#!/login", desc: "SRVT UPI Switch login portal with dedicated DR mapping.", icon: "fa-right-left" },
                { id: 14, title: "Accops SMUI", category: "Other", tag: "SMUI", dcUrl: "https://172.21.0.12:10443/smui/", drUrl: "https://10.158.172.12:10443/smui/", desc: "Accops virtual desktop & application access portal.", icon: "fa-desktop" }
            ];
        }
        localStorage.setItem(STORAGE_LINKS_KEY, JSON.stringify(links));
    }

    links = links.map(({ pinned, ...link }) => ({
        ...link,
        category: link.category === 'Pinned' ? 'Other' : link.category,
        icon: link.icon === 'fa-thumbtack' ? 'fa-desktop' : link.icon
    }));
    localStorage.setItem(STORAGE_LINKS_KEY, JSON.stringify(links));

    if (currentUser) {
        showPortalInterface();
    } else {
        const overlay = document.getElementById('auth-overlay');
        if (overlay) overlay.classList.remove('hidden');
    }
}

// --- Authentication Handler ---
function handleLogin(event) {
    event.preventDefault();
    const emailInput = document.getElementById('login-email').value.trim().toLowerCase();
    const passwordInput = document.getElementById('login-password').value;
    const errorBox = document.getElementById('login-error');

    const matchedUser = users.find(u => u.email.toLowerCase() === emailInput && u.password === passwordInput);

    if (matchedUser) {
        currentUser = matchedUser;
        localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(currentUser));
        if (errorBox) errorBox.classList.add('hidden');
        showPortalInterface();
    } else {
        if (errorBox) {
            errorBox.textContent = "Invalid email address or password. Please check your credentials.";
            errorBox.classList.remove('hidden');
        }
    }
}

function logoutUser() {
    currentUser = null;
    localStorage.removeItem(STORAGE_SESSION_KEY);
    const overlay = document.getElementById('auth-overlay');
    const wrapper = document.getElementById('portal-wrapper');
    if (overlay) overlay.classList.remove('hidden');
    if (wrapper) wrapper.classList.add('hidden');
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
        <button onclick="selectCategory('Dashboard')" class="w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-semibold transition-all ${currentCategory === 'Dashboard' ? 'bg-blue-600 text-white shadow-md' : 'text-slate-300 hover:bg-slate-800 hover:text-white'}">
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
            <button onclick="selectCategory('${cat}')" class="w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all ${isActive ? 'bg-blue-600 text-white shadow-md' : 'text-slate-300 hover:bg-slate-800 hover:text-white'}">
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
        filtered = links.filter(l => l.title.toLowerCase().includes(query) || l.desc.toLowerCase().includes(query) || l.tag.toLowerCase().includes(query));
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
                <button onclick="openAllCategory('${currentCategory}')" class="text-xs bg-slate-800 hover:bg-slate-900 text-white px-3 py-2 rounded-lg font-semibold transition-all">
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
                            <i class="fa-solid ${item.icon || 'fa-link'}"></i>
                        </div>
                        <div>
                            <span class="text-[10px] font-bold uppercase tracking-wider text-blue-600 bg-blue-50 px-2 py-0.5 rounded">${item.tag || item.category}</span>
                            <h3 class="font-bold text-slate-900 text-sm mt-0.5 line-clamp-1">${item.title}</h3>
                        </div>
                    </div>
                    <div class="flex items-center space-x-1.5 flex-shrink-0">
                        ${hasDr ? `
                            <div class="inline-flex rounded-lg p-0.5 bg-slate-100 border border-slate-200 text-[10px] font-bold">
                                <button onclick="setLinkMode(${item.id}, 'dc')" class="px-2 py-1 rounded-md transition-all ${mode === 'dc' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-600 hover:text-slate-900'}">DC</button>
                                <button onclick="setLinkMode(${item.id}, 'dr')" class="px-2 py-1 rounded-md transition-all ${mode === 'dr' ? 'bg-amber-500 text-white shadow-sm' : 'text-slate-600 hover:text-slate-900'}">DR</button>
                            </div>
                        ` : `<span class="text-[10px] font-bold px-2 py-1 bg-slate-100 text-slate-500 rounded border border-slate-200">DC ONLY</span>`}
                        
                    </div>
                </div>
                <p class="text-xs text-slate-500 line-clamp-2 mb-4">${item.desc || 'Operational department portal endpoint.'}</p>
            </div>

            <div>
                <div class="bg-slate-50 rounded-xl p-2.5 mb-3 border border-slate-100 flex items-center justify-between">
                    <span class="text-[11px] font-mono text-slate-600 truncate mr-2 select-all">${activeUrl}</span>
                    <button onclick="copyToClipboard('${activeUrl}')" class="text-slate-400 hover:text-blue-600 p-1 flex-shrink-0 transition-colors" title="Copy URL">
                        <i class="fa-regular fa-copy text-xs"></i>
                    </button>
                </div>
                <div class="flex items-center justify-between pt-2 border-t border-slate-100 text-xs">
                    <span class="text-slate-400 uppercase font-bold text-[10px]">${item.category}</span>
                    <a href="${activeUrl}" target="_blank" class="inline-flex items-center space-x-1.5 font-semibold text-blue-600 hover:text-blue-700 bg-blue-50 hover:bg-blue-100 px-3 py-1.5 rounded-lg transition-all">
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
    toast.innerHTML = `<i class="fa-solid ${isError ? 'fa-circle-exclamation text-white' : 'fa-circle-check text-blue-400'}"></i><span>${message}</span>`;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
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
        window.open(url, '_blank');
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
        id: Date.now(),
        title: document.getElementById('add-title').value,
        category: document.getElementById('add-category').value,
        tag: document.getElementById('add-tag').value || 'Custom',
        dcUrl: document.getElementById('add-dc').value,
        drUrl: document.getElementById('add-dr').value || '',
        desc: "Custom operational link added by administrator.",
        icon: "fa-link",
    };

    links.push(newLink);
    localStorage.setItem(STORAGE_LINKS_KEY, JSON.stringify(links));
    closeAddModal();
    renderSidebar();
    renderPortalContent();
    showToast("Custom URL added successfully!");
    event.target.reset();
}

function openAdminModal() {
    if (currentUser?.role !== 'admin') {
        showToast("Access Denied.", true);
        return;
    }
    renderUsersTable();
    document.getElementById('admin-modal')?.classList.remove('hidden');
}

function closeAdminModal() {
    document.getElementById('admin-modal')?.classList.add('hidden');
}

function renderUsersTable() {
    const tbody = document.getElementById('users-table-body');
    if (!tbody) return;

    tbody.innerHTML = users.map(u => `
        <tr>
            <td class="p-3 font-semibold text-slate-900">${u.email}</td>
            <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${u.role === 'admin' ? 'bg-amber-100 text-amber-800' : 'bg-blue-100 text-blue-800'}">${u.role}</span></td>
            <td class="p-3 text-right">
                ${u.email !== currentUser.email ? `<button onclick="deleteUser(${u.id})" class="text-red-500 hover:text-red-700 font-semibold">Delete</button>` : '<span class="text-slate-400">Current</span>'}
            </td>
        </tr>
    `).join('');
}

function handleCreateUser(event) {
    event.preventDefault();
    if (currentUser?.role !== 'admin') return;

    const email = document.getElementById('new-user-email').value.trim();
    const password = document.getElementById('new-user-pass').value;
    const role = document.getElementById('new-user-role').value;

    if (users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
        showToast("User with this email already exists!", true);
        return;
    }

    const newUser = { id: Date.now(), email, password, role };
    users.push(newUser);
    localStorage.setItem(STORAGE_USERS_KEY, JSON.stringify(users));
    renderUsersTable();
    showToast(`User ${email} created successfully!`);
    event.target.reset();
}

function deleteUser(id) {
    if (currentUser?.role !== 'admin') return;
    users = users.filter(u => u.id !== id);
    localStorage.setItem(STORAGE_USERS_KEY, JSON.stringify(users));
    renderUsersTable();
    showToast("User deleted successfully.");
}

// Search Event Listener
document.addEventListener('DOMContentLoaded', () => {
    initSystem();
    const searchInput = document.getElementById('global-search');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            renderPortalContent();
        });
    }
});