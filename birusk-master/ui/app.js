document.addEventListener('DOMContentLoaded', () => {
    const themeBtn = document.getElementById('theme-toggle');
    const html = document.documentElement;
    const contentArea = document.getElementById('content');
    const langSelect = document.getElementById('lang-selector');
    const sidebar = document.getElementById('sidebar');
    const mobileBtn = document.getElementById('mobile-menu-btn');
    const pageTitle = document.getElementById('page-title');
    
    let usersData = [];
    let nodesData = [];
    
    let coreSettings = JSON.parse(localStorage.getItem('birusk_settings')) || {
        subDomain: '',
        defaultCleanIp: '',
        enableStats: true,
        mtprotoEnabled: false,
        mtprotoPort: '8566',
        mtprotoSecret: '',
        mtprotoTag: ''
    };

    let currentTheme = localStorage.getItem('theme') || 'light';
    html.setAttribute('data-theme', currentTheme);
    
    themeBtn.addEventListener('click', () => {
        currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
        localStorage.setItem('theme', currentTheme);
        html.setAttribute('data-theme', currentTheme);
    });

    const overlay = document.querySelector('.overlay') || document.createElement('div');
    if (!document.querySelector('.overlay')) {
        overlay.className = 'overlay';
        document.body.appendChild(overlay);
    }

    const toggleMenu = () => {
        sidebar.classList.toggle('open');
        if (sidebar.classList.contains('open')) {
            overlay.style.display = 'block';
            setTimeout(() => overlay.style.opacity = '1', 10);
        } else {
            overlay.style.opacity = '0';
            setTimeout(() => overlay.style.display = 'none', 300);
        }
    };

    mobileBtn.addEventListener('click', toggleMenu);
    overlay.addEventListener('click', toggleMenu);

    let currentLang = localStorage.getItem('lang') || 'en';
    
    const applyLang = (lang) => {
        langSelect.value = lang;
        html.setAttribute('lang', lang);
        html.setAttribute('dir', lang === 'fa' ? 'rtl' : 'ltr');
        
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            if (translations[lang] && translations[lang][key]) {
                el.textContent = translations[lang][key];
            } else if (translations[lang] && translations[lang][key] && el.placeholder !== undefined) {
                el.placeholder = translations[lang][key];
            }
        });
    };

    langSelect.addEventListener('change', (e) => {
        currentLang = e.target.value;
        localStorage.setItem('lang', currentLang);
        applyLang(currentLang);
        const activePage = document.querySelector('.nav-item.active').dataset.page;
        if(activePage) renderContent(activePage);
    });

    const formatBytes = (bytes) => {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const formatDate = (unix) => {
        if (!unix || unix === 0) return '∞';
        return new Date(unix * 1000).toLocaleDateString(currentLang === 'fa' ? 'fa-IR' : 'en-US');
    };

    const fetchData = async () => {
        try {
            const [uRes, nRes] = await Promise.all([ fetch('/api/users'), fetch('/api/nodes') ]);
            usersData = await uRes.json() || [];
            nodesData = await nRes.json() || [];
        } catch (e) {
            console.error("API Error", e);
        }
    };

    window.copyText = (text, msg) => {
        navigator.clipboard.writeText(text).then(() => alert(msg)).catch(() => alert('Copy Failed!'));
    };

    window.openModal = (id) => {
        document.getElementById(id).classList.add('open');
    };

    window.closeModal = (id) => {
        document.getElementById(id).classList.remove('open');
    };

    window.generateMtprotoSecret = () => {
        const chars = '0123456789abcdef';
        let hex = '';
        for (let i = 0; i < 32; i++) {
            hex += chars[Math.floor(Math.random() * chars.length)];
        }
        document.getElementById('setting-mtproto-secret').value = hex;
    };

    window.openUserWizard = (id = null) => {
        if (id) {
            const u = usersData.find(x => x.id === id);
            document.getElementById('form-user-id').value = u.id;
            document.getElementById('form-user-name').value = u.name;
            document.getElementById('form-user-limit').value = u.data_limit ? Math.floor(u.data_limit / (1024**3)) : 0;
            
            let daysLeft = 0;
            if (u.expire_time > 0) {
                const diff = (u.expire_time * 1000) - Date.now();
                daysLeft = diff > 0 ? Math.ceil(diff / (1000 * 60 * 60 * 24)) : 0;
            }
            document.getElementById('form-user-days').value = daysLeft;
            
            document.getElementById('form-user-vless').checked = (u.vless_enabled !== 0);
            document.getElementById('form-user-trojan').checked = (u.trojan_enabled !== 0);
            document.getElementById('form-user-vmess').checked = (u.vmess_enabled !== 0);
            document.getElementById('form-user-remark').value = u.custom_remark || '';
            document.getElementById('user-modal-title').innerText = currentLang === 'fa' ? 'ویرایش کاربر' : 'Edit User';
        } else {
            document.getElementById('form-user-id').value = '';
            document.getElementById('form-user-name').value = '';
            document.getElementById('form-user-limit').value = '0';
            document.getElementById('form-user-days').value = '30';
            
            document.getElementById('form-user-vless').checked = true;
            document.getElementById('form-user-trojan').checked = true;
            document.getElementById('form-user-vmess').checked = true;
            document.getElementById('form-user-remark').value = '';
            document.getElementById('user-modal-title').innerText = currentLang === 'fa' ? 'افزودن کاربر' : 'Add User';
        }
        openModal('user-modal');
    };

    window.submitUserForm = async () => {
        const id = document.getElementById('form-user-id').value;
        const name = document.getElementById('form-user-name').value;
        const limit = parseFloat(document.getElementById('form-user-limit').value || 0);
        const days = parseInt(document.getElementById('form-user-days').value || 0);
        const useVless = document.getElementById('form-user-vless').checked;
        const useTrojan = document.getElementById('form-user-trojan').checked;
        const useVmess = document.getElementById('form-user-vmess').checked;
        const remark = document.getElementById('form-user-remark').value;

        if (!name) return alert('Name is required!');
        
        let exp = 0;
        if (days > 0) exp = Math.floor(Date.now() / 1000) + (days * 86400);

        const payload = { 
            name: name, data_limit: limit * (1024**3), expire_time: exp,
            vless_enabled: useVless, trojan_enabled: useTrojan, vmess_enabled: useVmess, custom_remark: remark
        };

        const btn = document.getElementById('btn-save-user');
        btn.disabled = true;

        try {
            if (id) {
                payload.id = id;
                await fetch('/api/users', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            } else {
                await fetch('/api/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            }
        } catch (e) { console.error(e); }

        btn.disabled = false;
        closeModal('user-modal');
        renderContent('users');
    };

    window.deleteUser = async (id) => {
        if(!confirm(currentLang === 'fa' ? 'آیا از حذف اطمینان دارید؟' : 'Are you sure?')) return;
        await fetch(`/api/users?id=${id}`, { method: 'DELETE' });
        renderContent('users');
    };

    window.toggleNodeFields = () => {
        const transport = document.getElementById('form-node-transport').value;
        const security = document.getElementById('form-node-security').value;
        
        const groupReality = document.getElementById('group-reality');
        const groupFingerprint = document.getElementById('group-fingerprint');
        const labelPath = document.getElementById('label-path');
        
        if (security === 'reality') groupReality.style.display = 'flex';
        else groupReality.style.display = 'none';

        if (security === 'none') groupFingerprint.style.display = 'none';
        else groupFingerprint.style.display = 'block';

        if (transport === 'grpc') labelPath.innerText = 'ServiceName';
        else labelPath.innerText = 'Path';
    };

    window.openNodeWizard = (id = null) => {
        if (id) {
            const n = nodesData.find(x => x.id === id);
            document.getElementById('form-node-id').value = n.id;
            document.getElementById('form-node-name').value = n.name;
            document.getElementById('form-node-addr').value = n.address;
            document.getElementById('form-node-type').value = n.type;
            document.getElementById('form-node-port').value = n.port || 443;
            document.getElementById('form-node-transport').value = n.transport || 'ws';
            document.getElementById('form-node-security').value = n.security || 'tls';
            document.getElementById('form-node-path').value = n.path || '/';
            document.getElementById('form-node-host').value = n.host || '';
            document.getElementById('form-node-pbk').value = n.pbk || '';
            document.getElementById('form-node-sid').value = n.sid || '';
            document.getElementById('form-node-fingerprint').value = n.fingerprint || 'chrome';
            document.getElementById('node-modal-title').innerText = currentLang === 'fa' ? 'ویرایش نود' : 'Edit Node';
        } else {
            document.getElementById('form-node-id').value = '';
            document.getElementById('form-node-name').value = '';
            document.getElementById('form-node-addr').value = '';
            document.getElementById('form-node-type').value = 'cloudflare';
            document.getElementById('form-node-port').value = 443;
            document.getElementById('form-node-transport').value = 'ws';
            document.getElementById('form-node-security').value = 'tls';
            document.getElementById('form-node-path').value = '/';
            document.getElementById('form-node-host').value = '';
            document.getElementById('form-node-pbk').value = '';
            document.getElementById('form-node-sid').value = '';
            document.getElementById('form-node-fingerprint').value = 'chrome';
            document.getElementById('node-modal-title').innerText = currentLang === 'fa' ? 'افزودن نود' : 'Add Node';
        }
        window.toggleNodeFields();
        openModal('node-modal');
    };

    window.submitNodeForm = async () => {
        const id = document.getElementById('form-node-id').value;
        const name = document.getElementById('form-node-name').value;
        const addr = document.getElementById('form-node-addr').value;
        const type = document.getElementById('form-node-type').value;
        const port = parseInt(document.getElementById('form-node-port').value || 443);
        const transport = document.getElementById('form-node-transport').value;
        const security = document.getElementById('form-node-security').value;
        const path = document.getElementById('form-node-path').value;
        const host = document.getElementById('form-node-host').value;
        const pbk = document.getElementById('form-node-pbk').value;
        const sid = document.getElementById('form-node-sid').value;
        const fingerprint = document.getElementById('form-node-fingerprint').value;

        if (!name || !addr) return alert('Required fields missing!');

        const payload = { 
            name: name, type: type, address: addr, port: port, transport: transport, security: security,
            path: path, host: host, pbk: pbk, sid: sid, fingerprint: fingerprint
        };
        
        const btn = document.getElementById('btn-save-node');
        btn.disabled = true;

        try {
            if (id) {
                await fetch('/api/nodes', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            } else {
                await fetch('/api/nodes', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            }
        } catch (e) { console.error(e); }

        btn.disabled = false;
        closeModal('node-modal');
        renderContent('nodes');
    };

    window.deleteNode = async (id) => {
        if(!confirm(currentLang === 'fa' ? 'آیا از حذف اطمینان دارید؟' : 'Are you sure?')) return;
        await fetch(`/api/nodes?id=${id}`, { method: 'DELETE' });
        renderContent('nodes');
    };

    window.saveSettings = () => {
        coreSettings.subDomain = document.getElementById('setting-domain').value;
        coreSettings.defaultCleanIp = document.getElementById('setting-cleanip').value;
        coreSettings.enableStats = document.getElementById('setting-stats').checked;
        coreSettings.mtprotoEnabled = document.getElementById('setting-mtproto-enable').checked;
        coreSettings.mtprotoPort = document.getElementById('setting-mtproto-port').value; 
        coreSettings.mtprotoSecret = document.getElementById('setting-mtproto-secret').value;
        coreSettings.mtprotoTag = document.getElementById('setting-mtproto-tag').value;
        
        localStorage.setItem('birusk_settings', JSON.stringify(coreSettings));
        const btn = document.getElementById('btn-save-settings');
        
        fetch('/api/settings', { 
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(coreSettings) 
        }).then(() => {
            btn.innerText = currentLang === 'fa' ? 'ذخیره شد ✔' : 'Saved ✔';
            setTimeout(() => { btn.innerText = currentLang === 'fa' ? 'ذخیره تنظیمات' : 'Save Settings'; }, 2000);
        });
    };

    // --- SVG Icons Helper ---
    const iconData = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>`;
    const iconUsers = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>`;
    const iconCopy = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;
    const iconEdit = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>`;
    const iconTrash = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`;

    const renderContent = async (page) => {
        contentArea.innerHTML = '<div style="text-align:center; padding: 40px; color: var(--text-muted);">Loading...</div>';
        
        if (page !== 'settings') await fetchData();

        let htmlContent = '';

        if (page === 'dashboard') {
            const totalTraffic = usersData.reduce((acc, user) => acc + (user.used_data || 0), 0);
            const maxTrafficCap = usersData.reduce((acc, user) => acc + (user.data_limit || 0), 0);
            const activeNodes = nodesData.filter(n => n.status === 'active').length;
            
            htmlContent = `
                <div class="grid-cards">
                    <div class="card" style="display: flex; align-items: center; gap: 20px; padding: 32px;">
                        <div style="background: var(--primary-light); color: var(--primary); width: 64px; height: 64px; border-radius: 16px; display: flex; justify-content: center; align-items: center;">
                            ${iconData}
                        </div>
                        <div>
                            <span class="card-title" style="margin-bottom: 4px;" data-i18n="table_usage">Data Usage</span>
                            <span class="card-value">${formatBytes(totalTraffic)}</span>
                        </div>
                    </div>
                    <div class="card" style="display: flex; align-items: center; gap: 20px; padding: 32px;">
                        <div style="background: rgba(16, 185, 129, 0.15); color: var(--success); width: 64px; height: 64px; border-radius: 16px; display: flex; justify-content: center; align-items: center;">
                            ${iconUsers}
                        </div>
                        <div>
                            <span class="card-title" style="margin-bottom: 4px;" data-i18n="card_total_users">Users</span>
                            <span class="card-value">${usersData.length}</span>
                        </div>
                    </div>
                </div>
            `;
        } 
        else if (page === 'users') {
            htmlContent = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
                    <div></div>
                    <button onclick="openUserWizard()" data-i18n="btn_add_user">Add User</button>
                </div>
                <div class="card" style="padding: 0; overflow: hidden;">
                    <table>
                        <thead>
                            <tr>
                                <th data-i18n="table_name">User</th>
                                <th data-i18n="table_usage">Usage</th>
                                <th style="text-align: right;" data-i18n="table_actions">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${usersData.map(u => {
                                const isExp = u.expire_time > 0 && (u.expire_time * 1000) < Date.now();
                                const statusClass = isExp ? 'status-expired' : 'status-active';
                                
                                const subBaseUrl = coreSettings.subDomain ? 
                                    (coreSettings.subDomain.startsWith('http') ? coreSettings.subDomain : 'https://' + coreSettings.subDomain) : 
                                    window.location.origin;
                                const subLink = `${subBaseUrl}/sub?id=${u.id}`;
                                
                                return `
                                <tr>
                                    <td data-label="User" style="font-weight: 500;">
                                        <div style="display: flex; align-items: center;">
                                            <span class="status-dot ${statusClass}"></span>
                                            ${u.name}
                                        </div>
                                    </td>
                                    <td data-label="Usage" style="color: var(--text-muted);">
                                        ${formatBytes(u.used_data)} / ${u.data_limit ? formatBytes(u.data_limit) : '∞'}
                                    </td>
                                    <td data-label="Actions" style="text-align: right;">
                                        <div style="display:flex; gap:8px; justify-content: flex-end;">
                                            <button class="btn-icon" onclick="copyText('${subLink}', 'Copied!')" title="Copy Link">${iconCopy}</button>
                                            <button class="btn-icon" onclick="openUserWizard('${u.id}')" title="Edit">${iconEdit}</button>
                                            <button class="btn-icon btn-danger" onclick="deleteUser('${u.id}')" title="Delete" style="border:none;">${iconTrash}</button>
                                        </div>
                                    </td>
                                </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }
        else if (page === 'nodes') {
            htmlContent = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
                    <div></div>
                    <button onclick="openNodeWizard()" data-i18n="btn_add_node">Add Node</button>
                </div>
                <div class="card" style="padding: 0; overflow: hidden;">
                    <table>
                        <thead>
                            <tr>
                                <th>Address</th>
                                <th>Specs</th>
                                <th style="text-align: right;" data-i18n="table_actions">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${nodesData.map(n => `
                                <tr>
                                    <td data-label="Address" style="font-weight: 500;">
                                        <div style="display: flex; align-items: center;">
                                            <span class="status-dot ${n.status === 'active' ? 'status-active' : 'status-offline'}"></span>
                                            ${n.address}:${n.port}
                                        </div>
                                    </td>
                                    <td data-label="Specs" style="color: var(--text-muted); font-size: 0.85rem;">
                                        ${n.transport.toUpperCase()} / ${n.security.toUpperCase()}
                                    </td>
                                    <td data-label="Actions" style="text-align: right;">
                                        <div style="display:flex; gap:8px; justify-content: flex-end;">
                                            <button class="btn-icon" onclick="copyText('${n.token}', 'Token Copied!')" title="Copy Token">${iconCopy}</button>
                                            <button class="btn-icon" onclick="openNodeWizard('${n.id}')" title="Edit">${iconEdit}</button>
                                            <button class="btn-icon btn-danger" onclick="deleteNode('${n.id}')" title="Delete" style="border:none;">${iconTrash}</button>
                                        </div>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }
        else if (page === 'settings') {
            htmlContent = `
                <div style="max-width: 700px; margin: 0 auto;">
                    <div class="card">
                        <div class="form-group">
                            <label>Subscription Domain</label>
                            <input type="text" id="setting-domain" placeholder="sub.domain.com" value="${coreSettings.subDomain || ''}">
                        </div>

                        <div class="form-group">
                            <label>Global Clean IP</label>
                            <input type="text" id="setting-cleanip" placeholder="e.g. 104.17.142.23" value="${coreSettings.defaultCleanIp || ''}">
                        </div>

                        <div class="switch-group">
                            <div>
                                <div style="font-weight: 600;">Telegram MTProto</div>
                                <div style="font-size: 0.8rem; color: var(--text-muted);">Enable internal proxy engine</div>
                            </div>
                            <label class="switch">
                                <input type="checkbox" id="setting-mtproto-enable" ${coreSettings.mtprotoEnabled ? 'checked' : ''}>
                                <span class="slider"></span>
                            </label>
                        </div>
                        
                        <div class="form-row" style="margin-top: 16px;">
                            <div class="form-group">
                                <label>MTProto Port</label>
                                <input type="number" id="setting-mtproto-port" value="${coreSettings.mtprotoPort || '8566'}">
                            </div>
                            <div class="form-group">
                                <label>Sponsor Tag</label>
                                <input type="text" id="setting-mtproto-tag" value="${coreSettings.mtprotoTag || ''}">
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label>MTProto Secret</label>
                            <div style="display:flex; gap:12px;">
                                <input type="text" id="setting-mtproto-secret" value="${coreSettings.mtprotoSecret || ''}" style="flex:1;">
                                <button onclick="generateMtprotoSecret()" class="btn-secondary">Generate</button>
                            </div>
                        </div>

                        <button id="btn-save-settings" onclick="saveSettings()" style="width:100%; margin-top: 24px; padding: 12px;" data-i18n="nav_settings">Save Settings</button>
                    </div>
                </div>
            `;
        }

        contentArea.innerHTML = htmlContent;
        applyLang(currentLang);
    };

    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');
            
            const page = item.dataset.page;
            const titleKey = 'nav_' + page;
            
            pageTitle.setAttribute('data-i18n', titleKey);
            if (translations[currentLang] && translations[currentLang][titleKey]) {
                pageTitle.textContent = translations[currentLang][titleKey];
            }
            
            renderContent(page);
            if (window.innerWidth <= 768) {
                toggleMenu();
            }
        });
    });

    applyLang(currentLang);
    renderContent('dashboard');
});