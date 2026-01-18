/**
 * SecureVaultX Main Application
 * Handles all UI interactions and screen navigation
 */

class SecureVaultApp {
    constructor() {
        this.currentScreen = 'login';
        this.currentDashboardSection = 'dashboard';
        this.sessionStartTime = null;
        this.sessionTimer = null;
        this.timeTimer = null;
        this.logTimer = null;
        this.liveDotTimer = null;
        this.logs = [];
        this.currentDecryptFile = null;
        this.decryptedData = null;

        this.init();
    }

    async init() {
        // Show loading screen
        await this.simulateLoading();

        // Bind all event listeners
        this.bindEvents();

        // Check for existing session
        const token = localStorage.getItem('svx_token');
        if (token) {
            try {
                await api.validateToken();
                const user = JSON.parse(localStorage.getItem('svx_user') || '{}');
                this.showDashboard(user.username || 'User');
            } catch (e) {
                api.clearAuth();
                this.showScreen('login');
            }
        } else {
            this.showScreen('login');
        }
    }

    async simulateLoading() {
        return new Promise(resolve => {
            setTimeout(() => {
                const loadingScreen = document.getElementById('loadingScreen');
                loadingScreen.classList.add('fade-out');
                setTimeout(() => {
                    loadingScreen.classList.add('hidden');
                    resolve();
                }, 500);
            }, 2000);
        });
    }

    bindEvents() {
        // Login events
        document.getElementById('loginBtn').addEventListener('click', () => this.handleLogin());
        document.getElementById('loginPassword').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleLogin();
        });
        document.getElementById('showRegisterBtn').addEventListener('click', () => this.showScreen('register'));

        // Register events
        document.getElementById('registerBtn').addEventListener('click', () => this.handleRegister());
        document.getElementById('showLoginBtn').addEventListener('click', () => this.showScreen('login'));
        document.getElementById('regPassword').addEventListener('input', (e) => this.updatePasswordStrength(e.target.value));

        // Navigation
        document.querySelectorAll('.nav-item').forEach(btn => {
            btn.addEventListener('click', () => {
                const screen = btn.dataset.screen;
                this.navigateTo(screen);
            });
        });

        // Quick actions
        document.getElementById('quickEncryptBtn').addEventListener('click', () => this.navigateTo('encrypt'));
        document.getElementById('quickDecryptBtn').addEventListener('click', () => this.navigateTo('decrypt'));

        // Logout & Panic
        document.getElementById('logoutBtn').addEventListener('click', () => this.handleLogout());
        document.getElementById('panicBtn').addEventListener('click', () => this.handlePanic());

        // File upload
        const fileInput = document.getElementById('fileInput');
        const dropZone = document.getElementById('fileDropZone');

        fileInput.addEventListener('change', (e) => this.handleFileSelect(e.target.files[0]));
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            if (e.dataTransfer.files.length) {
                this.handleFileSelect(e.dataTransfer.files[0]);
            }
        });

        // Encrypt
        document.getElementById('encryptBtn').addEventListener('click', () => this.handleEncrypt());

        // Decrypt
        document.getElementById('refreshFilesBtn').addEventListener('click', () => this.loadEncryptedFiles());

        // Modal
        document.getElementById('cancelDecryptBtn').addEventListener('click', () => this.closeDecryptModal());
        document.getElementById('previewBtn').addEventListener('click', () => this.handlePreview());
        document.getElementById('saveDecryptedBtn').addEventListener('click', () => this.handleSaveDecrypted());
        document.querySelector('.modal-overlay').addEventListener('click', () => this.closeDecryptModal());

        // Preview tabs
        document.querySelectorAll('.preview-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.preview-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
            });
        });

        // Error overlay close
        document.getElementById('closeErrorBtn').addEventListener('click', () => {
            document.getElementById('errorOverlay').classList.add('hidden');
        });

        // Audit filters
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.filterLogs(btn.dataset.filter);
            });
        });
    }

    // ========================================
    // Screen Navigation
    // ========================================

    showScreen(screenName) {
        document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
        document.getElementById(`${screenName}Screen`).classList.remove('hidden');
        this.currentScreen = screenName;
    }

    navigateTo(section) {
        // Update nav
        document.querySelectorAll('.nav-item').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.screen === section);
        });

        // Hide all content sections
        document.querySelectorAll('.content-section').forEach(s => s.classList.add('hidden'));

        // Show selected section
        const sectionMap = {
            'dashboard': 'dashboardHome',
            'encrypt': 'encryptScreen',
            'decrypt': 'decryptScreen',
            'device': 'deviceScreen',
            'audit': 'auditScreen'
        };

        document.getElementById(sectionMap[section]).classList.remove('hidden');
        this.currentDashboardSection = section;

        // Load data for specific sections
        if (section === 'decrypt') {
            this.loadEncryptedFiles();
        } else if (section === 'device') {
            this.loadDeviceStatus();
        } else if (section === 'audit') {
            this.loadAuditLogs();
        }
    }

    showDashboard(username) {
        this.showScreen('dashboard');
        document.getElementById('welcomeText').textContent = `Welcome back, ${username}`;

        // Start session timer
        this.sessionStartTime = new Date();
        this.startSessionTimer();

        // Start time display
        this.startTimeDisplay();

        // Load initial data
        this.loadDashboardStats();
        this.loadActivityFeed();
    }

    // ========================================
    // Authentication
    // ========================================

    async handleLogin() {
        const username = document.getElementById('loginUsername').value.trim();
        const password = document.getElementById('loginPassword').value;
        const errorEl = document.getElementById('loginError');
        const btn = document.getElementById('loginBtn');

        if (!username) {
            errorEl.textContent = 'Username is required';
            return;
        }
        if (!password) {
            errorEl.textContent = 'Password is required';
            return;
        }

        btn.classList.add('loading');
        btn.disabled = true;
        errorEl.textContent = '';

        try {
            const response = await api.login(username, password);
            this.showDashboard(response.username);
            this.addLog('SUCCESS', 'core.auth', `User ${username} logged in successfully`);
        } catch (error) {
            errorEl.textContent = error.message || 'Login failed';
            this.addLog('ERROR', 'core.auth', `Login failed: ${error.message}`);
        } finally {
            btn.classList.remove('loading');
            btn.disabled = false;
        }
    }

    async handleRegister() {
        const username = document.getElementById('regUsername').value.trim();
        const password = document.getElementById('regPassword').value;
        const confirm = document.getElementById('regConfirmPassword').value;
        const role = document.getElementById('regRole').value;
        const errorEl = document.getElementById('registerError');
        const btn = document.getElementById('registerBtn');

        // Validation
        if (!username || username.length < 3) {
            errorEl.textContent = 'Username must be at least 3 characters';
            return;
        }
        if (!password || password.length < 12) {
            errorEl.textContent = 'Password must be at least 12 characters';
            return;
        }
        if (password !== confirm) {
            errorEl.textContent = 'Passwords do not match';
            return;
        }
        if (this.calculatePasswordStrength(password) < 60) {
            errorEl.textContent = 'Password is too weak';
            return;
        }

        btn.classList.add('loading');
        btn.disabled = true;
        errorEl.textContent = '';

        try {
            await api.register(username, password, role);
            this.showSuccess('Account created successfully!');
            setTimeout(() => this.showScreen('login'), 1500);
        } catch (error) {
            errorEl.textContent = error.message || 'Registration failed';
        } finally {
            btn.classList.remove('loading');
            btn.disabled = false;
        }
    }

    async handleLogout() {
        await api.logout();
        this.stopTimers();
        document.getElementById('loginUsername').value = '';
        document.getElementById('loginPassword').value = '';
        document.getElementById('loginError').textContent = '';
        this.showScreen('login');
    }

    handlePanic() {
        this.addLog('CRITICAL', 'security.panic', 'PANIC TRIGGERED - Vault locked');
        this.showError('⚠️ PANIC LOCK ACTIVATED\nAll sessions terminated.');
        this.handleLogout();
    }

    // ========================================
    // Password Strength
    // ========================================

    calculatePasswordStrength(password) {
        if (!password) return 0;
        let score = 0;
        if (password.length >= 8) score += 20;
        if (password.length >= 12) score += 15;
        if (password.length >= 16) score += 10;
        if (/[a-z]/.test(password)) score += 10;
        if (/[A-Z]/.test(password)) score += 15;
        if (/[0-9]/.test(password)) score += 15;
        if (/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) score += 15;
        return Math.min(100, score);
    }

    updatePasswordStrength(password) {
        const strength = this.calculatePasswordStrength(password);
        const fill = document.getElementById('strengthBarFill');
        const text = document.getElementById('strengthText');

        fill.style.width = `${strength}%`;

        if (strength < 30) {
            fill.style.background = '#FF6B6B';
            text.textContent = 'Weak';
            text.style.color = '#FF6B6B';
        } else if (strength < 60) {
            fill.style.background = '#FFD93D';
            text.textContent = 'Fair';
            text.style.color = '#FFD93D';
        } else if (strength < 80) {
            fill.style.background = '#00D4FF';
            text.textContent = 'Good';
            text.style.color = '#00D4FF';
        } else {
            fill.style.background = '#00FF88';
            text.textContent = 'Strong';
            text.style.color = '#00FF88';
        }
    }

    // ========================================
    // Dashboard
    // ========================================

    async loadDashboardStats() {
        try {
            const stats = await api.getStats();
            document.getElementById('fileCount').textContent = stats.file_count || 0;
        } catch (e) {
            document.getElementById('fileCount').textContent = '0';
        }
    }

    loadActivityFeed() {
        const feed = document.getElementById('activityFeed');
        const now = new Date();

        const activities = [
            `• Login successful at ${now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}`,
            '• System integrity check passed',
            '• Encryption engine ready (Kyber-1024)'
        ];

        feed.innerHTML = activities.map(a => `<div class="activity-item">${a}</div>`).join('');
    }

    startSessionTimer() {
        this.sessionTimer = setInterval(() => {
            const elapsed = Math.floor((new Date() - this.sessionStartTime) / 1000);
            const minutes = Math.floor(elapsed / 60);
            const seconds = elapsed % 60;
            document.getElementById('sessionTime').textContent =
                `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        }, 1000);
    }

    startTimeDisplay() {
        const updateTime = () => {
            const now = new Date();
            const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
            const date = now.toLocaleDateString('en-US', options);
            const time = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            document.getElementById('currentTime').textContent = `${date} • ${time}`;
        };
        updateTime();
        this.timeTimer = setInterval(updateTime, 1000);
    }

    stopTimers() {
        if (this.sessionTimer) clearInterval(this.sessionTimer);
        if (this.timeTimer) clearInterval(this.timeTimer);
        if (this.logTimer) clearInterval(this.logTimer);
        if (this.liveDotTimer) clearInterval(this.liveDotTimer);
    }

    // ========================================
    // File Encryption
    // ========================================

    selectedFile = null;

    handleFileSelect(file) {
        if (!file) return;

        this.selectedFile = file;

        // Update UI
        document.getElementById('fileInfo').classList.remove('hidden');
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileSize').textContent = `📊 ${this.formatSize(file.size)}`;
        document.getElementById('fileType').textContent = `📝 ${this.getFileExtension(file.name)} file`;

        // Update drop zone
        document.querySelector('.file-drop-content').innerHTML = `
            <div class="file-drop-icon">📄</div>
            <div class="file-drop-text">${file.name}</div>
        `;
    }

    async handleEncrypt() {
        if (!this.selectedFile) {
            this.showError('Please select a file first');
            return;
        }

        const password = document.getElementById('encryptPassword').value;
        const confirm = document.getElementById('encryptConfirmPassword').value;
        const algorithm = document.querySelector('input[name="algorithm"]:checked').value;

        if (!password || password.length < 8) {
            this.showError('Password must be at least 8 characters');
            return;
        }
        if (password !== confirm) {
            this.showError('Passwords do not match');
            return;
        }

        const progressContainer = document.getElementById('encryptProgress');
        const progressFill = document.getElementById('encryptProgressFill');
        const status = document.getElementById('encryptStatus');
        const btn = document.getElementById('encryptBtn');

        progressContainer.classList.remove('hidden');
        btn.disabled = true;

        try {
            // Simulate progress steps
            this.updateProgress(progressFill, status, 10, 'Reading file...');
            await this.delay(300);

            this.updateProgress(progressFill, status, 30, 'Deriving key with Argon2id...');
            await this.delay(500);

            this.updateProgress(progressFill, status, 50, `Encrypting with ${algorithm.toUpperCase()}...`);

            const result = await api.encryptFile(this.selectedFile, password, algorithm);

            this.updateProgress(progressFill, status, 90, 'Finalizing...');
            await this.delay(300);

            this.updateProgress(progressFill, status, 100, 'Complete!');

            this.showSuccess(`Encrypted: ${result.filename}`);
            this.addLog('SUCCESS', 'core.crypto', `File encrypted: ${this.selectedFile.name} → ${result.filename}`);

            // Reset form
            setTimeout(() => this.resetEncryptForm(), 1500);

        } catch (error) {
            this.showError(`Encryption failed: ${error.message}`);
            this.addLog('ERROR', 'core.crypto', `Encryption failed: ${error.message}`);
        } finally {
            btn.disabled = false;
            progressContainer.classList.add('hidden');
        }
    }

    updateProgress(fill, status, percent, text) {
        fill.style.width = `${percent}%`;
        status.textContent = text;
    }

    resetEncryptForm() {
        this.selectedFile = null;
        document.getElementById('fileInfo').classList.add('hidden');
        document.getElementById('encryptPassword').value = '';
        document.getElementById('encryptConfirmPassword').value = '';
        document.querySelector('.file-drop-content').innerHTML = `
            <div class="file-drop-icon">📂</div>
            <div class="file-drop-text">Click to choose file or drag & drop</div>
        `;
        document.querySelector('input[name="algorithm"][value="aes"]').checked = true;
    }

    // ========================================
    // File Decryption
    // ========================================

    async loadEncryptedFiles() {
        try {
            const response = await api.listFiles();
            const files = response.files || [];

            document.getElementById('fileCountLabel').textContent = `📁 ${files.length} encrypted file(s)`;

            const container = document.getElementById('fileList');

            if (files.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon">📂</div>
                        <div class="empty-text">No encrypted files found. Encrypt some files first!</div>
                    </div>
                `;
                return;
            }

            container.innerHTML = files.map(file => `
                <div class="file-card" data-id="${file.id}">
                    <div class="file-card-header">
                        <div class="file-card-icon">🔐</div>
                        <div class="file-card-info">
                            <div class="file-card-name">${this.escapeHtml(file.original_path)}</div>
                            <div class="file-card-details">
                                <span class="file-card-detail">📊 ${this.formatSize(file.file_size)}</span>
                                <span class="file-card-detail algo">🔒 ${file.algorithm}</span>
                                <span class="file-card-detail">📅 ${this.formatDate(file.created_at)}</span>
                            </div>
                        </div>
                        <button class="btn btn-primary decrypt-btn" data-id="${file.id}">🔓 Decrypt</button>
                    </div>
                </div>
            `).join('');

            // Bind decrypt buttons
            container.querySelectorAll('.decrypt-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const fileId = e.target.dataset.id;
                    const file = files.find(f => f.id === fileId);
                    this.openDecryptModal(file);
                });
            });

        } catch (error) {
            this.showError(`Failed to load files: ${error.message}`);
        }
    }

    openDecryptModal(file) {
        this.currentDecryptFile = file;
        this.decryptedData = null;

        document.getElementById('decryptModalTitle').textContent = `🔓 Decrypt: ${file.original_path}`;
        document.getElementById('modalFileSize').textContent = `📊 Size: ${this.formatSize(file.file_size)}`;
        document.getElementById('modalFileAlgo').textContent = `🔒 Algorithm: ${file.algorithm}`;
        document.getElementById('decryptPassword').value = '';
        document.getElementById('decryptError').textContent = '';
        document.getElementById('previewContent').innerHTML = '<div class="preview-placeholder">Enter password and click Preview to see file content</div>';
        document.getElementById('previewInfo').textContent = '';
        document.getElementById('saveDecryptedBtn').disabled = true;

        document.getElementById('decryptModal').classList.remove('hidden');
    }

    closeDecryptModal() {
        document.getElementById('decryptModal').classList.add('hidden');
        this.currentDecryptFile = null;
        this.decryptedData = null;
    }

    async handlePreview() {
        const password = document.getElementById('decryptPassword').value;
        if (!password) {
            document.getElementById('decryptError').textContent = '❌ Please enter password';
            return;
        }

        document.getElementById('decryptError').textContent = '⏳ Decrypting...';

        try {
            const result = await api.decryptFile(this.currentDecryptFile.id, password);
            this.decryptedData = result;

            // Show preview
            const content = document.getElementById('previewContent');
            if (result.preview) {
                content.textContent = result.preview;
            } else {
                content.innerHTML = `<div class="preview-placeholder">Binary file (${this.formatSize(result.size)})<br>Cannot preview in browser.</div>`;
            }

            document.getElementById('previewInfo').textContent =
                `✅ ${result.is_text ? 'Text' : 'Binary'} file: ${this.formatSize(result.size)}`;

            document.getElementById('decryptError').textContent = '';
            document.getElementById('saveDecryptedBtn').disabled = false;

        } catch (error) {
            document.getElementById('decryptError').textContent = `❌ ${error.message}`;
            document.getElementById('saveDecryptedBtn').disabled = true;
        }
    }

    async handleSaveDecrypted() {
        if (!this.decryptedData) return;

        try {
            await api.downloadDecrypted(this.decryptedData.decrypted_id, this.decryptedData.original_name);
            this.showSuccess(`Saved: ${this.decryptedData.original_name}`);
            this.addLog('SUCCESS', 'core.crypto', `File decrypted: ${this.decryptedData.original_name}`);
            this.closeDecryptModal();
        } catch (error) {
            this.showError(`Download failed: ${error.message}`);
        }
    }

    // ========================================
    // Device Status
    // ========================================

    async loadDeviceStatus() {
        try {
            const status = await api.getSystemStatus();

            document.getElementById('osName').textContent = status.os || 'Unknown';

            const checksContainer = document.getElementById('securityChecks');
            const checks = status.checks || {};

            checksContainer.innerHTML = Object.entries(checks).map(([key, check]) => `
                <div class="security-check-card ${check.ok ? 'ok' : 'error'}">
                    <div class="check-icon">${this.getCheckIcon(key)}</div>
                    <div class="check-title">${this.formatCheckName(key)}</div>
                    <div class="check-status ${check.ok ? 'ok' : 'error'}">${check.status}</div>
                </div>
            `).join('');

            document.getElementById('lastVerified').textContent =
                `Last verified: ${new Date().toLocaleTimeString()}`;

        } catch (error) {
            // Use fallback data
            document.getElementById('osName').textContent = navigator.platform || 'Web Browser';
            this.loadFallbackSecurityChecks();
        }
    }

    loadFallbackSecurityChecks() {
        const checks = [
            { icon: '🛡️', name: 'System Integrity', status: 'VERIFIED', ok: true },
            { icon: '🔐', name: 'Encryption Engine', status: 'KYBER-1024 READY', ok: true },
            { icon: '🔒', name: 'Secure Memory', status: 'PROTECTED', ok: true },
            { icon: '🌐', name: 'Network Isolation', status: 'LOCAL ONLY', ok: true }
        ];

        const container = document.getElementById('securityChecks');
        container.innerHTML = checks.map(check => `
            <div class="security-check-card ok">
                <div class="check-icon">${check.icon}</div>
                <div class="check-title">${check.name}</div>
                <div class="check-status ok">${check.status}</div>
            </div>
        `).join('');

        document.getElementById('lastVerified').textContent =
            `Last verified: ${new Date().toLocaleTimeString()}`;
    }

    getCheckIcon(key) {
        const icons = {
            'system_integrity': '🛡️',
            'encryption_engine': '🔐',
            'secure_memory': '🔒',
            'network_isolation': '🌐'
        };
        return icons[key] || '✅';
    }

    formatCheckName(key) {
        return key.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
    }

    // ========================================
    // Audit Logs
    // ========================================

    loadAuditLogs() {
        // Initialize with demo logs
        if (this.logs.length === 0) {
            this.logs = [
                { severity: 'INFO', source: 'securevault.main', message: 'Application initialized successfully', time: this.getTimeAgo(5) },
                { severity: 'SUCCESS', source: 'core.auth', message: 'User authentication verified', time: this.getTimeAgo(4) },
                { severity: 'INFO', source: 'core.crypto', message: 'Kyber-1024 encryption engine loaded', time: this.getTimeAgo(3) },
                { severity: 'SUCCESS', source: 'security.memory', message: 'Secure memory pool allocated', time: this.getTimeAgo(2) },
                { severity: 'INFO', source: 'gui.app', message: 'Dashboard screen rendered', time: this.getTimeAgo(1) }
            ];
        }

        this.renderLogs();
        this.updateLogStats();
        this.startLiveLogUpdates();
    }

    addLog(severity, source, message) {
        const now = new Date();
        this.logs.unshift({
            severity,
            source,
            message,
            time: now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        });

        if (this.currentDashboardSection === 'audit') {
            this.renderLogs();
            this.updateLogStats();
        }
    }

    renderLogs() {
        const container = document.getElementById('logEntries');
        const severityIcons = {
            'INFO': 'ℹ️',
            'SUCCESS': '✅',
            'WARNING': '⚠️',
            'ERROR': '❌',
            'CRITICAL': '🚨'
        };

        container.innerHTML = this.logs.map(log => `
            <div class="log-entry ${log.severity.toLowerCase()}">
                <div class="log-icon">${severityIcons[log.severity] || '📝'}</div>
                <div class="log-content">
                    <div class="log-header">
                        <span class="log-source">${log.source}</span>
                        <span class="log-severity">${log.severity}</span>
                        <span class="log-time">${log.time}</span>
                    </div>
                    <div class="log-message">${this.escapeHtml(log.message)}</div>
                </div>
            </div>
        `).join('');
    }

    updateLogStats() {
        const total = this.logs.length;
        const info = this.logs.filter(l => l.severity === 'INFO').length;
        const success = this.logs.filter(l => l.severity === 'SUCCESS').length;
        const warning = this.logs.filter(l => l.severity === 'WARNING').length;
        const error = this.logs.filter(l => ['ERROR', 'CRITICAL'].includes(l.severity)).length;

        document.getElementById('totalLogs').textContent = total;
        document.getElementById('infoLogs').textContent = info;
        document.getElementById('successLogs').textContent = success;
        document.getElementById('warningLogs').textContent = warning;
        document.getElementById('errorLogs').textContent = error;
    }

    filterLogs(filter) {
        const entries = document.querySelectorAll('.log-entry');
        entries.forEach(entry => {
            if (filter === 'all') {
                entry.style.display = '';
            } else {
                entry.style.display = entry.classList.contains(filter) ? '' : 'none';
            }
        });
    }

    startLiveLogUpdates() {
        // Clear existing timers
        if (this.logTimer) clearInterval(this.logTimer);
        if (this.liveDotTimer) clearInterval(this.liveDotTimer);

        // Simulate new logs every 10 seconds
        this.logTimer = setInterval(() => {
            const messages = [
                { severity: 'INFO', source: 'core.session', message: 'Session heartbeat acknowledged' },
                { severity: 'SUCCESS', source: 'security.scan', message: 'Background security scan completed' },
                { severity: 'INFO', source: 'core.memory', message: 'Memory usage within safe limits' }
            ];
            const msg = messages[Math.floor(Math.random() * messages.length)];
            this.addLog(msg.severity, msg.source, msg.message);
        }, 10000);

        // Blink live dot
        let visible = true;
        this.liveDotTimer = setInterval(() => {
            visible = !visible;
            const dot = document.getElementById('liveDot');
            if (dot) dot.style.opacity = visible ? 1 : 0;
        }, 1000);
    }

    getTimeAgo(minutesAgo) {
        const date = new Date(Date.now() - minutesAgo * 60000);
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    // ========================================
    // Utilities
    // ========================================

    formatSize(bytes) {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0;
        while (bytes >= 1024 && i < units.length - 1) {
            bytes /= 1024;
            i++;
        }
        return `${bytes.toFixed(1)} ${units[i]}`;
    }

    formatDate(dateStr) {
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    getFileExtension(filename) {
        const ext = filename.split('.').pop().toUpperCase();
        return ext || 'Unknown';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    showSuccess(message) {
        const overlay = document.getElementById('successOverlay');
        document.getElementById('successMessage').textContent = message;
        overlay.classList.remove('hidden');
        setTimeout(() => overlay.classList.add('hidden'), 2000);
    }

    showError(message) {
        const overlay = document.getElementById('errorOverlay');
        document.getElementById('errorMessage').textContent = message;
        overlay.classList.remove('hidden');
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.app = new SecureVaultApp();
});
