/**
 * SecureVaultX API Client
 * Handles all communication with the backend
 */

class SecureVaultAPI {
    constructor() {
        // HARDCODED CORRECT BACKEND URL
        this.baseUrl = 'https://securevault-abiu.onrender.com/api';
        this.token = localStorage.getItem('svx_token');
        console.log("API Initialized with: " + this.baseUrl);
    }

    /**
     * Set the API base URL
     */
    setBaseUrl(url) {
        this.baseUrl = url;
    }

    /**
     * Get authorization headers
     */
    getHeaders() {
        const headers = {
            'Content-Type': 'application/json'
        };
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }
        return headers;
    }

    /**
     * Make an API request
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            ...options,
            headers: {
                ...this.getHeaders(),
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                throw new APIError(data.error || 'Request failed', response.status);
            }

            return data;
        } catch (error) {
            if (error instanceof APIError) {
                throw error;
            }
            throw new APIError('Network error. Please check your connection.', 0);
        }
    }

    /**
     * Set authentication token
     */
    setToken(token) {
        this.token = token;
        if (token) {
            localStorage.setItem('svx_token', token);
        } else {
            localStorage.removeItem('svx_token');
        }
    }

    /**
     * Clear authentication
     */
    clearAuth() {
        this.token = null;
        localStorage.removeItem('svx_token');
        localStorage.removeItem('svx_user');
    }

    // ========================================
    // Authentication Endpoints
    // ========================================

    async register(username, password, role = 'USER') {
        return this.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, password, role })
        });
    }

    async login(username, password) {
        const data = await this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        if (data.token) {
            this.setToken(data.token);
            localStorage.setItem('svx_user', JSON.stringify({
                id: data.user_id,
                username: data.username,
                role: data.role
            }));
        }

        return data;
    }

    async logout() {
        try {
            await this.request('/auth/logout', { method: 'POST' });
        } catch (e) {
            // Ignore logout errors
        }
        this.clearAuth();
    }

    async validateToken() {
        return this.request('/auth/validate');
    }

    // ========================================
    // File Encryption Endpoints
    // ========================================

    async encryptFile(file, password, algorithm = 'aes') {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('password', password);
        formData.append('algorithm', algorithm);

        const response = await fetch(`${this.baseUrl}/encrypt`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.token}`
            },
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new APIError(data.error || 'Encryption failed', response.status);
        }

        return data;
    }

    async decryptFile(fileId, password) {
        return this.request('/decrypt', {
            method: 'POST',
            body: JSON.stringify({ file_id: fileId, password })
        });
    }

    async downloadDecrypted(decryptedId, filename) {
        const url = `${this.baseUrl}/download/${decryptedId}?filename=${encodeURIComponent(filename)}`;

        const response = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${this.token}`
            }
        });

        if (!response.ok) {
            throw new APIError('Download failed', response.status);
        }

        const blob = await response.blob();

        // Trigger download
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(downloadUrl);
    }

    async listFiles() {
        return this.request('/files');
    }

    async deleteFile(fileId) {
        return this.request(`/files/${fileId}`, { method: 'DELETE' });
    }

    // ========================================
    // Dashboard Endpoints
    // ========================================

    async getStats() {
        return this.request('/stats');
    }

    async getSystemStatus() {
        return this.request('/system/status');
    }

    async healthCheck() {
        return this.request('/health');
    }
}

/**
 * Custom API Error class
 */
class APIError extends Error {
    constructor(message, status) {
        super(message);
        this.name = 'APIError';
        this.status = status;
    }
}

// Create global API instance
window.api = new SecureVaultAPI();
