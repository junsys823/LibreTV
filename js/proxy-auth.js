/**
 * 代理请求鉴权模块
 * 为代理请求添加基于 PASSWORD 的鉴权机制
 */

// 从全局配置获取密码哈希（如果存在）
let cachedPasswordHash = null;

function isValidPasswordHash(hash) {
    return typeof hash === 'string' && /^[a-f0-9]{64}$/i.test(hash);
}

/**
 * 获取当前会话的密码哈希
 */
async function getPasswordHash() {
    const envPasswordHash = window.__ENV__?.PASSWORD;
    if (isValidPasswordHash(envPasswordHash)) {
        const passwordStateKey = window.PASSWORD_CONFIG?.localStorageKey || 'passwordVerified';
        const storedHash = localStorage.getItem('proxyAuthHash');
        const passwordState = localStorage.getItem(passwordStateKey);

        if (storedHash && storedHash !== envPasswordHash) {
            localStorage.removeItem('proxyAuthHash');
        }

        if (passwordState) {
            try {
                const parsedState = JSON.parse(passwordState);
                if (parsedState.passwordHash && parsedState.passwordHash !== envPasswordHash) {
                    localStorage.removeItem(passwordStateKey);
                }
            } catch (error) {
                const legacyPasswordHash = localStorage.getItem('passwordHash');
                if (legacyPasswordHash && legacyPasswordHash !== envPasswordHash) {
                    localStorage.removeItem(passwordStateKey);
                    localStorage.removeItem('passwordHash');
                }
            }
        }

        cachedPasswordHash = envPasswordHash;
        localStorage.setItem('proxyAuthHash', envPasswordHash);
        return envPasswordHash;
    }

    if (isValidPasswordHash(cachedPasswordHash)) {
        return cachedPasswordHash;
    }
    
    // 1. 优先从已存储的代理鉴权哈希获取
    const storedHash = localStorage.getItem('proxyAuthHash');
    if (isValidPasswordHash(storedHash)) {
        cachedPasswordHash = storedHash;
        return storedHash;
    } else if (storedHash) {
        localStorage.removeItem('proxyAuthHash');
    }
    
    // 2. 尝试从密码验证状态获取（password.js 验证后存储的哈希）
    const passwordStateKey = window.PASSWORD_CONFIG?.localStorageKey || 'passwordVerified';
    const passwordState = localStorage.getItem(passwordStateKey);
    if (passwordState) {
        try {
            const parsedState = JSON.parse(passwordState);
            const storedPasswordHash = parsedState.passwordHash;
            const isFresh = parsedState.timestamp &&
                (!window.PASSWORD_CONFIG?.verificationTTL ||
                    Date.now() - parsedState.timestamp < window.PASSWORD_CONFIG.verificationTTL);

            if (parsedState.verified && isValidPasswordHash(storedPasswordHash) && isFresh) {
                localStorage.setItem('proxyAuthHash', storedPasswordHash);
                cachedPasswordHash = storedPasswordHash;
                return storedPasswordHash;
            }
        } catch (error) {
            // 兼容旧版存储格式：passwordVerified=true + passwordHash=...
            const storedPasswordHash = localStorage.getItem('passwordHash');
            if (passwordState === 'true' && isValidPasswordHash(storedPasswordHash)) {
                localStorage.setItem('proxyAuthHash', storedPasswordHash);
                cachedPasswordHash = storedPasswordHash;
                return storedPasswordHash;
            }
        }
    }
    
    // 3. 尝试从用户输入的密码生成哈希
    const userPassword = localStorage.getItem('userPassword');
    if (userPassword) {
        try {
            // 动态导入 sha256 函数
            const { sha256 } = await import('./sha256.js');
            const hash = await sha256(userPassword);
            if (isValidPasswordHash(hash)) {
                localStorage.setItem('proxyAuthHash', hash);
                cachedPasswordHash = hash;
                return hash;
            }
        } catch (error) {
            console.error('生成密码哈希失败:', error);
        }
    }
    
    return null;
}

/**
 * 为代理请求URL添加鉴权参数
 */
async function addAuthToProxyUrl(url) {
    try {
        const hash = await getPasswordHash();
        if (!hash) {
            console.warn('无法获取密码哈希，代理请求可能失败');
            return url;
        }
        
        // 添加时间戳防止重放攻击
        const timestamp = Date.now();
        
        // 检查URL是否已包含查询参数
        const separator = url.includes('?') ? '&' : '?';
        
        return `${url}${separator}auth=${encodeURIComponent(hash)}&t=${timestamp}`;
    } catch (error) {
        console.error('添加代理鉴权失败:', error);
        return url;
    }
}

/**
 * 验证代理请求的鉴权
 */
function validateProxyAuth(authHash, serverPasswordHash, timestamp) {
    if (!authHash || !serverPasswordHash) {
        return false;
    }
    
    // 验证哈希是否匹配
    if (authHash !== serverPasswordHash) {
        return false;
    }
    
    // 验证时间戳（10分钟有效期）
    const now = Date.now();
    const maxAge = 10 * 60 * 1000; // 10分钟
    
    if (timestamp && (now - parseInt(timestamp)) > maxAge) {
        console.warn('代理请求时间戳过期');
        return false;
    }
    
    return true;
}

/**
 * 清除缓存的鉴权信息
 */
function clearAuthCache() {
    cachedPasswordHash = null;
    localStorage.removeItem('proxyAuthHash');
}

// 监听密码变化，清除缓存
window.addEventListener('storage', (e) => {
    if (e.key === 'userPassword' || (window.PASSWORD_CONFIG && e.key === window.PASSWORD_CONFIG.localStorageKey)) {
        clearAuthCache();
    }
});

// 导出函数
window.ProxyAuth = {
    addAuthToProxyUrl,
    validateProxyAuth,
    clearAuthCache,
    getPasswordHash
};
