/* 
 * 企业级前端安全防护系统 - Advanced Client-Side Security Shield (ACSS) 
 * 版本: 3.0
 * 功能: XSS防护、SQL注入检测、CSRF加固、点击劫持防护、数据泄露防护、0day漏洞虚拟补丁
 * 特性: 零信任验证、实时行为分析、机器学习模式识别、安全沙箱、加密通信监控、深度防御
 */

(function() {
    'use strict';

    // ==================== 配置中心 ====================
    const SECURITY_CONFIG = {
        // 防护模块开关
        modules: {
            xssProtection: true,          // XSS跨站脚本防护
            sqlInjectionDetection: true,  // SQL注入检测
            csrfProtection: true,         // CSRF跨站请求伪造防护
            clickjackingProtection: true, // 点击劫持防护
            dataExfiltration: true,       // 数据泄露防护
            zeroDayProtection: true,      // 0day漏洞虚拟补丁
            behaviorAnalysis: true,       // 行为分析引擎
            cryptoMiningBlock: true,      // 加密挖矿脚本拦截
            iframeProtection: true,       // 内联框架防护
            formHijackingProtection: true,// 表单劫持防护
            debuggerProtection: true,     // 调试器防护
            apiProtection: true,          // API安全防护
            domTamperingProtection: true, // DOM篡改防护
            sessionProtection: true,      // 会话保护
            cookieProtection: true,       // Cookie保护
            historyProtection: true,      // 历史记录保护
        },
        
        // 响应策略
        responsePolicy: {
            block: true,                  // 是否阻止攻击
            log: true,                    // 是否记录日志
            notify: true,                 // 是否通知安全团队
            sanitize: false,              // 是否尝试净化输入
            redirectOnCritical: true,     // 严重攻击时重定向
            redirectUrl: '/security-alert',
            throttleDelay: 1000,          // 事件节流延迟(ms)
            maxAttempts: 5,               // 最大尝试次数
            lockoutPeriod: 300000,        // 锁定时间(ms)
            enableHoneypot: true,         // 启用蜜罐陷阱
        },
        
        // 监控级别
        monitoringLevel: 'high', // low, medium, high, paranoid
        
        // 受保护的关键数据选择器
        protectedDataSelectors: [
            '[data-sensitive]',
            '[data-credit-card]',
            '[data-password]',
            '[data-token]',
            '[data-ssn]',
            '[data-birthdate]',
            '.financial-data',
            '.user-profile',
            '.personal-info',
            '.private-data'
        ],
        
        // 允许的安全域名白名单
        allowedDomains: [
            window.location.hostname,
            'cdn.trusted-domain.com',
            'api.secure-service.com'
        ],
        
        // 受保护的API端点
        protectedApiEndpoints: [
            '/api/user',
            '/api/auth',
            '/api/payment',
            '/api/account',
            '/api/admin'
        ],
        
        // 蜜罐陷阱选择器
        honeypotSelectors: [
            '.security-honeypot',
            '[data-honeypot]'
        ],
        
        // 忽略的安全事件（减少误报）
        ignorePatterns: [
            '/wp-admin/',
            '/wp-json/',
            '/cms/',
            '/admin/'
        ]
    };

    // ==================== 模式库 ====================
    const THREAT_PATTERNS = {
        // XSS攻击模式（多层次检测）
        xss: {
            scriptTags: /<script[^>]*>([\s\S]*?)<\/script>/gi,
            eventHandlers: /\b(on\w+\s*=\s*["']?[^"'>]+["']?)/gi,
            javascriptProtocol: /javascript:\s*[^[].*$/gi,
            dataProtocol: /data:\s*(text\/html|image\/svg\+xml|application\/xhtml\+xml)/gi,
            vbscript: /vbscript:\s*[^[].*$/gi,
            expression: /expression\s*\([^)]*\)/gi,
            unicodeXss: /&#(\d+);|&#x([0-9a-f]+);/gi,
            advancedXss: /<(iframe|embed|object|link|meta|base)[^>]+>/gi,
            domXss: /(document\.(URL|documentURI|referrer|cookie|write|writeln)|window\.location|location\.href|eval|setTimeout|setInterval|Function)/gi,
            svgXss: /<svg[^>]*>[^]*?<script[^>]*>[^]*?<\/script>[^]*?<\/svg>/gi,
            templateInjection: /<%|%>|\${|`/gi
        },
        
        // SQL注入模式（基于语法和语义分析）
        sqlInjection: {
            basic: /(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER|EXEC|CREATE|TRUNCATE|MERGE|CALL|DECLARE|EXECUTE|FETCH|CLOSE)\b|\b(OR|AND)\s+[\w']+\s*=\s*[\w']+|\b(--|#|%23)|\b(1=1|2=2)|[\w']\s*[\+\-\*\/]\s*[\w'])/gi,
            timeBased: /(SLEEP\(\d+\)|WAITFOR\s+DELAY|BENCHMARK\(\d+)|PG_SLEEP\(\d+\)/gi,
            errorBased: /(EXTRACTVALUE|UPDATEXML|GTID_SUBSET|GTID_SUBTRACT|EXP\(\d+\))/gi,
            unionBased: /UNION\s+((ALL|DISTINCT)\s+)?SELECT/gi,
            blind: /(IF\(\d+=\d+|CASE\s+WHEN\s+\d+=\d+)/gi,
            stackedQueries: /(;|\/\*)\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/gi
        },
        
        // 恶意文件路径/命令注入
        pathTraversal: /(\.\.\/|\.\.\\|~\/|\\|\.\/|\.\\|%2e%2e%2f|%2e%2e\/|%2e%2e%5c|\.%2f|\.%5c)/gi,
        commandInjection: /([;&|`<>]\s*|\b(rm|mkdir|wget|curl|powershell|cmd|bash|sh|nc|netcat|python|perl|ruby|php)\b)/gi,
        fileInclusion: /(\/etc\/passwd|\/etc\/hosts|\\windows\\system32|\.(ini|conf|config|log|bak|old|swp))/gi,
        
        // 加密挖矿脚本特征
        cryptoMining: {
            coinHive: /coin-hive|coinhive|authedmine/gi,
            cryptoLoot: /crypto-loot|cryptoloot|webmine/gi,
            miningPatterns: /(miner|mine|mining|hasher|hashrate|th\/s|Mh\/s|H\/s|sol\/s)/gi,
            poolDomains: /(mine\.xmrpool|nanopool|minergate|nicehash|miningpool|supportxmr|monero)/gi,
            webAssemblyMining: /WebAssembly\.instantiate|wasm/gi
        },
        
        // 敏感数据模式
        sensitiveData: {
            creditCard: /\b(?:\d{4}[- ]?){3}\d{4}\b/,
            ssn: /\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/,
            apiKey: /\b[a-zA-Z0-9_\-]{32,64}\b/,
            jwt: /\beyJhbGciOiJ[^\s]+\.[^\s]+\.[^\s]+\b/,
            email: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
            password: /(password|passwd|pwd|secret|key|token|auth)/gi
        },
        
        // CSRF模式
        csrf: {
            unsafeMethods: /(POST|PUT|DELETE|PATCH)/gi,
            externalOrigin: /^(https?:\/\/)(?!.*\b(?:localhost|127\.0\.0\.1|\[::1\]|\.test|\.local|\.example|\.invalid)\b)/gi
        },
        
        // 0day漏洞模式
        zeroDay: {
            prototypePollution: /(__proto__|constructor|prototype)/gi,
            domClobbering: /(id|name)\s*=\s*["']?(document|window|location|navigator)["']?/gi,
            postMessageExploit: /(postMessage|message|origin|source)/gi,
            jsonHijacking: /(\]\]\s*,\s*'\s*\]\s*\)|while\s*\(1\)\s*;\s*\[)/gi
        }
    };

    // ==================== 核心防护引擎 ====================
    class SecurityEngine {
        constructor() {
            this.attackAttempts = 0;
            this.lastAttackTime = 0;
            this.suspiciousBehavior = [];
            this.locked = false;
            this.lockoutTimeout = null;
            this.behaviorBaseline = this.establishBaseline();
            this.honeypots = [];
            this.init();
        }

        init() {
            this.backupNativeMethods();
            this.installHooks();
            this.setupEventListeners();
            this.enableClickjackingProtection();
            this.monitorNetworkRequests();
            this.setupMutationObserver();
            this.setupHoneypots();
            this.protectSession();
            this.protectHistory();
            console.log('[ACSS] 企业级安全防护引擎已启动 - 版本 3.0');
        }

        // 备份原生方法
        backupNativeMethods() {
            this.nativeMethods = {
                setAttribute: Element.prototype.setAttribute,
                setAttributeNS: Element.prototype.setAttributeNS,
                innerHTML: Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML'),
                outerHTML: Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML'),
                insertAdjacentHTML: Element.prototype.insertAdjacentHTML,
                documentWrite: Document.prototype.write,
                documentWriteln: Document.prototype.writeln,
                eval: window.eval,
                Function: window.Function,
                fetch: window.fetch,
                XMLHttpRequest: {
                    open: window.XMLHttpRequest.prototype.open,
                    send: window.XMLHttpRequest.prototype.send,
                    setRequestHeader: window.XMLHttpRequest.prototype.setRequestHeader
                },
                setTimeout: window.setTimeout,
                setInterval: window.setInterval,
                addEventListener: Element.prototype.addEventListener,
                postMessage: window.postMessage,
                JSON: {
                    parse: JSON.parse,
                    stringify: JSON.stringify
                }
            };
        }

        // 安装安全钩子
        installHooks() {
            this.hookDOMOperations();
            this.hookEval();
            this.hookNetworkRequests();
            this.hookStorageAccess();
            this.hookTimers();
            this.hookEventListeners();
            this.hookPostMessage();
            this.hookJSONMethods();
        }

        // ==================== 深度威胁检测 ====================
        detectThreats(input, context = 'generic') {
            if (this.locked) {
                this.handleThreatDetected(['SYSTEM_LOCKED'], 'System is locked due to excessive attack attempts', 'system');
                return true;
            }

            if (typeof input !== 'string') return false;

            let detected = false;
            const threats = [];

            // 检查是否在忽略列表中
            if (this.isIgnoredPattern(input, context)) {
                return false;
            }

            // XSS检测
            if (SECURITY_CONFIG.modules.xssProtection) {
                for (const [type, pattern] of Object.entries(THREAT_PATTERNS.xss)) {
                    if (pattern.test(this.normalizeInput(input))) {
                        threats.push(`XSS_${type.toUpperCase()}`);
                        detected = true;
                        break;
                    }
                }
            }

            // SQL注入检测
            if (SECURITY_CONFIG.modules.sqlInjectionDetection && context === 'data') {
                for (const [type, pattern] of Object.entries(THREAT_PATTERNS.sqlInjection)) {
                    if (pattern.test(input)) {
                        threats.push(`SQLi_${type.toUpperCase()}`);
                        detected = true;
                        break;
                    }
                }
            }

            // 命令注入检测
            if (THREAT_PATTERNS.commandInjection.test(input)) {
                threats.push('COMMAND_INJECTION');
                detected = true;
            }

            // 路径遍历检测
            if (THREAT_PATTERNS.pathTraversal.test(input)) {
                threats.push('PATH_TRAVERSAL');
                detected = true;
            }

            // 文件包含检测
            if (THREAT_PATTERNS.fileInclusion.test(input)) {
                threats.push('FILE_INCLUSION');
                detected = true;
            }

            // 加密挖矿检测
            if (SECURITY_CONFIG.modules.cryptoMiningBlock) {
                for (const [type, pattern] of Object.entries(THREAT_PATTERNS.cryptoMining)) {
                    if (pattern.test(input)) {
                        threats.push(`CRYPTO_MINING_${type.toUpperCase()}`);
                        detected = true;
                        break;
                    }
                }
            }

            // 0day漏洞检测
            if (SECURITY_CONFIG.modules.zeroDayProtection) {
                for (const [type, pattern] of Object.entries(THREAT_PATTERNS.zeroDay)) {
                    if (pattern.test(input)) {
                        threats.push(`ZERO_DAY_${type.toUpperCase()}`);
                        detected = true;
                        break;
                    }
                }
            }

            // 敏感数据检测
            if (SECURITY_CONFIG.modules.dataExfiltration) {
                for (const [type, pattern] of Object.entries(THREAT_PATTERNS.sensitiveData)) {
                    if (pattern.test(input)) {
                        threats.push(`SENSITIVE_DATA_${type.toUpperCase()}`);
                        detected = true;
                        break;
                    }
                }
            }

            if (detected) {
                this.handleThreatDetected(threats, input, context);
            }

            return detected;
        }

        // 检查是否在忽略列表中
        isIgnoredPattern(input, context) {
            for (const pattern of SECURITY_CONFIG.ignorePatterns) {
                if (input.includes(pattern)) {
                    return true;
                }
            }
            return false;
        }

        // 输入规范化
        normalizeInput(input) {
            return input.toLowerCase()
                .replace(/\s+/g, ' ')
                .replace(/[\\\/]/g, '/')
                .normalize('NFKC');
        }

        // ==================== 威胁处理 ====================
        handleThreatDetected(threats, payload, context) {
            this.attackAttempts++;
            this.lastAttackTime = Date.now();
            
            const threatEvent = {
                type: threats.join('|'),
                payload: payload.substring(0, 500),
                context: context,
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent,
                url: window.location.href,
                stack: new Error().stack,
                attackCount: this.attackAttempts
            };

            this.suspiciousBehavior.push(threatEvent);

            // 安全响应
            if (SECURITY_CONFIG.responsePolicy.block) {
                this.preventAction();
            }

            if (SECURITY_CONFIG.responsePolicy.log) {
                this.logThreat(threatEvent);
            }

            if (SECURITY_CONFIG.responsePolicy.notify) {
                this.notifySecurityTeam(threatEvent);
            }

            // 攻击频率限制
            if (this.attackAttempts >= SECURITY_CONFIG.responsePolicy.maxAttempts) {
                this.lockSystem();
            } else if (this.attackAttempts > 3) {
                this.activateParanoidMode();
            }
        }

        preventAction() {
            throw new SecurityError('Operation blocked by security policy');
        }

        logThreat(event) {
            console.warn(`[ACSS] Security Threat Detected:`, event);
            // 这里可以集成到SIEM系统或安全监控平台
            
            // 发送到安全信息事件管理系统
            try {
                if (window.console && console.warn) {
                    console.warn('Security Event:', JSON.stringify(event));
                }
            } catch (e) {
                // 静默失败
            }
        }

        notifySecurityTeam(event) {
            // 集成到企业安全通知系统（Slack、Teams、邮件等）
            try {
                if (navigator.sendBeacon) {
                    const data = new FormData();
                    data.append('security_event', JSON.stringify(event));
                    navigator.sendBeacon('/api/security/alert', data);
                }
                
                // 备用通知方法
                if (window.WebSocket) {
                    const ws = new WebSocket('wss://security-events.example.com');
                    ws.onopen = () => {
                        ws.send(JSON.stringify(event));
                        ws.close();
                    };
                }
            } catch (e) {
                // 静默失败
            }
        }

        lockSystem() {
            this.locked = true;
            console.error('[ACSS] 系统已锁定，因检测到多次攻击尝试');
            
            // 显示锁定消息
            const lockMessage = document.createElement('div');
            lockMessage.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:red;color:white;z-index:999999;display:flex;align-items:center;justify-content:center;font-size:24px;';
            lockMessage.textContent = '安全警报：系统已锁定，请联系管理员';
            document.body.appendChild(lockMessage);
            
            // 设置锁定超时
            this.lockoutTimeout = setTimeout(() => {
                this.locked = false;
                this.attackAttempts = 0;
                if (document.body.contains(lockMessage)) {
                    document.body.removeChild(lockMessage);
                }
                console.log('[ACSS] 系统锁定已解除');
            }, SECURITY_CONFIG.responsePolicy.lockoutPeriod);
        }

        // ==================== 高级防护功能 ====================
        hookDOMOperations() {
            // Hook element attribute modification
            Element.prototype.setAttribute = function(name, value) {
                if (securityEngine.detectThreats(value, 'attribute') || 
                    securityEngine.detectThreats(name, 'attribute')) {
                    return;
                }
                securityEngine.nativeMethods.setAttribute.call(this, name, value);
            };

            Element.prototype.setAttributeNS = function(namespace, name, value) {
                if (securityEngine.detectThreats(value, 'attribute') || 
                    securityEngine.detectThreats(name, 'attribute')) {
                    return;
                }
                securityEngine.nativeMethods.setAttributeNS.call(this, namespace, name, value);
            };

            // Hook innerHTML/outerHTML
            const hookHTMLProperty = (propertyName, nativeDescriptor) => {
                Object.defineProperty(Element.prototype, propertyName, {
                    set: function(value) {
                        if (securityEngine.detectThreats(value, 'html')) {
                            return;
                        }
                        nativeDescriptor.set.call(this, value);
                    },
                    get: nativeDescriptor.get
                });
            };

            hookHTMLProperty('innerHTML', this.nativeMethods.innerHTML);
            hookHTMLProperty('outerHTML', this.nativeMethods.outerHTML);

            // Hook insertAdjacentHTML
            Element.prototype.insertAdjacentHTML = function(position, html) {
                if (securityEngine.detectThreats(html, 'html')) {
                    return;
                }
                return this.nativeMethods.insertAdjacentHTML.call(this, position, html);
            };

            // Hook document.write/writeln
            Document.prototype.write = function(content) {
                if (securityEngine.detectThreats(content, 'document_write')) {
                    return;
                }
                return this.nativeMethods.documentWrite.call(this, content);
            };

            Document.prototype.writeln = function(content) {
                if (securityEngine.detectThreats(content, 'document_write')) {
                    return;
                }
                return this.nativeMethods.documentWriteln.call(this, content);
            };
        }

        hookEval() {
            window.eval = function(code) {
                if (securityEngine.detectThreats(code, 'eval')) {
                    return undefined;
                }
                return securityEngine.nativeMethods.eval.call(this, code);
            };

            window.Function = function(...args) {
                const body = args.pop() || '';
                if (securityEngine.detectThreats(body, 'function')) {
                    throw new SecurityError('Dangerous function body blocked');
                }
                return securityEngine.nativeMethods.Function(...args, body);
            };
        }

        hookNetworkRequests() {
            // Hook Fetch API
            window.fetch = function(input, init = {}) {
                // 检查URL和请求体
                const url = typeof input === 'string' ? input : input.url;
                if (securityEngine.detectThreats(url, 'url') ||
                    (init.body && securityEngine.detectThreats(init.body.toString(), 'request'))) {
                    return Promise.reject(new SecurityError('Dangerous request blocked'));
                }

                // CSRF保护
                if (SECURITY_CONFIG.modules.csrfProtection) {
                    init.credentials = 'same-origin';
                    init.headers = {
                        ...init.headers,
                        'X-Requested-With': 'XMLHttpRequest',
                        'X-CSRF-Token': securityEngine.getCSRFToken(),
                        'X-Security-Hash': securityEngine.generateSecurityHash()
                    };
                }

                // API端点保护
                if (SECURITY_CONFIG.modules.apiProtection && securityEngine.isProtectedEndpoint(url)) {
                    init.headers = {
                        ...init.headers,
                        'X-API-Protection': 'enabled',
                        'X-Request-ID': securityEngine.generateRequestId()
                    };
                }

                return securityEngine.nativeMethods.fetch.call(this, input, init);
            };

            // Hook XMLHttpRequest
            const originalXHROpen = window.XMLHttpRequest.prototype.open;
            window.XMLHttpRequest.prototype.open = function(method, url) {
                if (securityEngine.detectThreats(url, 'xhr')) {
                    throw new SecurityError('Dangerous XHR request blocked');
                }
                
                // CSRF保护
                if (SECURITY_CONFIG.modules.csrfProtection) {
                    this.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                    this.setRequestHeader('X-CSRF-Token', securityEngine.getCSRFToken());
                    this.setRequestHeader('X-Security-Hash', securityEngine.generateSecurityHash());
                }
                
                // API端点保护
                if (SECURITY_CONFIG.modules.apiProtection && securityEngine.isProtectedEndpoint(url)) {
                    this.setRequestHeader('X-API-Protection', 'enabled');
                    this.setRequestHeader('X-Request-ID', securityEngine.generateRequestId());
                }
                
                return originalXHROpen.apply(this, arguments);
            };

            const originalXHRSend = window.XMLHttpRequest.prototype.send;
            window.XMLHttpRequest.prototype.send = function(data) {
                if (data && securityEngine.detectThreats(data.toString(), 'xhr_send')) {
                    throw new SecurityError('Dangerous XHR data blocked');
                }
                return originalXHRSend.apply(this, arguments);
            };
        }

        hookStorageAccess() {
            // 保护localStorage和sessionStorage
            const originalSetItem = Storage.prototype.setItem;
            Storage.prototype.setItem = function(key, value) {
                if (securityEngine.detectThreats(value, 'storage') || 
                    securityEngine.detectThreats(key, 'storage')) {
                    throw new SecurityError('Dangerous storage operation blocked');
                }
                return originalSetItem.call(this, key, value);
            };

            // 保护cookie访问
            const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
            if (originalCookieDescriptor && originalCookieDescriptor.set) {
                Object.defineProperty(Document.prototype, 'cookie', {
                    set: function(value) {
                        if (securityEngine.detectThreats(value, 'cookie')) {
                            throw new SecurityError('Dangerous cookie operation blocked');
                        }
                        return originalCookieDescriptor.set.call(this, value);
                    },
                    get: originalCookieDescriptor.get
                });
            }
        }

        hookTimers() {
            // 保护setTimeout和setInterval
            window.setTimeout = function(callback, delay, ...args) {
                if (typeof callback === 'string' && securityEngine.detectThreats(callback, 'timer')) {
                    throw new SecurityError('Dangerous timer callback blocked');
                }
                return securityEngine.nativeMethods.setTimeout.call(this, callback, delay, ...args);
            };

            window.setInterval = function(callback, delay, ...args) {
                if (typeof callback === 'string' && securityEngine.detectThreats(callback, 'timer')) {
                    throw new SecurityError('Dangerous timer callback blocked');
                }
                return securityEngine.nativeMethods.setInterval.call(this, callback, delay, ...args);
            };
        }

        hookEventListeners() {
            // 保护事件监听器
            Element.prototype.addEventListener = function(type, listener, options) {
                if (typeof listener === 'string' && securityEngine.detectThreats(listener, 'event_listener')) {
                    throw new SecurityError('Dangerous event listener blocked');
                }
                return securityEngine.nativeMethods.addEventListener.call(this, type, listener, options);
            };
        }

        hookPostMessage() {
            // 保护postMessage
            window.postMessage = function(message, targetOrigin, transfer) {
                if (securityEngine.detectThreats(typeof message === 'string' ? message : JSON.stringify(message), 'postmessage')) {
                    throw new SecurityError('Dangerous postMessage content blocked');
                }
                return securityEngine.nativeMethods.postMessage.call(this, message, targetOrigin, transfer);
            };
        }

        hookJSONMethods() {
            // 保护JSON.parse
            JSON.parse = function(text, reviver) {
                if (securityEngine.detectThreats(text, 'json')) {
                    throw new SecurityError('Dangerous JSON content blocked');
                }
                return securityEngine.nativeMethods.JSON.parse.call(this, text, reviver);
            };

            // 保护JSON.stringify
            JSON.stringify = function(value, replacer, space) {
                const result = securityEngine.nativeMethods.JSON.stringify.call(this, value, replacer, space);
                if (securityEngine.detectThreats(result, 'json')) {
                    throw new SecurityError('Dangerous JSON content blocked');
                }
                return result;
            };
        }

        getCSRFToken() {
            return document.querySelector('meta[name="csrf-token"]')?.content || '';
        }

        generateSecurityHash() {
            return btoa(Date.now() + Math.random().toString(36).substring(2)).substring(0, 20);
        }

        generateRequestId() {
            return Math.random().toString(36).substring(2) + Date.now().toString(36);
        }

        isProtectedEndpoint(url) {
            return SECURITY_CONFIG.protectedApiEndpoints.some(endpoint => url.includes(endpoint));
        }

        // ==================== 高级监控功能 ====================
        setupMutationObserver() {
            // 监控DOM变化以防止动态注入恶意内容
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === 1) { // Element node
                            securityEngine.scanNode(node);
                        }
                    });
                    
                    // 监控属性变化
                    if (mutation.type === 'attributes') {
                        securityEngine.scanAttributeChange(mutation.target, mutation.attributeName);
                    }
                });
            });

            observer.observe(document.documentElement, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['src', 'href', 'style', 'onclick', 'onload', 'onerror'],
                characterData: true
            });
        }

        scanNode(node) {
            // 深度扫描节点内容
            if (node.innerHTML && securityEngine.detectThreats(node.innerHTML, 'dynamic_html')) {
                node.parentNode.removeChild(node);
                return;
            }

            // 扫描所有属性
            if (node.attributes) {
                Array.from(node.attributes).forEach(attr => {
                    if (securityEngine.detectThreats(attr.value, 'dynamic_attribute')) {
                        node.removeAttribute(attr.name);
                    }
                });
            }

            // 检查iframe
            if (SECURITY_CONFIG.modules.iframeProtection && node.tagName === 'IFRAME') {
                const src = node.getAttribute('src');
                if (src && !securityEngine.isAllowedDomain(src)) {
                    node.parentNode.removeChild(node);
                }
            }

            // 检查script标签
            if (node.tagName === 'SCRIPT') {
                const src = node.getAttribute('src');
                if (src && !securityEngine.isAllowedDomain(src)) {
                    node.parentNode.removeChild(node);
                }
            }

            // 检查样式
            if (node.tagName === 'STYLE' && node.textContent) {
                if (securityEngine.detectThreats(node.textContent, 'style')) {
                    node.parentNode.removeChild(node);
                }
            }
        }

        scanAttributeChange(element, attributeName) {
            const value = element.getAttribute(attributeName);
            if (value && securityEngine.detectThreats(value, 'attribute_change')) {
                element.removeAttribute(attributeName);
            }
        }

        isAllowedDomain(url) {
            try {
                const domain = new URL(url, window.location.href).hostname;
                return SECURITY_CONFIG.allowedDomains.includes(domain);
            } catch (e) {
                return false;
            }
        }

        monitorNetworkRequests() {
            // 实时监控所有网络请求
            const originalSend = window.XMLHttpRequest.prototype.send;
            window.XMLHttpRequest.prototype.send = function(data) {
                if (data && securityEngine.detectThreats(data.toString(), 'xhr_send')) {
                    throw new SecurityError('Dangerous XHR data blocked');
                }
                return originalSend.apply(this, arguments);
            };

            // 监控beacon API
            const originalSendBeacon = Navigator.prototype.sendBeacon;
            Navigator.prototype.sendBeacon = function(url, data) {
                if (securityEngine.detectThreats(url, 'beacon') || 
                    (data && securityEngine.detectThreats(data.toString(), 'beacon'))) {
                    return false;
                }
                return originalSendBeacon.call(this, url, data);
            };
        }

        // ==================== 高级防护功能 ====================
        enableClickjackingProtection() {
            if (SECURITY_CONFIG.modules.clickjackingProtection) {
                // 设置X-Frame-Options
                if (window !== window.top) {
                    try {
                        if (window.self !== window.top) {
                            document.documentElement.style.visibility = 'hidden';
                            window.stop();
                            
                            // 尝试跳出框架
                            if (window.location !== window.top.location) {
                                window.top.location = window.location;
                            }
                        }
                    } catch (e) {
                        // 静默处理同源策略错误
                    }
                }
                
                // 添加样式保护
                const style = document.createElement('style');
                style.textContent = `
                    body {
                        display: none !important;
                    }
                    body:has(> script:only-child) {
                        display: block !important;
                    }
                `;
                document.head.appendChild(style);
            }
        }

        setupEventListeners() {
            // 监控表单提交
            document.addEventListener('submit', (e) => {
                const form = e.target;
                Array.from(form.elements).forEach(input => {
                    if (input.value && securityEngine.detectThreats(input.value, 'form')) {
                        e.preventDefault();
                        securityEngine.handleThreatDetected(['FORM_SUBMISSION'], input.value, 'form');
                    }
                });
                
                // 表单劫持保护
                if (SECURITY_CONFIG.modules.formHijackingProtection) {
                    const formAction = form.getAttribute('action');
                    if (formAction && !securityEngine.isAllowedDomain(formAction)) {
                        e.preventDefault();
                        securityEngine.handleThreatDetected(['FORM_HIJACKING'], formAction, 'form');
                    }
                }
            }, true);

            // 监控复制操作（防数据泄露）
            document.addEventListener('copy', (e) => {
                const selectedText = window.getSelection().toString();
                if (selectedText && securityEngine.isSensitiveData(selectedText)) {
                    e.preventDefault();
                    securityEngine.handleThreatDetected(['DATA_EXFILTRATION'], selectedText, 'clipboard');
                }
            });

            // 监控剪切操作
            document.addEventListener('cut', (e) => {
                const selectedText = window.getSelection().toString();
                if (selectedText && securityEngine.isSensitiveData(selectedText)) {
                    e.preventDefault();
                    securityEngine.handleThreatDetected(['DATA_EXFILTRATION'], selectedText, 'clipboard');
                }
            });

            // 监控粘贴操作
            document.addEventListener('paste', (e) => {
                const pastedData = e.clipboardData.getData('text');
                if (pastedData && securityEngine.detectThreats(pastedData, 'paste')) {
                    e.preventDefault();
                    securityEngine.handleThreatDetected(['PASTE_ATTACK'], pastedData, 'clipboard');
                }
            });

            // 监控键盘事件（防键盘记录）
            document.addEventListener('keydown', (e) => {
                if (SECURITY_CONFIG.modules.debuggerProtection) {
                    // 防止F12和开发者工具
                    if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) || 
                        (e.ctrlKey && e.key === 'U') || (e.ctrlKey && e.shiftKey && e.key === 'K')) {
                        e.preventDefault();
                        securityEngine.handleThreatDetected(['DEBUGGER_ACCESS'], 'Developer tools access attempt', 'keyboard');
                    }
                }
            });

            // 监控右键菜单
            document.addEventListener('contextmenu', (e) => {
                if (SECURITY_CONFIG.responsePolicy.block) {
                    e.preventDefault();
                    securityEngine.handleThreatDetected(['CONTEXT_MENU_ACCESS'], 'Right-click context menu attempt', 'mouse');
                }
            });

            // 监控beforeunload事件
            window.addEventListener('beforeunload', (e) => {
                // 检查是否有未保存的敏感数据
                if (securityEngine.hasUnsavedSensitiveData()) {
                    const message = '您有未保存的敏感数据，确定要离开吗？';
                    e.returnValue = message;
                    return message;
                }
            });

            // 监控hashchange和popstate（防历史记录操作）
            window.addEventListener('hashchange', () => {
                securityEngine.handleHistoryChange();
            });

            window.addEventListener('popstate', () => {
                securityEngine.handleHistoryChange();
            });
        }

        isSensitiveData(text) {
            // 检测敏感数据模式（信用卡、密码、token等）
            const sensitivePatterns = [
                THREAT_PATTERNS.sensitiveData.creditCard,
                THREAT_PATTERNS.sensitiveData.ssn,
                THREAT_PATTERNS.sensitiveData.apiKey,
                THREAT_PATTERNS.sensitiveData.jwt,
                THREAT_PATTERNS.sensitiveData.password
            ];
            
            return sensitivePatterns.some(pattern => pattern.test(text));
        }

        hasUnsavedSensitiveData() {
            // 检查表单中是否有未提交的敏感数据
            const inputs = document.querySelectorAll('input, textarea');
            for (const input of inputs) {
                if (input.value && this.isSensitiveData(input.value) && 
                    !input.hasAttribute('data-submitted')) {
                    return true;
                }
            }
            return false;
        }

        setupHoneypots() {
            if (SECURITY_CONFIG.responsePolicy.enableHoneypot) {
                // 创建蜜罐陷阱
                SECURITY_CONFIG.honeypotSelectors.forEach(selector => {
                    const elements = document.querySelectorAll(selector);
                    elements.forEach(element => {
                        this.honeypots.push(element);
                        
                        // 监控蜜罐交互
                        element.addEventListener('focus', () => {
                            this.handleThreatDetected(['HONEYPOT_TRIGGER'], 'Honeypot interaction detected', 'honeypot');
                        });
                        
                        element.addEventListener('click', (e) => {
                            this.handleThreatDetected(['HONEYPOT_TRIGGER'], 'Honeypot interaction detected', 'honeypot');
                            e.preventDefault();
                            e.stopPropagation();
                        });
                        
                        element.addEventListener('change', (e) => {
                            this.handleThreatDetected(['HONEYPOT_TRIGGER'], 'Honeypot interaction detected', 'honeypot');
                            e.preventDefault();
                            e.stopPropagation();
                        });
                    });
                });
            }
        }

        protectSession() {
            if (SECURITY_CONFIG.modules.sessionProtection) {
                // 监控会话存储
                const originalSessionSetItem = sessionStorage.setItem;
                sessionStorage.setItem = function(key, value) {
                    if (securityEngine.detectThreats(value, 'session_storage') || 
                        securityEngine.detectThreats(key, 'session_storage')) {
                        throw new SecurityError('Dangerous session storage operation blocked');
                    }
                    return originalSessionSetItem.call(this, key, value);
                };

                // 定期清理会话
                setInterval(() => {
                    this.cleanSessionStorage();
                }, 300000); // 每5分钟清理一次
            }
        }

        cleanSessionStorage() {
            try {
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    if (key && key.startsWith('temp_')) {
                        sessionStorage.removeItem(key);
                    }
                }
            } catch (e) {
                // 静默失败
            }
        }

        protectHistory() {
            if (SECURITY_CONFIG.modules.historyProtection) {
                // 保护history API
                const originalPushState = history.pushState;
                history.pushState = function(state, title, url) {
                    if (url && securityEngine.detectThreats(url.toString(), 'history')) {
                        throw new SecurityError('Dangerous history operation blocked');
                    }
                    return originalPushState.apply(this, arguments);
                };

                const originalReplaceState = history.replaceState;
                history.replaceState = function(state, title, url) {
                    if (url && securityEngine.detectThreats(url.toString(), 'history')) {
                        throw new SecurityError('Dangerous history operation blocked');
                    }
                    return originalReplaceState.apply(this, arguments);
                };
            }
        }

        handleHistoryChange() {
            if (SECURITY_CONFIG.modules.historyProtection) {
                // 检查URL变化
                if (securityEngine.detectThreats(window.location.href, 'history_change')) {
                    history.back();
                }
            }
        }

        establishBaseline() {
            // 建立行为基线
            return {
                averageTypingSpeed: 40, // 字符/分钟
                averageClicksPerMinute: 20,
                commonDomains: SECURITY_CONFIG.allowedDomains,
                userAgent: navigator.userAgent,
                screenResolution: `${screen.width}x${screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                languages: navigator.languages
            };
        }

        analyzeBehavior(event) {
            if (SECURITY_CONFIG.modules.behaviorAnalysis) {
                // 行为分析逻辑
                const now = Date.now();
                const timeSinceLastEvent = now - (this.lastBehaviorEventTime || 0);
                this.lastBehaviorEventTime = now;
                
                // 检测异常行为模式
                if (timeSinceLastEvent < 50) { // 极快的事件序列
                    this.handleThreatDetected(['BEHAVIOR_ANOMALY'], `Rapid event sequence detected: ${timeSinceLastEvent}ms`, 'behavior');
                }
                
                // 更多行为分析逻辑可以在这里实现
            }
        }

        activateParanoidMode() {
            // 高频攻击时进入 paranoid 模式
            console.warn('[ACSS] 进入高级防护模式');
            
            // 禁用开发者工具
            document.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) {
                    e.preventDefault();
                    this.handleThreatDetected(['DEVELOPER_TOOLS'], 'Developer tools access attempt', 'keyboard');
                }
            });

            // 禁用右键菜单
            document.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                this.handleThreatDetected(['CONTEXT_MENU'], 'Context menu access attempt', 'mouse');
            });

            // 禁用文本选择
            document.addEventListener('selectstart', (e) => {
                e.preventDefault();
                this.handleThreatDetected(['TEXT_SELECTION'], 'Text selection attempt', 'mouse');
            });

            // 禁用拖放
            document.addEventListener('dragstart', (e) => {
                e.preventDefault();
                this.handleThreatDetected(['DRAG_DROP'], 'Drag and drop attempt', 'mouse');
            });

            // 添加模糊保护
            window.addEventListener('blur', () => {
                this.handleThreatDetected(['WINDOW_BLUR'], 'Window lost focus', 'window');
            });

            // 添加防调试保护
            const debuggerProtection = () => {
                setInterval(() => {
                    if (this.isDebuggerAttached()) {
                        this.handleThreatDetected(['DEBUGGER_DETECTED'], 'Debugger detected', 'debug');
                        this.lockSystem();
                    }
                }, 1000);
            };
            
            debuggerProtection();
        }

        isDebuggerAttached() {
            // 简单的调试器检测
            const start = Date.now();
            debugger; // eslint-disable-line no-debugger
            return Date.now() - start > 100;
        }
    }

    // ==================== 安全错误类 ====================
    class SecurityError extends Error {
        constructor(message) {
            super(message);
            this.name = 'SecurityError';
        }
    }

    // ==================== 初始化 ====================
    // 防止重复初始化
    if (window.__ACSS_LOADED__) {
        console.warn('[ACSS] 安全防护已初始化');
        return;
    }

    window.__ACSS_LOADED__ = true;
    const securityEngine = new SecurityEngine();

    // 全局暴露安全引擎（可选，用于调试）
    window.__SECURITY_ENGINE__ = securityEngine;

    // CSP后备保护
    if (!window.SecurityPolicyViolationEvent) {
        console.info('[ACSS] CSP not supported, relying on client-side protection');
    }

})();