/**
 * Seraph AI Browser Shield - Background Service Worker
 * Real-time protection against browser-based attacks
 */

// Configuration
const SERAPH_SERVER = 'http://localhost:8001'; // Default - can be changed in settings
const BLOCKLIST_UPDATE_INTERVAL = 300000; // 5 minutes

// Threat databases
let maliciousDomains = new Set([
  'malware-test.com', 'phishing-example.org', 'evil-download.net',
  'credential-steal.xyz', 'cryptominer.io', 'ransomware-delivery.com'
]);

let suspiciousPatterns = [
  /login.*\.php\?.*redirect/i,           // Phishing redirects
  /\.exe$|\.scr$|\.bat$|\.ps1$/i,        // Dangerous downloads
  /data:text\/html.*base64/i,            // Data URL XSS
  /javascript:/i,                         // JS injection
  /passw(or)?d.*=.*[a-z0-9]{8,}/i,       // Password in URL
  /api[_-]?key.*=.*[a-z0-9]{20,}/i,      // API key exposure
];

let cryptojackingScripts = [
  'coinhive.min.js', 'cryptonight.wasm', 'deepminer.min.js',
  'coin-hive.com', 'coinhive.com', 'crypto-loot.com', 'coin-have.com'
];

// Statistics
let stats = {
  pagesScanned: 0,
  threatsBlocked: 0,
  phishingBlocked: 0,
  malwareBlocked: 0,
  cryptojackingBlocked: 0,
  xssBlocked: 0,
  lastUpdated: Date.now()
};

// Load stats from storage
chrome.storage.local.get(['seraphStats', 'seraphSettings'], (result) => {
  if (result.seraphStats) stats = result.seraphStats;
});

// Save stats periodically
setInterval(() => {
  chrome.storage.local.set({ seraphStats: stats });
}, 10000);

/**
 * Check if URL is malicious
 */
function checkUrl(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    
    // Check blocklist
    if (maliciousDomains.has(domain)) {
      return { blocked: true, reason: 'malicious_domain', severity: 'critical' };
    }
    
    // Check for typosquatting of popular sites
    const typosquatTargets = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix'];
    for (const target of typosquatTargets) {
      if (domain.includes(target) && !domain.endsWith(`.${target}.com`) && !domain.endsWith(`${target}.com`)) {
        // Potential typosquat
        const distance = levenshteinDistance(domain.replace(/\..+$/, ''), target);
        if (distance > 0 && distance <= 2) {
          return { blocked: true, reason: 'typosquatting', severity: 'high', target };
        }
      }
    }
    
    // Check suspicious patterns
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(url)) {
        return { blocked: true, reason: 'suspicious_pattern', severity: 'medium', pattern: pattern.toString() };
      }
    }
    
    // Check for data theft indicators
    if (url.includes('password=') || url.includes('passwd=') || url.includes('credit_card=')) {
      return { blocked: true, reason: 'data_exposure', severity: 'critical' };
    }
    
    return { blocked: false };
  } catch (e) {
    return { blocked: false };
  }
}

/**
 * Levenshtein distance for typosquatting detection
 */
function levenshteinDistance(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Web request interceptor
 */
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    stats.pagesScanned++;
    
    const check = checkUrl(details.url);
    if (check.blocked) {
      stats.threatsBlocked++;
      
      if (check.reason === 'malicious_domain') stats.malwareBlocked++;
      if (check.reason === 'typosquatting') stats.phishingBlocked++;
      
      // Log threat
      console.log('[Seraph Shield] Blocked:', check.reason, details.url);
      
      // Send notification
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '🛡️ Seraph Shield - Threat Blocked',
        message: `Blocked ${check.reason.replace('_', ' ')}: ${new URL(details.url).hostname}`,
        priority: 2
      });
      
      // Report to server
      reportThreat(details.url, check);
      
      // Redirect to blocked page
      return { redirectUrl: chrome.runtime.getURL('blocked.html') + '?reason=' + encodeURIComponent(check.reason) };
    }
    
    // Check for cryptojacking scripts
    for (const miner of cryptojackingScripts) {
      if (details.url.toLowerCase().includes(miner)) {
        stats.threatsBlocked++;
        stats.cryptojackingBlocked++;
        console.log('[Seraph Shield] Blocked cryptojacking:', details.url);
        return { cancel: true };
      }
    }
    
    return {};
  },
  { urls: ['<all_urls>'] },
  ['blocking']
);

/**
 * Header inspection for security
 */
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers = details.responseHeaders || [];
    const warnings = [];
    
    // Check for missing security headers
    const hasCSP = headers.some(h => h.name.toLowerCase() === 'content-security-policy');
    const hasXSS = headers.some(h => h.name.toLowerCase() === 'x-xss-protection');
    const hasFrameOptions = headers.some(h => h.name.toLowerCase() === 'x-frame-options');
    
    if (!hasCSP && details.type === 'main_frame') {
      warnings.push('missing_csp');
    }
    
    // Log security warnings (don't block, just monitor)
    if (warnings.length > 0) {
      console.log('[Seraph Shield] Security warnings for', details.url, ':', warnings);
    }
    
    return {};
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

/**
 * Report threat to Seraph server
 */
async function reportThreat(url, check) {
  try {
    const settings = await chrome.storage.local.get('seraphSettings');
    const serverUrl = settings.seraphSettings?.serverUrl || SERAPH_SERVER;
    
    await fetch(`${serverUrl}/api/swarm/alerts/critical`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent_id: 'browser-extension',
        host_id: 'browser',
        alert_type: 'BROWSER_THREAT_BLOCKED',
        severity: check.severity,
        threat_type: check.reason,
        message: `Blocked ${check.reason}: ${url}`,
        evidence: { url, check },
        timestamp: new Date().toISOString()
      })
    });
  } catch (e) {
    // Server may not be reachable - that's OK
  }
}

/**
 * Update blocklist from server
 */
async function updateBlocklist() {
  try {
    const settings = await chrome.storage.local.get('seraphSettings');
    const serverUrl = settings.seraphSettings?.serverUrl || SERAPH_SERVER;
    
    const response = await fetch(`${serverUrl}/api/browser-shield/blocklist`);
    if (response.ok) {
      const data = await response.json();
      if (data.domains) {
        maliciousDomains = new Set([...maliciousDomains, ...data.domains]);
        console.log('[Seraph Shield] Blocklist updated:', maliciousDomains.size, 'domains');
      }
    }
  } catch (e) {
    // Server may not be reachable
  }
  
  stats.lastUpdated = Date.now();
}

// Update blocklist periodically
chrome.alarms.create('updateBlocklist', { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'updateBlocklist') {
    updateBlocklist();
  }
});

// Initial blocklist fetch
updateBlocklist();

/**
 * Message handler for popup and content scripts
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'getStats') {
    sendResponse(stats);
  } else if (request.type === 'checkUrl') {
    sendResponse(checkUrl(request.url));
  } else if (request.type === 'reportXSS') {
    stats.xssBlocked++;
    stats.threatsBlocked++;
    reportThreat(sender.tab?.url || 'unknown', { 
      blocked: true, 
      reason: 'xss_attempt', 
      severity: 'high',
      payload: request.payload 
    });
    sendResponse({ blocked: true });
  } else if (request.type === 'contentAnalysis') {
    // Analyze content from content script
    const result = analyzeContent(request.data);
    sendResponse(result);
  }
  return true;
});

/**
 * Analyze page content for threats
 */
function analyzeContent(data) {
  const threats = [];
  
  // Check for phishing indicators
  if (data.forms && data.forms.length > 0) {
    for (const form of data.forms) {
      if (form.hasPasswordField && !data.isHttps) {
        threats.push({ type: 'insecure_password_form', severity: 'high' });
      }
      if (form.action && form.action.includes('login') && !data.url.includes(new URL(form.action).hostname)) {
        threats.push({ type: 'cross_origin_login', severity: 'high' });
      }
    }
  }
  
  // Check for suspicious scripts
  if (data.scripts) {
    for (const script of data.scripts) {
      if (script.includes('keylog') || script.includes('capture') || script.includes('exfil')) {
        threats.push({ type: 'suspicious_script', severity: 'critical' });
      }
    }
  }
  
  return { threats, count: threats.length };
}

console.log('[Seraph Shield] Browser protection active');
