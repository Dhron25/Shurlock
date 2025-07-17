const API_KEY = 'AIzaSyBz4ZT6Z05ezubMfJYOrNVaJVeBqE3I3sE';
const SAFE_BROWSING_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;

class SecurityScanner {
  constructor() {
    this.scanResults = new Map();
    this.settings = {};
    this.loadSettings();
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.sync.get(['shurlock_settings']);
      this.settings = result.shurlock_settings || {
        scanning: {
          timeout: 10,
          autoRescan: true
        },
        appearance: {
          theme: 'dark'
        }
      };
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  }

  async performComprehensiveScan(tabId, url) {
    if (!url || !url.startsWith('http')) {
      return;
    }

    console.log(`Starting comprehensive scan for: ${url}`);
    
    const scanResult = {
      url: url,
      timestamp: Date.now(),
      status: 'scanning',
      overallRisk: 0,
      brief: 'Performing comprehensive security analysis...',
      details: {
        safeBrowsing: { status: 'pending', data: null },
        sslCertificate: { status: 'pending', data: null },
        domainReputation: { status: 'pending', data: null },
        urlAnalysis: { status: 'pending', data: null },
        securityHeaders: { status: 'pending', data: null }
      }
    };

    this.updateScanResult(tabId, scanResult);
    this.updateIcon(tabId, 'scanning');

    try {
      console.log('Checking Safe Browsing...');
      const safeBrowsingResult = await this.checkSafeBrowsing(url);
      scanResult.details.safeBrowsing = { status: 'completed', data: safeBrowsingResult };
      this.updateScanResult(tabId, scanResult);

      console.log('Checking SSL Certificate...');
      const sslResult = await this.checkSSLCertificate(url);
      scanResult.details.sslCertificate = { status: 'completed', data: sslResult };
      this.updateScanResult(tabId, scanResult);

      console.log('Checking Domain Reputation...');
      const domainResult = await this.checkDomainReputation(url);
      scanResult.details.domainReputation = { status: 'completed', data: domainResult };
      this.updateScanResult(tabId, scanResult);

      console.log('Analyzing URL Structure...');
      const urlAnalysisResult = this.analyzeURLStructure(url);
      scanResult.details.urlAnalysis = { status: 'completed', data: urlAnalysisResult };
      this.updateScanResult(tabId, scanResult);

      console.log('Checking Security Headers...');
      const securityHeadersResult = await this.checkSecurityHeaders(url);
      scanResult.details.securityHeaders = { status: 'completed', data: securityHeadersResult };
      this.updateScanResult(tabId, scanResult);

      // Calculate overall risk and generate brief
      const riskAnalysis = this.calculateOverallRisk(scanResult.details);
      scanResult.overallRisk = riskAnalysis.risk;
      scanResult.status = riskAnalysis.status;
      scanResult.brief = riskAnalysis.brief;

      this.updateScanResult(tabId, scanResult);
      this.updateIcon(tabId, riskAnalysis.status);

      console.log('Comprehensive scan completed:', scanResult);

    } catch (error) {
      console.error('Comprehensive scan failed:', error);
      scanResult.status = 'error';
      scanResult.brief = 'Security scan failed due to technical issues.';
      this.updateScanResult(tabId, scanResult);
      this.updateIcon(tabId, 'error');
    }
  }

  async checkSafeBrowsing(url) {
    try {
      const response = await fetch(SAFE_BROWSING_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: {
            clientId: 'shurlock-extension',
            clientVersion: '2.0.0',
          },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING', 
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: url }],
          },
        }),
      });

      if (!response.ok) {
        throw new Error(`Safe Browsing API error: ${response.status}`);
      }

      const data = await response.json();
      console.log('Safe Browsing result:', data);
      
      return {
        safe: !data.matches || data.matches.length === 0,
        threats: data.matches || [],
        details: data.matches?.map(match => ({
          type: match.threatType,
          platform: match.platformType,
          threat: match.threat
        })) || []
      };
    } catch (error) {
      console.error('Safe Browsing check failed:', error);
      return {
        safe: true,
        threats: [],
        details: [],
        error: error.message
      };
    }
  }

  async checkSSLCertificate(url) {
    try {
      const urlObj = new URL(url);
      const isHTTPS = urlObj.protocol === 'https:';
      
      if (!isHTTPS) {
        return {
          valid: false,
          grade: 'No SSL',
          details: {
            protocol: 'HTTP',
            hasSSL: false,
            issue: 'Site does not use HTTPS',
            warnings: ['Site is not using HTTPS encryption']
          }
        };
      }

      try {
        const response = await fetch(url, { 
          method: 'HEAD',
          signal: AbortSignal.timeout(5000)
        });
        
        return {
          valid: true,
          grade: 'HTTPS Active',
          details: {
            protocol: 'HTTPS',
            hasSSL: true,
            status: response.status,
            statusText: response.statusText,
            warnings: []
          }
        };
      } catch (fetchError) {
        return {
          valid: false,
          grade: 'SSL Error',
          details: {
            protocol: 'HTTPS',
            hasSSL: true,
            issue: 'SSL connection failed',
            error: fetchError.message,
            warnings: ['SSL connection could not be established']
          }
        };
      }
    } catch (error) {
      console.error('SSL check failed:', error);
      return {
        valid: false,
        grade: 'Check Failed',
        details: {
          error: error.message,
          warnings: ['SSL certificate check failed']
        }
      };
    }
  }

  async checkDomainReputation(url) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      
      const checks = {
        suspiciousTLD: this.checkSuspiciousTLD(domain),
        shortDomain: domain.replace(/\./g, '').length < 6,
        manySubdomains: domain.split('.').length > 4,
        containsNumbers: /\d{2,}/.test(domain),
        homographAttack: this.checkHomographAttack(domain),
        ipAddress: this.isIPAddress(domain),
        dashesInDomain: (domain.match(/-/g) || []).length > 2,
        randomPattern: this.checkRandomPattern(domain)
      };

      const suspiciousCount = Object.values(checks).filter(Boolean).length;
      const trustScore = Math.max(0, 100 - (suspiciousCount * 12));
      
      console.log('Domain reputation checks:', checks, 'Score:', trustScore);
      
      return {
        trustScore: trustScore,
        flags: checks,
        domain: domain,
        analysis: this.generateDomainAnalysis(checks, domain),
        riskFactors: Object.keys(checks).filter(key => checks[key]).map(key => this.formatRiskFactor(key))
      };
    } catch (error) {
      console.error('Domain reputation check failed:', error);
      return { 
        trustScore: 50, 
        error: error.message,
        domain: 'Unknown',
        analysis: 'Domain analysis failed',
        riskFactors: []
      };
    }
  }

  analyzeURLStructure(url) {
    try {
      const analysis = {
        length: url.length,
        hasQueryParams: url.includes('?'),
        hasFragments: url.includes('#'),
        urlShortener: this.checkURLShortener(url),
        suspiciousPatterns: this.checkSuspiciousPatterns(url),
        entropy: this.calculateEntropy(url),
        encodedChars: this.checkEncodedChars(url),
        multipleRedirects: url.includes('redirect') || url.includes('redir')
      };

      const riskScore = this.calculateURLRisk(analysis);
      
      console.log('URL analysis:', analysis, 'Risk score:', riskScore);

      return {
        riskScore: riskScore,
        details: analysis,
        recommendations: this.generateURLRecommendations(analysis)
      };
    } catch (error) {
      console.error('URL analysis failed:', error);
      return {
        riskScore: 50,
        error: error.message,
        details: {},
        recommendations: []
      };
    }
  }

  async checkSecurityHeaders(url) {
    try {
      const response = await fetch(url, { 
        method: 'HEAD',
        signal: AbortSignal.timeout(5000)
      });
      
      const headers = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });

      const securityHeaders = {
        'strict-transport-security': headers['strict-transport-security'],
        'content-security-policy': headers['content-security-policy'],
        'x-frame-options': headers['x-frame-options'],
        'x-content-type-options': headers['x-content-type-options'],
        'referrer-policy': headers['referrer-policy'],
        'x-xss-protection': headers['x-xss-protection']
      };

      const score = this.calculateSecurityHeaderScore(securityHeaders);
      const missing = this.getMissingSecurityHeaders(securityHeaders);

      console.log('Security headers:', securityHeaders, 'Score:', score);

      return {
        score: score,
        headers: securityHeaders,
        missing: missing,
        present: Object.keys(securityHeaders).filter(h => securityHeaders[h])
      };
    } catch (error) {
      console.error('Security headers check failed:', error);
      return { 
        score: 0, 
        error: error.message,
        headers: {},
        missing: ['All security headers'],
        present: []
      };
    }
  }

  calculateOverallRisk(details) {
    let riskScore = 0;
    let criticalIssues = [];
    let warnings = [];

    // Safe Browsing (Critical - 40 points)
    if (details.safeBrowsing?.status === 'completed' && details.safeBrowsing.data) {
      if (!details.safeBrowsing.data.safe && details.safeBrowsing.data.threats.length > 0) {
        riskScore += 40;
        criticalIssues.push('Malware/Phishing threats detected');
      }
    }

    // SSL Certificate (High - 25 points)
    if (details.sslCertificate?.status === 'completed' && details.sslCertificate.data) {
      if (!details.sslCertificate.data.valid) {
        riskScore += 25;
        warnings.push('SSL certificate issues');
      }
    }

    // Domain Reputation (Medium - 20 points) 
    if (details.domainReputation?.status === 'completed' && details.domainReputation.data) {
      const trustScore = details.domainReputation.data.trustScore || 0;
      if (trustScore < 50) {
        riskScore += 20;
        warnings.push('Suspicious domain characteristics');
      }
    }

    // URL Analysis (Low - 10 points)
    if (details.urlAnalysis?.status === 'completed' && details.urlAnalysis.data) {
      const urlRisk = details.urlAnalysis.data.riskScore || 0;
      if (urlRisk > 60) {
        riskScore += 10;
        warnings.push('Suspicious URL structure');
      }
    }

    // Security Headers (Low - 5 points)
    if (details.securityHeaders?.status === 'completed' && details.securityHeaders.data) {
      const headerScore = details.securityHeaders.data.score || 0;
      if (headerScore < 40) {
        riskScore += 5;
        warnings.push('Missing security headers');
      }
    }

    let status, brief;
    if (riskScore >= 60) {
      status = 'dangerous';
      brief = `High security risk detected. ${criticalIssues.concat(warnings).join(', ')}`;
    } else if (riskScore >= 25) {
      status = 'warning';
      brief = `Moderate security concerns found. ${warnings.join(', ')}`;
    } else {
      status = 'safe';
      brief = 'Site appears secure with no major security issues detected.';
    }

    console.log('Overall risk calculation:', { riskScore, status, brief });

    return { risk: riskScore, status, brief };
  }

  // Helper methods
  checkSuspiciousTLD(domain) {
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.bit', '.onion', '.click', '.download'];
    return suspiciousTLDs.some(tld => domain.endsWith(tld));
  }

  checkHomographAttack(domain) {
    const suspiciousChars = /[а-я]|[α-ω]|[א-ת]|[零-龯]/;
    return suspiciousChars.test(domain);
  }

  isIPAddress(domain) {
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Pattern.test(domain) || ipv6Pattern.test(domain);
  }

  checkRandomPattern(domain) {
    const randomPattern = /[a-zA-Z0-9]{8,}/;
    const parts = domain.split('.');
    return parts.some(part => randomPattern.test(part) && !/[aeiou]/.test(part));
  }

  checkURLShortener(url) {
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link', 'tinycc.com'];
    return shorteners.some(shortener => url.includes(shortener));
  }

  checkSuspiciousPatterns(url) {
    const patterns = [
      /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,
      /[a-zA-Z0-9]{25,}/,
      /-{3,}/,
      /\.{3,}/,
      /%[0-9a-fA-F]{2}/
    ];
    return patterns.some(pattern => pattern.test(url));
  }

  checkEncodedChars(url) {
    return (url.match(/%[0-9a-fA-F]{2}/g) || []).length > 3;
  }

  calculateEntropy(str) {
    const freq = {};
    for (let char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    
    let entropy = 0;
    const length = str.length;
    
    for (let char in freq) {
      const p = freq[char] / length;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }

  calculateURLRisk(analysis) {
    let risk = 0;
    if (analysis.length > 150) risk += 15;
    if (analysis.urlShortener) risk += 30;
    if (analysis.suspiciousPatterns) risk += 25;
    if (analysis.entropy > 4.5) risk += 10;
    if (analysis.encodedChars) risk += 15;
    if (analysis.multipleRedirects) risk += 10;
    return Math.min(risk, 100);
  }

  calculateSecurityHeaderScore(headers) {
    let score = 0;
    if (headers['strict-transport-security']) score += 20;
    if (headers['content-security-policy']) score += 25;
    if (headers['x-frame-options']) score += 15;
    if (headers['x-content-type-options']) score += 20;
    if (headers['referrer-policy']) score += 10;
    if (headers['x-xss-protection']) score += 10;
    return score;
  }

  getMissingSecurityHeaders(headers) {
    const recommended = [
      'strict-transport-security',
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'x-xss-protection'
    ];
    return recommended.filter(header => !headers[header]);
  }

  generateDomainAnalysis(checks, domain) {
    const issues = [];
    if (checks.suspiciousTLD) issues.push('Suspicious top-level domain');
    if (checks.shortDomain) issues.push('Very short domain name');
    if (checks.manySubdomains) issues.push('Multiple subdomains');
    if (checks.homographAttack) issues.push('Possible homograph attack');
    if (checks.ipAddress) issues.push('IP address instead of domain');
    if (checks.dashesInDomain) issues.push('Excessive dashes in domain');
    if (checks.randomPattern) issues.push('Random-looking domain pattern');
    
    return issues.length > 0 ? issues.join(', ') : 'Domain appears legitimate';
  }

  formatRiskFactor(key) {
    const riskFactorMap = {
      suspiciousTLD: 'Suspicious top-level domain',
      shortDomain: 'Very short domain name',
      manySubdomains: 'Multiple subdomains',
      containsNumbers: 'Contains multiple numbers',
      homographAttack: 'Possible homograph attack',
      ipAddress: 'IP address instead of domain',
      dashesInDomain: 'Excessive dashes in domain',
      randomPattern: 'Random-looking domain pattern'
    };
    return riskFactorMap[key] || key;
  }

  generateURLRecommendations(analysis) {
    const recommendations = [];
    if (analysis.urlShortener) recommendations.push('URL shortener detected - verify destination');
    if (analysis.suspiciousPatterns) recommendations.push('Suspicious URL patterns found');
    if (analysis.length > 200) recommendations.push('Unusually long URL');
    if (analysis.encodedChars) recommendations.push('Many encoded characters detected');
    if (analysis.multipleRedirects) recommendations.push('Potential redirect chain detected');
    
    return recommendations;
  }

  updateScanResult(tabId, result) {
    const key = `scanResult_${tabId}`;
    chrome.storage.local.set({ [key]: result });
  }

  updateIcon(tabId, status) {
    const iconPaths = {
      safe: 'images/icon-safe-48.png',
      warning: 'images/icon-warning-48.png',
      dangerous: 'images/icon-danger-48.png',
      scanning: 'images/icon-scanning-48.png',
      error: 'images/icon-error-48.png'
    };

    chrome.action.setIcon({
      path: iconPaths[status] || iconPaths.error,
      tabId: tabId
    });
  }
}

// Initialize scanner
const scanner = new SecurityScanner();

// Message handler for popup communications
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'rescan') {
    scanner.performComprehensiveScan(request.tabId, request.url);
    sendResponse({ success: true });
  }
  
  if (request.action === 'downloadReport') {
    const reportHTML = request.reportHTML;
    const filename = request.filename;
    
    const blob = new Blob([reportHTML], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    
    chrome.downloads.download({
      url: url,
      filename: filename,
      saveAs: true
    }, (downloadId) => {
      if (chrome.runtime.lastError) {
        console.error('Download failed:', chrome.runtime.lastError);
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
      } else {
        console.log('Download started:', downloadId);
        sendResponse({ success: true, downloadId: downloadId });
      }
      URL.revokeObjectURL(url);
    });
    
    return true; 
  }

  if (request.action === 'updateSettings') {
    scanner.loadSettings();
    sendResponse({ success: true });
  }
});

// Tab event listeners
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && isValidScanURL(tab.url)) {
    console.log('Valid URL detected, starting scan:', tab.url);
    scanner.performComprehensiveScan(tabId, tab.url);
  } else if (changeInfo.status === 'complete') {
    console.log('Skipping scan for URL:', tab.url);
    
    const key = `scanResult_${tabId}`;
    chrome.storage.local.remove(key);
  }
});

chrome.tabs.onActivated.addListener(activeInfo => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (isValidScanURL(tab.url)) {
      console.log('Valid URL on tab activation:', tab.url);
      scanner.performComprehensiveScan(tab.id, tab.url);
    } else {
      console.log('Skipping scan on tab activation for:', tab.url);
      
      const key = `scanResult_${activeInfo.tabId}`;
      chrome.storage.local.remove(key);
    }
  });
});

// Settings change listener
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'sync' && changes.shurlock_settings) {
    console.log('Settings updated, reloading scanner settings');
    scanner.loadSettings();
  }
});

function isValidScanURL(url) {
  if (!url) return false;
  
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return false;
  }
  
  const skipPatterns = [
    'chrome://',
    'chrome-extension://',
    'moz-extension://',
    'edge-extension://',
    'about:',
    'file://',
    'data:',
    'javascript:',
    'localhost',
    '127.0.0.1',
    '0.0.0.0'
  ];
  
  return !skipPatterns.some(pattern => url.includes(pattern));
}

console.log('Shurlock Security Scanner background script loaded');