// In production, use environment variables for API_KEY
// const API_KEY = 'YOUR_SAFE_BROWSING_API_KEY'; // Placeholder - not used in this commit

class SecurityScanner {
  constructor() {
    this.scanResults = new Map();
  }

  async performComprehensiveScan(tabId, url) {
    if (!url || !url.startsWith('http')) {
      return;
    }

    console.log(`Starting foundational scan for: ${url}`);
    
    const scanResult = {
      url: url,
      timestamp: Date.now(),
      status: 'scanning',
      overallRisk: 0,
      brief: 'Performing initial security checks...',
      details: {
        safeBrowsing: { status: 'pending', data: null }, // Placeholder
        sslCertificate: { status: 'pending', data: null },
        domainReputation: { status: 'pending', data: null }, // Placeholder
        urlAnalysis: { status: 'pending', data: null },
        securityHeaders: { status: 'pending', data: null } // Placeholder
      }
    };

    this.updateScanResult(tabId, scanResult);
    this.updateIcon(tabId, 'scanning');

    try {
      // Implement initial, basic checks
      console.log('Checking SSL Certificate...');
      const sslResult = await this.checkSSLCertificate(url);
      scanResult.details.sslCertificate = { status: 'completed', data: sslResult };
      this.updateScanResult(tabId, scanResult);

      console.log('Analyzing URL Structure...');
      const urlAnalysisResult = this.analyzeURLStructure(url);
      scanResult.details.urlAnalysis = { status: 'completed', data: urlAnalysisResult };
      this.updateScanResult(tabId, scanResult);

      // Calculate overall risk based on limited data for now
      const riskAnalysis = this.calculateOverallRisk(scanResult.details);
      scanResult.overallRisk = riskAnalysis.risk;
      scanResult.status = riskAnalysis.status;
      scanResult.brief = riskAnalysis.brief;

      this.updateScanResult(tabId, scanResult);
      this.updateIcon(tabId, riskAnalysis.status);

      console.log('Foundational scan completed:', scanResult);

    } catch (error) {
      console.error('Foundational scan failed:', error);
      scanResult.status = 'error';
      scanResult.brief = 'Initial scan failed due to technical issues.';
      this.updateScanResult(tabId, scanResult);
      this.updateIcon(tabId, 'error');
    }
  }

  // Safe Browsing will be implemented in the next commit
  async checkSafeBrowsing(url) {
    return { safe: true, threats: [] }; // Placeholder
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
            issue: 'Site does not use HTTPS'
          }
        };
      }

      // Simple check: just ensure it's HTTPS. Deeper validation in next commit.
      const response = await fetch(url, { 
        method: 'HEAD',
        signal: AbortSignal.timeout(3000) // Short timeout for basic check
      });
      
      return {
        valid: response.ok, // Treat any successful HEAD as valid for now
        grade: response.ok ? 'HTTPS Active' : 'SSL Error',
        details: {
          protocol: 'HTTPS',
          hasSSL: true,
          status: response.status
        }
      };
    } catch (error) {
      console.error('SSL check failed:', error);
      return {
        valid: false,
        grade: 'Check Failed',
        details: { error: error.message }
      };
    }
  }

  // Domain Reputation will be implemented in the next commit
  async checkDomainReputation(url) {
    return { trustScore: 75, domain: new URL(url).hostname }; // Placeholder
  }

  analyzeURLStructure(url) {
    try {
      const analysis = {
        length: url.length,
        hasQueryParams: url.includes('?'),
        urlShortener: this.checkURLShortener(url) // Simple shortener check
      };

      let riskScore = 0;
      if (analysis.urlShortener) riskScore += 30;
      if (analysis.length > 100) riskScore += 10; // Basic length check
      
      return {
        riskScore: riskScore,
        details: analysis,
        recommendations: []
      };
    } catch (error) {
      console.error('URL analysis failed:', error);
      return {
        riskScore: 50,
        error: error.message,
        details: {}
      };
    }
  }

  // Security Headers will be implemented in the next commit
  async checkSecurityHeaders(url) {
    return { score: 0, headers: {}, missing: [] }; // Placeholder
  }

  calculateOverallRisk(details) {
    let riskScore = 0;
    let brief = 'Performing initial analysis.';

    if (details.sslCertificate?.status === 'completed' && !details.sslCertificate.data?.valid) {
      riskScore += 30;
      brief = 'SSL certificate issues detected.';
    }
    if (details.urlAnalysis?.status === 'completed' && details.urlAnalysis.data?.riskScore > 0) {
      riskScore += details.urlAnalysis.data.riskScore / 2; // Half weight for initial checks
      if (details.urlAnalysis.data?.urlShortener) {
        brief = 'URL shortener detected, proceed with caution.';
      }
    }

    let status;
    if (riskScore >= 40) {
      status = 'warning';
      brief = brief + ' Some basic security concerns found.';
    } else if (riskScore > 0) {
      status = 'safe'; // Minor risks are still safe for now
      brief = brief + ' Initial checks indicate safety.';
    } else {
      status = 'safe';
      brief = 'Site appears safe based on initial checks.';
    }

    return { risk: Math.min(riskScore, 100), status, brief };
  }

  // Helper methods for this commit
  checkURLShortener(url) {
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co']; // Basic list
    return shorteners.some(shortener => url.includes(shortener));
  }

  // Other helper methods for full checks will be in the next commit

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

const scanner = new SecurityScanner();

// Message handler for popup communications (rescan added here)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'rescan') {
    scanner.performComprehensiveScan(request.tabId, request.url);
    sendResponse({ success: true });
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && isValidScanURL(tab.url)) {
    console.log('Valid URL detected, starting initial scan:', tab.url);
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
      console.log('Valid URL on tab activation, starting initial scan:', tab.url);
      scanner.performComprehensiveScan(tab.id, tab.url);
    } else {
      console.log('Skipping scan on tab activation for:', tab.url);
      const key = `scanResult_${activeInfo.tabId}`;
      chrome.storage.local.remove(key);
    }
  });
});

function isValidScanURL(url) {
  if (!url) return false;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return false;
  }
  const skipPatterns = [
    'chrome://', 'chrome-extension://', 'moz-extension://', 'edge-extension://',
    'about:', 'file://', 'data:', 'javascript:', 'localhost', '127.0.0.1', '0.0.0.0'
  ];
  return !skipPatterns.some(pattern => url.includes(pattern));
}