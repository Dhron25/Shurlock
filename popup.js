document.addEventListener('DOMContentLoaded', () => {
    const statusCard = document.getElementById('status-card');
    const statusIconContainer = document.getElementById('status-icon-container');
    const statusIcon = document.getElementById('status-icon');
    const statusTitle = document.getElementById('status-title');
    const statusBrief = document.getElementById('status-brief');
    const domainDisplay = document.getElementById('domain-display');
    const scanTime = document.getElementById('scan-time');
    const riskFill = document.getElementById('risk-fill');
    
    // Quick stats elements
    const safeBrowsingStatus = document.getElementById('safe-browsing-status');
    const sslStatus = document.getElementById('ssl-status');
    const domainStatus = document.getElementById('domain-status');
    
    // Action buttons
    const detailedReportBtn = document.getElementById('detailed-report-btn');
    const rescanBtn = document.getElementById('rescan-btn');
    
    let currentScanData = null;
    let currentTabId = null;

    // Button event listeners
    detailedReportBtn.addEventListener('click', generateDetailedReport);
    rescanBtn.addEventListener('click', performRescan);

    initializeScanner();
   
    function initializeScanner() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (!tab || !tab.id) {
            showError('Cannot access this page.');
            return;
        }

       
        if (!tab.url || (!tab.url.startsWith('http://') && !tab.url.startsWith('https://'))) {
            showError('This extension only works on web pages (HTTP/HTTPS).');
            return;
        }

        currentTabId = tab.id;
        
        try {
            const url = new URL(tab.url);
            domainDisplay.textContent = url.hostname;
        } catch (e) {
            domainDisplay.textContent = "Invalid URL";
            showError('Invalid URL format.');
            return;
        }

        loadScanResults(tab.id);
    });
}

    function loadScanResults(tabId) {
        const key = `scanResult_${tabId}`;
        
        chrome.storage.local.get([key], (result) => {
            const scanData = result[key];
            currentScanData = scanData;

            if (!scanData) {
                showScanning();
                return;
            }

            updateUI(scanData);
        });

        // Listen for real-time updates
        chrome.storage.onChanged.addListener((changes, namespace) => {
            if (namespace === 'local' && changes[key]) {
                currentScanData = changes[key].newValue;
                updateUI(changes[key].newValue);
            }
        });
    }

    function updateUI(scanData) {
        if (!scanData) return;


        // Update main status
        updateMainStatus(scanData);
        
        // Update risk meter
        updateRiskMeter(scanData);
        
        // Update quick stats
        updateQuickStats(scanData);
        
        // Update timestamp
        updateTimestamp(scanData.timestamp);
        
        // Enable/disable buttons
        updateButtonStates(scanData);
    }

    function updateMainStatus(scanData) {
    const { status, brief, overallRisk } = scanData;
    
    // Update status card styling
    statusCard.className = `status-card status-${status}`;
    
    // Update icon and text
    const statusConfig = {
        safe: {
            icon: 'icons/shield-check.svg',
            title: 'Site is Safe',
            iconClass: 'status-safe'
        },
        warning: {
            icon: 'icons/alert-triangle.svg',
            title: 'Security Warning',
            iconClass: 'status-warning'
        },
        dangerous: {
            icon: 'icons/shield-x.svg',
            title: 'Dangerous Site',
            iconClass: 'status-dangerous'
        },
        scanning: {
            icon: 'icons/loader.svg',
            title: 'Scanning...',
            iconClass: 'status-scanning'
        },
        error: {
            icon: 'icons/alert-circle.svg',
            title: 'Scan Error',
            iconClass: 'status-error'
        }
    };

    const config = statusConfig[status] || statusConfig.error;
    statusIcon.src = config.icon;
    statusIconContainer.className = `status-icon-container ${config.iconClass}`;
    statusTitle.textContent = config.title;
    statusBrief.textContent = brief || 'No additional information available.';
}

function showScanning() {
    statusCard.className = 'status-card status-scanning';
    statusIcon.src = 'icons/loader.svg';
    statusIconContainer.className = 'status-icon-container status-scanning';
    statusTitle.textContent = 'Scanning...';
    statusBrief.textContent = 'Performing comprehensive security analysis...';
    
    // Reset quick stats
    safeBrowsingStatus.textContent = 'Checking...';
    sslStatus.textContent = 'Checking...';
    domainStatus.textContent = 'Checking...';
    
    // Reset risk meter
    riskFill.style.width = '0%';
    
    // Disable buttons
    detailedReportBtn.disabled = true;
    rescanBtn.disabled = true;
}

function showError(message) {
    statusCard.className = 'status-card status-error';
    statusIcon.src = 'icons/alert-circle.svg';
    statusIconContainer.className = 'status-icon-container status-error';
    statusTitle.textContent = 'Error';
    statusBrief.textContent = message;
}

    function updateRiskMeter(scanData) {
        const riskScore = scanData.overallRisk || 0;
        const percentage = Math.min(riskScore, 100);
        
        riskFill.style.width = `${percentage}%`;
        riskFill.className = `meter-fill ${getRiskClass(riskScore)}`;
        
        // Add animation
        setTimeout(() => {
            riskFill.style.transition = 'width 0.8s ease-out';
        }, 100);
    }

    function getRiskClass(score) {
        if (score < 30) return 'risk-low';
        if (score < 70) return 'risk-medium';
        return 'risk-high';
    }

    function updateQuickStats(scanData) {
        const { details } = scanData;
        
        // Safe Browsing Status
        if (details.safeBrowsing?.status === 'completed') {
            const isSafe = details.safeBrowsing.data?.safe;
            safeBrowsingStatus.textContent = isSafe ? 'Clean' : 'Threats Found';
            safeBrowsingStatus.className = `stat-value ${isSafe ? 'stat-safe' : 'stat-danger'}`;
        } else {
            safeBrowsingStatus.textContent = 'Checking...';
            safeBrowsingStatus.className = 'stat-value stat-pending';
        }

        // SSL Certificate Status
        if (details.sslCertificate?.status === 'completed') {
            const ssl = details.sslCertificate.data;
            const grade = ssl?.grade || 'Unknown';
            sslStatus.textContent = ssl?.valid ? grade : 'Invalid';
            sslStatus.className = `stat-value ${ssl?.valid ? 'stat-safe' : 'stat-warning'}`;
        } else {
            sslStatus.textContent = 'Checking...';
            sslStatus.className = 'stat-value stat-pending';
        }

        // Domain Trust Status
        if (details.domainReputation?.status === 'completed') {
            const trust = details.domainReputation.data?.trustScore || 0;
            domainStatus.textContent = `${trust}%`;
            domainStatus.className = `stat-value ${getTrustClass(trust)}`;
        } else {
            domainStatus.textContent = 'Checking...';
            domainStatus.className = 'stat-value stat-pending';
        }
    }

    function getTrustClass(score) {
        if (score >= 80) return 'stat-safe';
        if (score >= 60) return 'stat-warning';
        return 'stat-danger';
    }

    function updateTimestamp(timestamp) {
        if (timestamp) {
            const date = new Date(timestamp);
            const timeString = date.toLocaleTimeString([], { 
                hour: '2-digit', 
                minute: '2-digit' 
            });
            scanTime.textContent = `Last scanned: ${timeString}`;
        }
    }

    function updateButtonStates(scanData) {
        const isComplete = scanData.status !== 'scanning';
        detailedReportBtn.disabled = !isComplete;
        rescanBtn.disabled = scanData.status === 'scanning';
    }

    function generateDetailedReport() {
        if (!currentScanData) {
            showNotification('No scan data available for report generation.', 'error');
            return;
        }

        try {
            const report = createDetailedReport(currentScanData);
            downloadReport(report);
        } catch (error) {
            console.error('Error generating report:', error);
            showNotification('Failed to generate report. Please try again.', 'error');
        }
    }

    function createDetailedReport(scanData) {
        const reportData = {
            title: 'Shurlock Security Report',
            url: scanData.url,
            domain: domainDisplay.textContent,
            timestamp: new Date(scanData.timestamp).toLocaleString(),
            overallRisk: scanData.overallRisk,
            status: scanData.status,
            brief: scanData.brief,
            details: formatReportDetails(scanData.details)
        };

        return generateHTMLReport(reportData);
    }

    function formatReportDetails(details) {
        const formatted = {};

        // Safe Browsing
        if (details.safeBrowsing?.data) {
            const sb = details.safeBrowsing.data;
            formatted.safeBrowsing = {
                status: sb.safe ? 'Clean' : 'Threats Detected',
                threats: sb.threats?.map(t => ({
                    type: t.type,
                    description: formatThreatType(t.type)
                })) || []
            };
        }

        // SSL Certificate
        if (details.sslCertificate?.data) {
            const ssl = details.sslCertificate.data;
            formatted.sslCertificate = {
                status: ssl.valid ? 'Valid' : 'Invalid',
                grade: ssl.grade || 'Unknown',
                protocol: ssl.details?.protocol || 'Unknown',
                warnings: ssl.details?.warnings || []
            };
        }

        // Domain Reputation
        if (details.domainReputation?.data) {
            const domain = details.domainReputation.data;
            formatted.domainReputation = {
                trustScore: domain.trustScore || 0,
                analysis: domain.analysis || 'No analysis available',
                riskFactors: domain.riskFactors || []
            };
        }

        // URL Analysis
        if (details.urlAnalysis?.data) {
            const url = details.urlAnalysis.data;
            formatted.urlAnalysis = {
                riskScore: url.riskScore || 0,
                length: url.details?.length || 0,
                recommendations: url.recommendations || []
            };
        }

        // Security Headers
        if (details.securityHeaders?.data) {
            const headers = details.securityHeaders.data;
            formatted.securityHeaders = {
                score: headers.score || 0,
                present: headers.present || [],
                missing: headers.missing || []
            };
        }

        return formatted;
    }

    function formatThreatType(type) {
        const descriptions = {
            'MALWARE': 'Malicious software that can harm your device',
            'SOCIAL_ENGINEERING': 'Attempts to trick users into revealing information',
            'UNWANTED_SOFTWARE': 'Programs that may be unwanted or harmful',
            'POTENTIALLY_HARMFUL_APPLICATION': 'Apps that may pose security risks'
        };
        return descriptions[type] || type;
    }

    function generateHTMLReport(data) {
        return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${data.title}</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 40px; 
            background: #f5f5f5; 
            color: #333;
        }
        .report-container { 
            background: white; 
            padding: 40px; 
            border-radius: 10px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
            max-width: 800px;
            margin: 0 auto;
        }
        .header { 
            border-bottom: 2px solid #e0e0e0; 
            padding-bottom: 20px; 
            margin-bottom: 30px; 
        }
        .header h1 { 
            color: #2c3e50; 
            margin: 0;
            font-size: 28px;
        }
        .header .subtitle { 
            color: #7f8c8d; 
            font-size: 14px; 
            margin-top: 5px;
        }
        .section { 
            margin-bottom: 30px; 
        }
        .section h2 { 
            color: #34495e; 
            border-left: 4px solid #3498db; 
            padding-left: 15px;
            font-size: 20px;
        }
        .risk-indicator { 
            display: inline-block; 
            padding: 8px 16px; 
            border-radius: 20px; 
            color: white; 
            font-weight: bold;
            font-size: 14px;
        }
        .risk-low { background: #27ae60; }
        .risk-medium { background: #f39c12; }
        .risk-high { background: #e74c3c; }
        .detail-grid { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 20px; 
            margin-top: 20px; 
        }
        .detail-item { 
            padding: 20px; 
            background: #f8f9fa; 
            border-radius: 8px;
            border: 1px solid #e9ecef;
        }
        .detail-item h3 { 
            margin-top: 0; 
            color: #2c3e50;
            font-size: 16px;
        }
        .status-safe { color: #27ae60; font-weight: bold; }
        .status-warning { color: #f39c12; font-weight: bold; }
        .status-danger { color: #e74c3c; font-weight: bold; }
        .footer { 
            margin-top: 40px; 
            padding-top: 20px; 
            border-top: 1px solid #e0e0e0; 
            font-size: 12px; 
            color: #7f8c8d;
            text-align: center;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .summary-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #e9ecef;
        }
        .summary-item strong {
            color: #2c3e50;
        }
        ul {
            padding-left: 20px;
        }
        li {
            margin-bottom: 5px;
        }
        @media (max-width: 600px) {
            .detail-grid {
                grid-template-columns: 1fr;
            }
            body {
                margin: 20px;
            }
            .report-container {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="report-container">
        <div class="header">
            <h1>Shurlock Security Report</h1>
            <div class="subtitle">Generated on ${data.timestamp}</div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <strong>Domain:</strong><br>${data.domain}
                </div>
                <div class="summary-item">
                    <strong>Overall Risk:</strong><br>
                    <span class="risk-indicator risk-${data.overallRisk < 30 ? 'low' : data.overallRisk < 70 ? 'medium' : 'high'}">
                        ${data.overallRisk}% Risk
                    </span>
                </div>
                <div class="summary-item">
                    <strong>Status:</strong><br>
                    <span class="status-${data.status}">${data.status.toUpperCase()}</span>
                </div>
            </div>
            <p><strong>Full URL:</strong> ${data.url}</p>
            <p><strong>Analysis Summary:</strong> ${data.brief}</p>
        </div>

        ${generateDetailSections(data.details)}

        <div class="footer">
            <p>This report was generated by Shurlock Security Scanner extension.<br>
            For more information about security findings, consult cybersecurity professionals.</p>
        </div>
    </div>
</body>
</html>
        `;
    }

    function generateDetailSections(details) {
        let sections = '';

        if (details.safeBrowsing) {
            sections += `
                <div class="section">
                    <h2>Safe Browsing Analysis</h2>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <h3>Status</h3>
                            <p><strong>Result:</strong> <span class="status-${details.safeBrowsing.status === 'Clean' ? 'safe' : 'danger'}">${details.safeBrowsing.status}</span></p>
                        </div>
                        <div class="detail-item">
                            <h3>Threat Analysis</h3>
                            ${details.safeBrowsing.threats && details.safeBrowsing.threats.length > 0 ? 
                                `<p><strong>Threats Found:</strong></p><ul>${details.safeBrowsing.threats.map(t => `<li><strong>${t.type}:</strong> ${t.description}</li>`).join('')}</ul>` : 
                                '<p>No threats detected by Google Safe Browsing</p>'
                            }
                        </div>
                    </div>
                </div>
            `;
        }

        if (details.sslCertificate) {
            sections += `
                <div class="section">
                    <h2>SSL Certificate Analysis</h2>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <h3>Certificate Status</h3>
                            <p><strong>Status:</strong> <span class="status-${details.sslCertificate.status === 'Valid' ? 'safe' : 'warning'}">${details.sslCertificate.status}</span></p>
                            <p><strong>Grade:</strong> ${details.sslCertificate.grade}</p>
                            <p><strong>Protocol:</strong> ${details.sslCertificate.protocol}</p>
                        </div>
                        <div class="detail-item">
                            <h3>Security Assessment</h3>
                            ${details.sslCertificate.warnings && details.sslCertificate.warnings.length > 0 ? 
                                `<p><strong>Warnings:</strong></p><ul>${details.sslCertificate.warnings.map(w => `<li>${w}</li>`).join('')}</ul>` :
                                '<p>No SSL certificate warnings detected</p>'
                            }
                        </div>
                    </div>
                </div>
            `;
        }

        if (details.domainReputation) {
            sections += `
                <div class="section">
                    <h2>Domain Reputation Analysis</h2>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <h3>Trust Score</h3>
                            <p><strong>Score:</strong> <span class="status-${details.domainReputation.trustScore >= 80 ? 'safe' : details.domainReputation.trustScore >= 60 ? 'warning' : 'danger'}">${details.domainReputation.trustScore}%</span></p>
                            <p><strong>Analysis:</strong> ${details.domainReputation.analysis}</p>
                        </div>
                        <div class="detail-item">
                            <h3>Risk Factors</h3>
                            ${details.domainReputation.riskFactors && details.domainReputation.riskFactors.length > 0 ? 
                                `<ul>${details.domainReputation.riskFactors.map(f => `<li>${f}</li>`).join('')}</ul>` :
                                '<p>No significant risk factors detected</p>'
                            }
                        </div>
                    </div>
                </div>
            `;
        }

        if (details.urlAnalysis) {
            sections += `
                <div class="section">
                    <h2>URL Structure Analysis</h2>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <h3>Risk Assessment</h3>
                            <p><strong>Risk Score:</strong> <span class="status-${details.urlAnalysis.riskScore < 30 ? 'safe' : details.urlAnalysis.riskScore < 70 ? 'warning' : 'danger'}">${details.urlAnalysis.riskScore}%</span></p>
                            <p><strong>URL Length:</strong> ${details.urlAnalysis.length} characters</p>
                        </div>
                        <div class="detail-item">
                            <h3>Recommendations</h3>
                            ${details.urlAnalysis.recommendations && details.urlAnalysis.recommendations.length > 0 ? 
                                `<ul>${details.urlAnalysis.recommendations.map(r => `<li>${r}</li>`).join('')}</ul>` :
                                '<p>No URL structure concerns detected</p>'
                            }
                        </div>
                    </div>
                </div>
            `;
        }

        if (details.securityHeaders) {
            sections += `
                <div class="section">
                    <h2>Security Headers Analysis</h2>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <h3>Header Score</h3>
                            <p><strong>Score:</strong> <span class="status-${details.securityHeaders.score >= 80 ? 'safe' : details.securityHeaders.score >= 40 ? 'warning' : 'danger'}">${details.securityHeaders.score}%</span></p>
                            <p><strong>Present Headers:</strong> ${details.securityHeaders.present.length}</p>
                        </div>
                        <div class="detail-item">
                            <h3>Missing Headers</h3>
                            ${details.securityHeaders.missing && details.securityHeaders.missing.length > 0 ? 
                                `<ul>${details.securityHeaders.missing.map(h => `<li>${h}</li>`).join('')}</ul>` :
                                '<p>All recommended security headers are present</p>'
                            }
                        </div>
                    </div>
                </div>
            `;
        }

        return sections;
    }

    function downloadReport(htmlContent) {
        const domain = domainDisplay.textContent;
        const timestamp = new Date().toISOString().slice(0, 10);
        const filename = `shurlock-security-report-${domain}-${timestamp}.html`;
        
        // Show loading state
        detailedReportBtn.disabled = true;
        const originalHTML = detailedReportBtn.innerHTML;
        detailedReportBtn.innerHTML = '<img src="icons/download.svg" alt="Download" class="btn-icon">Generating...';
        
        // Create blob URL and trigger download directly
        try {
            const blob = new Blob([htmlContent], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            
            // Create temporary download link
            const downloadLink = document.createElement('a');
            downloadLink.href = url;
            downloadLink.download = filename;
            downloadLink.style.display = 'none';
            
            document.body.appendChild(downloadLink);
            downloadLink.click();
            document.body.removeChild(downloadLink);
            
            // Clean up
            URL.revokeObjectURL(url);
            
            // Reset button state
            detailedReportBtn.disabled = false;
            detailedReportBtn.innerHTML = originalHTML;
            
            showNotification('Report downloaded successfully!', 'success');
            
        } catch (error) {
            console.error('Download error:', error);
            
            // Reset button state
            detailedReportBtn.disabled = false;
            detailedReportBtn.innerHTML = originalHTML;
            
            showNotification('Download failed. Please try again.', 'error');
        }
    }

    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 10px;
            right: 10px;
            background: ${type === 'success' ? '#27ae60' : type === 'error' ? '#e74c3c' : '#3498db'};
            color: white;
            padding: 12px 16px;
            border-radius: 6px;
            z-index: 1000;
            font-size: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            max-width: 300px;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    function performRescan() {
        if (!currentTabId) return;
        
        showScanning();
        
        // Clear existing scan data
        const key = `scanResult_${currentTabId}`;
        chrome.storage.local.remove(key);
        
        // Trigger new scan
        chrome.tabs.get(currentTabId, (tab) => {
            if (tab.url) {
                chrome.runtime.sendMessage({
                    action: 'rescan',
                    tabId: currentTabId,
                    url: tab.url
                });
            }
        });
    }
});



 
  