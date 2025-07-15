document.addEventListener('DOMContentLoaded', () => {
    const statusCard = document.getElementById('status-card');
    const statusIconContainer = document.getElementById('status-icon-container');
    const statusIcon = document.getElementById('status-icon');
    const statusTitle = document.getElementById('status-title');
    const statusBrief = document.getElementById('status-brief');
    const domainDisplay = document.getElementById('domain-display');
    const scanTime = document.getElementById('scan-time');
    const riskFill = document.getElementById('risk-fill');
    
    const safeBrowsingStatus = document.getElementById('safe-browsing-status');
    const sslStatus = document.getElementById('ssl-status');
    const domainStatus = document.getElementById('domain-status');
    
    const detailedReportBtn = document.getElementById('detailed-report-btn');
    const rescanBtn = document.getElementById('rescan-btn');
    
    let currentScanData = null;
    let currentTabId = null;

    // Button event listeners (will be enabled later)
    // detailedReportBtn.addEventListener('click', generateDetailedReport);
    // rescanBtn.addEventListener('click', performRescan);

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
                // Trigger scan from background if no data
                chrome.tabs.get(tabId, (tab) => {
                    if (tab.url) {
                        chrome.runtime.sendMessage({
                            action: 'rescan', // Re-use rescan action for initial scan
                            tabId: tabId,
                            url: tab.url
                        });
                    }
                });
                return;
            }

            updateUI(scanData); // Basic update function
        });

        // Listen for real-time updates (will be more comprehensive later)
        chrome.storage.onChanged.addListener((changes, namespace) => {
            if (namespace === 'local' && changes[key]) {
                currentScanData = changes[key].newValue;
                updateUI(changes[key].newValue);
            }
        });
    }

    function updateUI(scanData) {
        if (!scanData) return;

        // Only basic status update for this commit
        updateMainStatus(scanData); 
        // Quick stats and risk meter updates are minimal for now
        safeBrowsingStatus.textContent = scanData.details.safeBrowsing?.status === 'completed' ? (scanData.details.safeBrowsing.data?.safe ? 'Clean' : 'Threats') : 'Checking...';
        sslStatus.textContent = scanData.details.sslCertificate?.status === 'completed' ? (scanData.details.sslCertificate.data?.valid ? 'Valid' : 'Invalid') : 'Checking...';
        domainStatus.textContent = scanData.details.domainReputation?.status === 'completed' ? 'Analyzed' : 'Checking...';
        
        riskFill.style.width = `${scanData.overallRisk || 0}%`;
        scanTime.textContent = scanData.timestamp ? `Last scanned: ${new Date(scanData.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : '--';
        
        updateButtonStates(scanData);
    }

    function updateMainStatus(scanData) {
        const { status, brief } = scanData;
        
        statusCard.className = `status-card status-${status}`;
        
        // Basic status config
        const statusConfig = {
            safe: { icon: 'icons/shield-check.svg', title: 'Site is Safe', iconClass: 'status-safe' },
            warning: { icon: 'icons/alert-triangle.svg', title: 'Security Warning', iconClass: 'status-warning' },
            dangerous: { icon: 'icons/shield-x.svg', title: 'Dangerous Site', iconClass: 'status-dangerous' },
            scanning: { icon: 'icons/loader.svg', title: 'Scanning...', iconClass: 'status-scanning' },
            error: { icon: 'icons/alert-circle.svg', title: 'Scan Error', iconClass: 'status-error' }
        };

        const config = statusConfig[status] || statusConfig.scanning; // Default to scanning if unknown
        statusIcon.src = config.icon;
        statusIconContainer.className = `status-icon-container ${config.iconClass}`;
        statusTitle.textContent = config.title;
        statusBrief.textContent = brief || 'Performing analysis...';
    }

    function showScanning() {
        statusCard.className = 'status-card status-scanning';
        statusIcon.src = 'icons/loader.svg';
        statusIconContainer.className = 'status-icon-container status-scanning';
        statusTitle.textContent = 'Scanning...';
        statusBrief.textContent = 'Performing comprehensive security analysis...';
        
        safeBrowsingStatus.textContent = 'Checking...';
        sslStatus.textContent = 'Checking...';
        domainStatus.textContent = 'Checking...';
        
        riskFill.style.width = '0%';
        
        detailedReportBtn.disabled = true;
        rescanBtn.disabled = true;
    }

    function showError(message) {
        statusCard.className = 'status-card status-error';
        statusIcon.src = 'icons/alert-circle.svg';
        statusIconContainer.className = 'status-icon-container status-error';
        statusTitle.textContent = 'Error';
        statusBrief.textContent = message;
        detailedReportBtn.disabled = true;
        rescanBtn.disabled = true;
    }

    function updateButtonStates(scanData) {
        const isComplete = scanData.status !== 'scanning';
        detailedReportBtn.disabled = !isComplete;
        rescanBtn.disabled = scanData.status === 'scanning';
    }
    
    // Detailed report and rescan functions will be fully implemented in the next commit
    // function generateDetailedReport() { /* ... */ }
    // function performRescan() { /* ... */ }
    // function showNotification() { /* ... */ }
});