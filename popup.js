document.addEventListener('DOMContentLoaded', () => {
    const statusCard = document.getElementById('status-card');
    const statusIcon = document.getElementById('status-icon');
    const statusMessage = document.getElementById('status-message');
    const domainDisplay = document.getElementById('domain-display');

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (!tab || !tab.id) {
            statusMessage.textContent = 'Cannot access this page.';
            return;
        }

        try {
            const url = new URL(tab.url);
            domainDisplay.textContent = url.hostname;
        } catch (e) {
            domainDisplay.textContent = "Not a valid URL";
        }

        const key = `scanResult_${tab.id}`;
        chrome.storage.local.get([key], (result) => {
            const scanData = result[key];

            if (scanData?.status === 'safe') {
                statusCard.className = 'card-safe';
                statusIcon.src = 'icons/shield.svg';
                statusMessage.textContent = 'Site is Safe';
            } else if (scanData?.status === 'dangerous') {
                statusCard.className = 'card-danger';
                statusIcon.src = 'icons/alert-triangle.svg';
                const threatType = scanData.threat.toLowerCase().replace("_", " ");
                statusMessage.textContent = `Warning: ${threatType}`;
            } else {
                statusCard.className = 'card-neutral';
                statusIcon.src = 'icons/loader.svg';
                statusMessage.textContent = 'Not Scanned Yet';
            }
        });
    });
});