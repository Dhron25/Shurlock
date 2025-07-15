const API_KEY = 'AIzaSyBz4ZT6Z05ezubMfJYOrNVaJVeBqE3I3sE';
const API_URL = 
`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;

async function checkUrl(tabId, url) {
    if (!url || !url.startsWith('http')) {
        return;
      }
    
      try {
        const response = await fetch(API_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            client: {
              clientId: 'shurlock-extension',
              clientVersion: '1.0.0',
            },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url: url }],
            },
          }),
        });
    
        const data = await response.json();
        let result = {};
    
        if (data.matches && data.matches.length > 0) {
          
          console.log('Threat found:', data.matches[0].threatType);
          result = { status: 'dangerous', threat: data.matches[0].threatType };
          chrome.action.setIcon({ path: "images/icon-danger-48.png", tabId: tabId });
        } else {
        
          console.log('Site is safe.');
          result = { status: 'safe' };
          chrome.action.setIcon({ path: "images/icon-safe-48.png", tabId: tabId });
        }
    
       
        const key = `scanResult_${tabId}`;
        chrome.storage.local.set({ [key]: result });
    
      } catch (error) {
        console.error('Error checking URL:', error);
        
      }
    }

    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {

      if (changeInfo.status === 'complete' && tab.url) {
        checkUrl(tabId, tab.url);
      }
    });
    
   
    chrome.tabs.onActivated.addListener(activeInfo => {
        chrome.tabs.get(activeInfo.tabId, (tab) => {
            if (tab.url) {
                checkUrl(tab.id, tab.url);
            }
        });
    });

