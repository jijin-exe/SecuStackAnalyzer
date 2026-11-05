// Listens to all network traffic and saves the HTTP headers for the current tab
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    // Only capture the headers for the main website document, not images or scripts
    if (details.type === 'main_frame') {
      chrome.storage.session.set({ [details.tabId]: details.responseHeaders });
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Cleans up the memory when you close a tab
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(tabId.toString());
});