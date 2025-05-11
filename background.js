chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getIPQualityScore") {
      const ip = request.ip;
      const apiKey = "ieoKLDoxKZwJjc7j01oe2zfDQo6JRZd7"; // Replace with your real API key
      const url = `https://ipqualityscore.com/api/json/ip/${apiKey}/${ip}`;
  
      fetch(url)
        .then(res => res.json())
        .then(data => sendResponse({ success: true, data }))
        .catch(error => sendResponse({ success: false, error: error.message }));
  
      return true; // Required for async response
    }
  });
  