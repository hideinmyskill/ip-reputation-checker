async function loadProxyCheckKey() {
  const configURL = chrome.runtime.getURL("config.json");
  const res = await fetch(configURL);
  const config = await res.json();
  return config.ProxyCheck_API_KEY;
}


chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
  if (req.action === "proxyCheck") {
    
    loadProxyCheckKey().then(apiKey => {
      const url = `https://proxycheck.io/v2/${req.ip}?key=${apiKey}&vpn=1&asn=1&node=1&risk=1&_=${Date.now()}`;

      console.log("Fetching from ProxyCheck.io:", url);

      fetch(url)
        .then(res => res.json())
        .then(data => {
          console.log("ProxyCheck response:", data);
          sendResponse({ success: true, data });
        })
        .catch(err => {
          console.error("Fetch error:", err);
          sendResponse({ success: false, error: err.message });
        });
    }).catch(err => {
      console.error("Key load error:", err);
      sendResponse({ success: false, error: "Failed to load API key" });
    });

    return true; // Keeps message channel open
  }
});

console.log("im working");