chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "proxyCheck") {
      fetch(`https://proxycheck.io/v2/${req.ip}?key=public-oh7416-26yxkt-064508&vpn=1`)
        .then(r => r.json())
        .then(d => sendResponse({ success: true, data: d }))
        .catch(e => sendResponse({ success: false, error: e.message }));
      return true;
    }
  });
  
  console.log("im working")