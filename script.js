document.getElementById("checkBtn").addEventListener("click", checkIPs);

async function checkIPs() {
  const input = document.getElementById("ipInput").value.trim();
  const ips = input.split(/\s+/);
  const resultsBody = document.getElementById("resultsBody");

  // Clear previous results from display and storage
  resultsBody.innerHTML = "";
  chrome.storage.local.remove("savedResults");

  let storedRows = [];

  for (const ip of ips) {
    const vtRes = await getVirusTotal(ip);
    const abuseRes = await getAbuseDB(ip);
    const proxyRes = await getProxyCheck(ip);

    const rowHTML = `
      <tr>
        <td><strong>${ip}</strong></td>
        <td>${formatCell(vtRes)}</td>
        <td>${formatCell(abuseRes)}</td>
        <td>${formatCell(proxyRes)}</td>
      </tr>
    `;

    storedRows.push(rowHTML);
    resultsBody.insertAdjacentHTML("beforeend", rowHTML);
  }

  chrome.storage.local.set({ savedResults: storedRows });

  // Clear input after search
  document.getElementById("ipInput").value = "";
}

function formatCell(result) {
  return `
    <div style="color: ${result.statusClass === 'status-bad' ? '#ffaaaa' : '#aaffaa'}; font-size: 10px;">
      ${result.text}<br>
      <span style="font-size: 10px; color: #ccc;">${result.extraInfo || ""}</span>
    </div>
  `;
}

async function getVirusTotal(ip) {
    try {
      const config = await fetch('./config.json').then(res => res.json());

      const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
        headers: {
          "x-apikey": config.VT_API_KEY
        }
      });
  
      const data = await res.json();
      const attributes = data.data.attributes;
  
      const malicious = attributes.last_analysis_stats.malicious;
      const isp = attributes.as_owner || "Unknown";
      const country = attributes.country || "N/A";
      const flag = country ? `https://flagsapi.com/${country}/flat/24.png` : "";
      const date = attributes.last_analysis_date
        ? new Date(attributes.last_analysis_date * 1000).toLocaleString()
        : "N/A";
  
      const tags = attributes.tags || [];
      const tagList = tags.length > 0 ? tags.map(t => `<li>${t}</li>`).join("") : "<li>None</li>";
  
      return {
        text: malicious > 0 ? `Status: ${malicious} engines flagged this IP` : "Status: Clean",
        statusClass: malicious > 0 ? "status-bad" : "status-good",
        extraInfo: `
          <img src="${flag}" alt="${country}" style="width: 30px; height: auto; display: block; margin: 0 auto;">
          <strong>Country:</strong> ${country}<br>
          <strong>ISP:</strong> ${isp}<br>
          <strong>Last Analysis:</strong> ${date}<br>
        `
      };
    } catch {
      return {
        text: "Error fetching",
        statusClass: "status-bad",
        extraInfo: "No additional data"
      };
    }
  }

async function getAbuseDB(ip) {
  try {
    const config1 = await fetch('./config.json').then(res => res.json());
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
      headers: {
        "Key": config1.AbuseDB_API_KEY,
        "Accept": "application/json"
      }
    });
    const data = await res.json();
    const score = data.data.abuseConfidenceScore;
    const domain = data.data.domain;
    const usageType = data.data.usageType;
    console.log("abuseDB:", data)
    return {
      text: `Abuse Score: ${score}/100`,
      statusClass: score > 50 ? "status-bad" : "status-good",
      extraInfo: `
        <strong>Domain:</strong> ${domain}<br>
        <strong>Usage:</strong> ${usageType}`
    };
  } catch {
    return { text: "Error fetching", statusClass: "status-bad" };
  }
}
  
function getProxyCheck(ip) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: "proxyCheck", ip }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success) {
        console.error("ProxyCheck Error:", chrome.runtime.lastError || response?.error || "No response");
        resolve({
          text: "Error fetching",
          statusClass: "status-bad",
          extraInfo: "Unable to retrieve ProxyCheck data"
        });
        return;
      }

      const res = response.data[ip];
      if (!res) {
        resolve({
          text: "No data returned",
          statusClass: "status-bad",
          extraInfo: "Invalid IP or response format"
        });
        return;
      }

      console.log(res)
      const proxyDetected = res.proxy === "yes";
      const vpnType = res.type || "Unknown";
      const provider = res.provider || "N/A";
      const operator = res.operator || {};
      const operatorName = operator.name || "Unknown";
      const operatorUrl = operator.url || "#";
      const anonymity = operator.anonymity || "N/A";
      const popularity = operator.popularity || "N/A";
      const protocols = operator.protocols ? operator.protocols.join(", ") : "N/A";

      const policies = operator.policies || {};
      const policyHTML = Object.entries(policies)
        .map(([key, value]) => `<li><strong>${key.replace(/_/g, " ")}:</strong> ${value}</li>`)
        .join("");

      resolve({
        text: proxyDetected ? `Proxy detected (${vpnType})` : "No Proxy",
        statusClass: proxyDetected ? "status-bad" : "status-good",
        extraInfo: `
          <strong>Provider:</strong> ${provider}<br>
          <strong>Operator:</strong> ${operatorName}<br>
          <strong>Anonymity:</strong> ${anonymity}<br>
          <strong>Popularity:</strong> ${popularity}<br>
          <strong>Protocols:</strong> ${protocols}<br>
        `
      });
    });
  });
}

// add stored rows to popup
document.addEventListener("DOMContentLoaded", () => {
  const resultsBody = document.getElementById("resultsBody");

  chrome.storage.local.get("savedResults", (data) => {
    if (data.savedResults && Array.isArray(data.savedResults)) {
      resultsBody.innerHTML = data.savedResults.join("");
    }
  });

  document.getElementById("clearBtn").addEventListener("click", () => {
    chrome.storage.local.remove("savedResults", () => {
      resultsBody.innerHTML = "";
    });
  });
});
