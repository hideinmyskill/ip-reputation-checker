document.getElementById("checkBtn").addEventListener("click", checkIPs);

async function checkIPs() {
  const input = document.getElementById("ipInput").value.trim();
  const ips = input.split(/\s+/);
  const resultsContainer = document.getElementById("results");
  resultsContainer.innerHTML = "";

  for (const ip of ips) {
    const resultBox = document.createElement("div");
    resultBox.className = "result-box";
    resultBox.innerHTML = `<div class="ip-header">Checking IP: ${ip}</div>`;

    const vtRes = await getVirusTotal(ip);
    resultBox.innerHTML += createResultHTML("VirusTotal", "/icons/VTicon.png", vtRes);

    const abuseRes = await getAbuseDB(ip);
    resultBox.innerHTML += createResultHTML("AbuseIPDB", "https://www.abuseipdb.com/favicon.ico", abuseRes);

    const proxyRes = await getProxyCheck(ip);
    resultBox.innerHTML += createResultHTML("ProxyCheck.io", "https://proxycheck.io/favicon.ico", proxyRes);

    resultsContainer.appendChild(resultBox);
  }
}

function createResultHTML(name, iconUrl, result) {
    return `
      <div class="source">
        <img src="${iconUrl}" alt="${name}"> 
        <span>${name}: <span class="${result.statusClass}">${result.text}</span></span>
      </div>
      <div style="margin-left: 28px; font-size: 13px; color: #ccc;">${result.extraInfo || ""}</div>`;
  }
  
async function getVirusTotal(ip) {
    try {
      const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
        headers: {
          "x-apikey": "7dac5564f35df3bc9d6ae5bca3205612c8e4f59f76a62188e2293de31aa17f24"
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
        text: malicious > 0 ? `${malicious} engines flagged this IP` : "Clean",
        statusClass: malicious > 0 ? "status-bad" : "status-good",
        extraInfo: `
          <strong>Country:</strong> ${country} <img src="${flag}" alt="${country}"><br>
          <strong>ISP:</strong> ${isp}<br>
          <strong>Last Analysis:</strong> ${date}<br>
          <strong>Tags:</strong>
          <ul style="margin-left: 1rem; padding-left: 0.5rem; font-size: 12px;">
            ${tagList}
          </ul>
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
  
  
// async function getVirusTotal(ip) {
//     try {
//       const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
//         headers: { "x-apikey": "36598ab5e55fbb431ae562cc6018d94460587bdc49fdb7ada622ca072f917b38" }
//       });
//       const data = await res.json();
//       const attributes = data.data.attributes;
//       const malicious = attributes.last_analysis_stats.malicious;
//       const isp = attributes.as_owner || "Unknown";
//       const country = attributes.country || "N/A";
//       const flag = country ? `https://flagsapi.com/${country}/flat/24.png` : "";
//       const date = attributes.last_analysis_date 
//         ? new Date(attributes.last_analysis_date * 1000).toLocaleString() 
//         : "N/A";
  
//       return {
//         text: malicious > 0 ? `${malicious} engines flagged this IP` : "Clean",
//         statusClass: malicious > 0 ? "status-bad" : "status-good",
//         extraInfo: `<strong>Country:</strong> ${country} <img src="${flag}" alt="${country}"><br><strong>ISP:</strong> ${isp}<br><strong>Last Analysis:</strong> ${date}<br>`
//       };
//     } catch {
//       return {
//         text: "Error fetching",
//         statusClass: "status-bad",
//         extraInfo: "No additional data"
//       };
//     }
//   }

async function getAbuseDB(ip) {
  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
      headers: {
        "Key": "34be141c145e33e2b96236db598a5c466f1129cb3c2446d8d4a383b744ebe7a7eb49c4e2728e7df1",
        "Accept": "application/json"
      }
    });
    const data = await res.json();
    const score = data.data.abuseConfidenceScore;
    return {
      text: `Abuse Score: ${score}/100`,
      statusClass: score > 50 ? "status-bad" : "status-good"
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
