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

    const ipqsRes = await getIPQualityScore(ip);
    resultBox.innerHTML += createResultHTML("IPQualityScore", "https://www.ipqualityscore.com/templates/frontend/img/logo_light.svg", ipqsRes);


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
  

// function createResultHTML(name, iconUrl, result) {
//   return `
//     <div class="source">
//       <img src="${iconUrl}" alt="${name}"> 
//       <span>${name}: <span class="${result.statusClass}">${result.text}</span></span>
//     </div>`;
// }

async function getVirusTotal(ip) {
    try {
      const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
        headers: { "x-apikey": "36598ab5e55fbb431ae562cc6018d94460587bdc49fdb7ada622ca072f917b38" }
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
  
      return {
        text: malicious > 0 ? `${malicious} engines flagged this IP` : "Clean",
        statusClass: malicious > 0 ? "status-bad" : "status-good",
        extraInfo: `<strong>Country:</strong> ${country} <img src="${flag}" alt="${country}"><br><strong>ISP:</strong> ${isp}<br><strong>Last Analysis:</strong> ${date}<br>`
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
//   try {
//     const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
//       headers: { "x-apikey": "36598ab5e55fbb431ae562cc6018d94460587bdc49fdb7ada622ca072f917b38" }
//     });
//     const data = await res.json();
//     const malicious = data.data.attributes.last_analysis_stats.malicious;
//     return {
//       text: malicious > 0 ? `${malicious} engines flagged this IP` : "Clean",
//       statusClass: malicious > 0 ? "status-bad" : "status-good"
//     };
//   } catch {
//     return { text: "Error fetching", statusClass: "status-bad" };
//   }
// }

async function getAbuseDB(ip) {
  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
      headers: {
        "Key": "ae3d1bab448972cb7bbb1640b0ebe0310fe6b73904e7d7435963c985f9f27877dfc8779f71f272be",
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


function getIPQualityScore(ip) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { action: "getIPQualityScore", ip },
        (response) => {
          if (response && response.success) {
            const data = response.data;
            resolve({
              text: data.fraud_score > 75 ? `High Risk: ${data.fraud_score}/100` : `Risk Score: ${data.fraud_score}/100`,
              statusClass: data.fraud_score > 75 ? "status-bad" : "status-good",
              extraInfo: `VPN: ${data.vpn ? "Yes" : "No"}<br>
                          Proxy: ${data.proxy ? "Yes" : "No"}<br>
                          TOR: ${data.tor ? "Yes" : "No"}<br>
                          Bot: ${data.bot_status ? "Yes" : "No"}<br>
                          ISP: ${data.ISP || "Unknown"}<br>
                          Country: ${data.country_code || "N/A"} <img src="https://flagsapi.com/${data.country_code}/flat/24.png" alt="flag">`
            });
          } else {
            resolve({
              text: "Error fetching",
              statusClass: "status-bad",
              extraInfo: "No additional data"
            });
          }
        }
      );
    });
  }
  