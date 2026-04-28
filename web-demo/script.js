const output = document.getElementById("output");
const scanButtons = document.querySelectorAll(".scan-btn[data-scan]");
const resultsPanel = document.getElementById("resultsPanel");
const reports = document.getElementById("reports");
const postScanPrompt = document.getElementById("postScanPrompt");
const resetBtn = document.getElementById("resetBtn");
const terminalScreen = document.getElementById("terminalScreen");
const meterText = document.getElementById("meterText");
const meterBar = document.getElementById("meterBar");

const reportModal = document.getElementById("reportModal");
const modalTitle = document.getElementById("modalTitle");
const modalBody = document.getElementById("modalBody");
const closeModal = document.getElementById("closeModal");

let isScanning = false;
let reportsCache = {};

const sampleResults = {
  quick: [
    { port: 631, service: "ipp", version: "CUPS 2.4", severity: "None", cve: "No known CVEs" }
  ],
  full: [
    { port: 22, service: "ssh", version: "OpenSSH 9.3", severity: "Low", cve: "CVE-2023-38408" },
    { port: 80, service: "http", version: "nginx 1.24", severity: "Medium", cve: "CVE-2024-32760" },
    { port: 443, service: "https", version: "OpenSSL 3.0.2", severity: "High", cve: "CVE-2023-5363" },
    { port: 3306, service: "mysql", version: "MySQL 8.0", severity: "Critical", cve: "CVE-2024-21096" }
  ],
  custom: [
    { port: 53, service: "dns", version: "BIND 9.18", severity: "Low", cve: "CVE-2023-50387" },
    { port: 443, service: "https", version: "OpenSSL 3.0.2", severity: "High", cve: "CVE-2023-5363" },
    { port: 631, service: "ipp", version: "CUPS 2.4", severity: "None", cve: "No known CVEs" }
  ]
};

const sequences = {
  quick: [
    { text: "[INFO] Scanning with Quick Scan...", cls: "meta", progress: 15 },
    { text: "[INFO] Checking common service ports (top 100)", cls: "info", progress: 45 },
    { text: "[OK] Scanning... done", cls: "success", progress: 75 },
    { text: "[PORT] Port 631 | Service: ipp | Version: CUPS 2.4 | No known CVEs", cls: "success", progress: 90 },
    { text: "[REPORT] Generating reports...", cls: "warn", progress: 98 },
    { text: "[OK] Reports saved.", cls: "success", progress: 100 }
  ],
  full: [
    { text: "[INFO] Scanning with Full Scan...", cls: "meta", progress: 7 },
    { text: "[INFO] Port sweep started for range 1-65535", cls: "info", progress: 33 },
    { text: "[INFO] Fingerprinting discovered services", cls: "info", progress: 59 },
    { text: "[WARN] High-risk signatures found", cls: "warn", progress: 78 },
    { text: "[OK] Scanning... done", cls: "success", progress: 90 },
    { text: "[REPORT] Generating reports...", cls: "warn", progress: 97 },
    { text: "[OK] Reports saved.", cls: "success", progress: 100 }
  ],
  custom: [
    { text: "[INFO] Scanning with Custom Range...", cls: "meta", progress: 14 },
    { text: "[INFO] Simulated custom profile: ports 20-1024", cls: "info", progress: 52 },
    { text: "[OK] Scanning... done", cls: "success", progress: 80 },
    { text: "[REPORT] Generating reports...", cls: "warn", progress: 96 },
    { text: "[OK] Reports saved.", cls: "success", progress: 100 }
  ]
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function setButtons(disabled) {
  scanButtons.forEach((button) => {
    button.disabled = disabled;
  });
}

function setMeter(progress, label) {
  meterBar.style.width = `${progress}%`;
  meterText.textContent = `${label} (${progress}%)`;
}

async function typeLine(text, cls = "info") {
  const line = document.createElement("p");
  line.className = `line ${cls}`;
  line.textContent = "";
  output.appendChild(line);

  for (const ch of text) {
    line.textContent += ch;
    terminalScreen.scrollTop = terminalScreen.scrollHeight;
    await sleep(12);
  }

  line.classList.add("complete");
  await sleep(140);
}

function badgeClass(level) {
  return `badge-${level.toLowerCase()}`;
}

function renderResults(items) {
  resultsPanel.innerHTML = "";
  resultsPanel.classList.remove("empty");

  items.forEach((item) => {
    const el = document.createElement("article");
    el.className = "finding";
    el.innerHTML = `
      <p class="line"><strong>Port:</strong> ${item.port}</p>
      <p class="line"><strong>Service:</strong> ${item.service}</p>
      <p class="line"><strong>Version:</strong> ${item.version}</p>
      <p class="line"><strong>CVE:</strong> ${item.cve}</p>
      <p class="line"><strong>Severity:</strong> <span class="badge ${badgeClass(item.severity)}">${item.severity}</span></p>
    `;
    resultsPanel.appendChild(el);
  });
}

function getTimestamp() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

function renderReports(items, scanMode) {
  const timestamp = getTimestamp();
  const txtName = `scan_${timestamp}.txt`;
  const jsonName = `scan_${timestamp}.json`;

  reportsCache = {
    [txtName]: [
      "PORT OVERSEER REPORT",
      `Mode: ${scanMode.toUpperCase()}`,
      `Generated: ${timestamp}`,
      "",
      ...items.map((i) => `- ${i.port}/tcp ${i.service} ${i.version} | ${i.cve} | ${i.severity.toUpperCase()}`)
    ].join("\n"),
    [jsonName]: JSON.stringify({
      mode: scanMode,
      generated_at: timestamp,
      host: "demo-target.local",
      findings: items
    }, null, 2)
  };

  reports.classList.remove("empty");
  reports.innerHTML = "";

  Object.keys(reportsCache).forEach((fileName) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "report-link";
    btn.textContent = fileName;
    btn.addEventListener("click", () => openModal(fileName));
    reports.appendChild(btn);
  });
}

function openModal(fileName) {
  modalTitle.textContent = fileName;
  modalBody.textContent = reportsCache[fileName] || "No report data available.";
  reportModal.classList.remove("hidden");
  reportModal.setAttribute("aria-hidden", "false");
}

function closeModalView() {
  reportModal.classList.add("hidden");
  reportModal.setAttribute("aria-hidden", "true");
}

async function runScan(mode) {
  if (isScanning) {
    await typeLine("[WARN] A scan is already running. Wait for completion.", "warn");
    return;
  }

  isScanning = true;
  setButtons(true);
  postScanPrompt.classList.add("hidden");
  output.innerHTML = "";
  resultsPanel.classList.add("empty");
  resultsPanel.innerHTML = "<p>Scan in progress...</p>";
  reports.classList.add("empty");
  reports.innerHTML = "<p>Generating artifact previews...</p>";
  setMeter(0, "Running");

  const flow = sequences[mode] || sequences.quick;
  for (const step of flow) {
    await typeLine(step.text, step.cls);
    setMeter(step.progress, "Running");
    await sleep(120);
  }

  const findings = sampleResults[mode] || sampleResults.quick;
  renderResults(findings);
  renderReports(findings, mode);

  await typeLine("[PROMPT] Press Enter to return to menu.", "warn");
  postScanPrompt.classList.remove("hidden");
  setMeter(100, "Completed");
  isScanning = false;
  setButtons(false);
}

function resetToMenu() {
  output.innerHTML = "";
  postScanPrompt.classList.add("hidden");
  setMeter(0, "Idle");
  typeLine("[INFO] Main menu restored. Select scan profile.", "info");
}

scanButtons.forEach((button) => {
  button.addEventListener("click", () => runScan(button.dataset.scan));
});

resetBtn.addEventListener("click", resetToMenu);
closeModal.addEventListener("click", closeModalView);

window.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !isScanning && !postScanPrompt.classList.contains("hidden")) {
    resetToMenu();
  }
  if (event.key === "Escape") {
    closeModalView();
  }
});

reportModal.addEventListener("click", (event) => {
  if (event.target === reportModal) {
    closeModalView();
  }
});
