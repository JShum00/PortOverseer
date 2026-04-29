/**********************
 *  CLI CORE
 **********************/
const CLI = {
  state: "menu",
  busy: false,
  resumeHandler: null,

  async run(input) {
    if (this.resumeHandler) {
      const handler = this.resumeHandler;
      this.resumeHandler = null;
      handler();
      return;
    }
    if (this.busy) {
      print("[SYSTEM] Busy. Please wait...", "dim");
      return;
    }

    this.busy = true;

    print(`> ${input}`, "system");

    try {
      switch (input) {
        case "1":
          await Engine.scan.quick();
          break;
        case "2":
          await Engine.scan.full();
          break;
        case "3":
          await Engine.scan.custom();
          break;
        case "4":
          await Engine.update.database();
          break;
        case "5":
          await Engine.help();
          break;
        case "6":
          await Engine.audit.run();
          break;
        case "7":
          await Engine.exit();
          break;
        default:
          Engine.invalid();
      }
    } catch (err) {
      print(`[ERROR] ${err.message}`, "critical");
      console.error(err);
    }

    this.busy = false;
  },
};


/**********************
 *  UI STATE
 **********************/
const UI = {
  statusLine: null,
  progressLine: null,
};


/**********************
 *  OUTPUT SYSTEM
 **********************/
function print(text, type = "low") {
  const out = document.querySelector(".cli-output");

  const line = document.createElement("div");

  const map = {
    critical: "cli-critical",
    high: "cli-high",
    medium: "cli-medium",
    low: "cli-low",
    clean: "cli-clean",
    dim: "cli-dim",
    system: "cli-system",
  };

  line.className = map[type] || "cli-low";
  line.textContent = text;

  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}


/**********************
 *  STATUS + PROGRESS
 **********************/
function setStatus(text) {
  const out = document.querySelector(".cli-output");

  if (!UI.statusLine) {
    UI.statusLine = document.createElement("div");
    UI.statusLine.className = "cli-system";
    UI.statusLine.style.opacity = "0.9";
    out.appendChild(UI.statusLine);
  }

  UI.statusLine.textContent = text;
  out.scrollTop = out.scrollHeight;
}

function renderProgress(label, current, total) {
  const width = 30;

  const percent = Math.floor((current / total) * 100);
  const filled = Math.floor((current / total) * width);

  const bar = "█".repeat(filled) + "░".repeat(width - filled);

  const text = `${label} [${bar}] ${percent}%`;

  const out = document.querySelector(".cli-output");

  if (!UI.progressLine) {
    UI.progressLine = document.createElement("div");
    UI.progressLine.className = "cli-system";
    out.appendChild(UI.progressLine);
  }

  UI.progressLine.textContent = text;
  out.scrollTop = out.scrollHeight;
}

/**********************
 *  ENGINE LAYER
 **********************/
const Engine = {
  invalid() {
    print("[SYSTEM] Invalid selection.", "dim");
    renderMenu();
  },

  lock() {
    CLI.busy = true;
  },

  unlock() {
    CLI.busy = false;
  },

  exit() {
    print("[SYSTEM] Exiting Port Overseer...", "system");

    setTimeout(() => {
      window.open("", "_self");
      window.close();

      // fallback if browser blocks it
      document.body.innerHTML = `
        <div style="color:#7f95aa;font-family:monospace;padding:20px;">
          Session terminated.<br><br>
          You may now close this tab.
        </div>
      `;
    }, 500);
  },

  scan: {
    async quick() {
      Engine.lock();

      print("Scanning with Quick Scan...", "system");
      await delay(700);

      await spinner("Scanning", 1200);
      print("Scanning... done", "dim");

      const results = fakePorts(3, 6);

      for (const r of results) {
        print(
          `Port ${r.port} | Service: ${r.service} | Version: ${r.version} | No known CVEs`,
          "clean"
        );
        await delay(180);
      }

      print("\nGenerating Reports...", "system");
      await delay(900);

      print("Reports saved.", "dim");
      print("Report Saved: /reports/quick_scan.txt", "dim");
      print("Report Saved: /reports/quick_scan.json", "dim");

      await delay(500);

      Engine.unlock();
    },

    async full() {
      Engine.lock();
      print("Scanning with Full Scan...", "system");
      await delay(700);

      await spinner("Scanning", 2500);
      print("Scanning... done", "dim");

      await delay(400);

      const results = fakePorts(8, 15);

      for (const r of results) {
        const hasCVEs = Math.random() < 0.4; // simulate vulnerability chance

        if (!hasCVEs) {
          print(
            `Port ${r.port} | Service: ${r.service} | Version: ${r.version} | No known CVEs`,
            "clean"
          );
          await delay(180);
          continue;
        }

        const severityPool = ["Low", "Medium", "High", "Critical"];
        const severity =
          severityPool[Math.floor(Math.random() * severityPool.length)];

        const cveCount = Math.floor(5 + Math.random() * 15);

        print(
          `Port ${r.port} | Service: ${r.service} | Version: ${r.version} | ${cveCount} CVEs found - highest: ${severity}`,
          severity.toLowerCase()
        );

        await delay(120);

        // generate CVE list
        for (let i = 0; i < cveCount; i++) {
          const year = 1999 + Math.floor(Math.random() * 5);
          const id =
            `CVE-${year}-${Math.floor(1000 + Math.random() * 9000)}`;

          print(
            `    ${id} | Severity: ${severity}`,
            severity.toLowerCase()
          );

          await delay(60);
        }

        await delay(200);
      }

      print("\nGenerating Reports...", "system");
      await delay(900);

      print("Reports Saved.", "dim");

      print("Report saved: /reports/full_scan.txt", "dim");
      print("Report saved: /reports/full_scan.json", "dim");

      await delay(500);

      Engine.unlock();
    },

    async custom() {
      Engine.lock();

      print("Custom Scan selected.", "system");
      await delay(500);

      const start = Math.floor(20 + Math.random() * 200);
      const end = start + Math.floor(50 + Math.random() * 500);

      print(`Scanning port range ${start}-${end}...`, "system");
      await delay(800);

      await spinner("Scanning custom range", 2000);

      const results = fakePorts(4, 10);

      print("Scan complete.", "dim");
      await delay(300);

      for (const r of results) {
        const hasCVEs = Math.random() < 0.35;

        if (!hasCVEs) {
          print(
            `Port ${r.port} | Service: ${r.service} | Version: ${r.version} | No known CVEs`,
            "clean"
          );
          await delay(150);
          continue;
        }

        const severityPool = ["Low", "Medium", "High", "Critical"];
        const severity =
          severityPool[Math.floor(Math.random() * severityPool.length)];

        const cveCount = Math.floor(3 + Math.random() * 12);

        print(
          `Port ${r.port} | Service: ${r.service} | Version: ${r.version} | ${cveCount} CVEs found - highest: ${severity}`,
          severity.toLowerCase()
        );

        for (let i = 0; i < cveCount; i++) {
          const id = `CVE-${1999 + Math.floor(Math.random() * 6)}-${Math.floor(
            1000 + Math.random() * 9000
          )}`;

          print(`    ${id} | Severity: ${severity}`, severity.toLowerCase());
          await delay(50);
        }

        await delay(120);
      }

      print("\nGenerating Reports...", "system");
      await delay(700);

      print("Reports Saved.", "dim");
      print("Report saved: /reports/custom_scan.txt", "dim");
      print("Report saved: /reports/custom_scan.json", "dim");

      Engine.unlock();
    }
  },

  update: {
    async database() {
      Engine.lock();

      print("[SYSTEM] Initializing updater module...", "system");
      await delay(700);

      print("[DB] Checking last update timestamp...", "system");
      await delay(800);

      const incremental = Math.random() > 0.5;

      print(
        incremental
          ? "[DB] Incremental update detected."
          : "[DB] No previous data found. Full update required.",
        "system"
      );

      await delay(900);

      print("[BACKUP] Rotating database backups...", "system");
      await delay(900);

      print("[INIT] Initializing SQLite layer...", "system");
      await delay(800);

      print("\n[DOWNLOAD] Connecting to NVD API...", "system");
      await delay(900);

      const total = 12;

      for (let i = 1; i <= total; i++) {
        renderProgress("Downloading CVEs...", i, total);
        await delay(250 + Math.random() * 300);
      }

      print("\n[PARSER] Processing vulnerability records...", "system");
      await delay(900);

      const inserted = Math.floor(total * 0.85);
      const skipped = total - inserted;

      for (let i = 1; i <= inserted; i++) {
        renderProgress("Inserting CVEs...", i, inserted);
        await delay(120);
      }

      print("\n[WRITE] Committing database transaction...", "system");
      await delay(800);

      print("[WRITE] Updating last_updated timestamp...", "system");
      await delay(600);

      print("\nSelect an Option:", "system");
      print(`Total fetched: ${total}`, "dim");
      print(`Total inserted: ${inserted}`, "dim");
      print(`Total skipped: ${skipped}`, "dim");

      Engine.unlock();
    },
  },

  help: async function () {
    Engine.lock();

    const out = document.querySelector(".cli-output");
    out.innerHTML = "";

    print("PORT OVERSEER // HELP", "system");
    await delay(400);

    print("\nCOMMAND REFERENCE\n", "system");

    print("1. Quick Scan", "clean");
    print("   Scan top 1,000 common localhost ports, detect services,", "dim");
    print("   match CVEs, and generate reports (TXT + JSON).", "dim");

    await delay(200);

    print("\n2. Full Scan", "clean");
    print("   Scan all 65,535 localhost ports with service detection,", "dim");
    print("   CVE lookup enabled. May take several minutes.", "dim");

    await delay(200);

    print("\n3. Custom Range", "clean");
    print("   Scan user-defined port range with CVE correlation.", "dim");

    await delay(200);

    print("\n4. Update Database", "clean");
    print("   Fetch latest NVD CVE dataset and refresh local SQLite DB.", "dim");

    await delay(200);

    print("\n5. Help", "clean");
    print("   Display this help screen.", "dim");

    await delay(200);

    print("\n6. Full Local Audit", "clean");
    print("   Scan localhost + LAN interface, generate separate reports.", "dim");

    await delay(200);

    print("\n7. Exit", "clean");
    print("   Close Port Overseer session.", "dim");

    await delay(400);

    print("\nPRIVILEGE REQUIREMENTS", "system");
    print("- Windows: Run as Administrator", "dim");
    print("- Linux: Run as root (sudo)", "dim");
    print("- Elevated privileges required for all scans & DB actions", "dim");

    await delay(300);

    print("\nOUTPUT DIRECTORY", "system");
    print("/reports/", "clean");

    await delay(500);

    print("\nPress Enter to return to the main menu...", "system");

    CLI.resumeHandler = () => {
      renderMenu();
    };

    Engine.unlock();
  },

  audit: {
    async run(portRange = null) {
      Engine.lock();
  
      print("Starting Full Local Audit...", "system");
      await delay(600);
  
      print("\n[LOOPBACK] Scanning 127.0.0.1...", "system");
      await delay(800);
      await spinner("Scanning loopback", 1200);
  
      const loopbackResults = fakePorts(5, 10);
  
      print("Loopback scan complete.\n", "dim");
  
      const lanDetected = Math.random() > 0.2;
  
      let lanResults = [];
  
      if (!lanDetected) {
        print(
          "Warning: Could not determine LAN IP. Proceeding with loopback only.",
          "dim"
        );
      } else {
        const lanIP = fakeLANIP();
  
        print(`\n[LAN] Scanning ${lanIP}...`, "system");
        await delay(900);
        await spinner("Scanning LAN", 1500);
  
        lanResults = fakePorts(6, 12);
  
        print("LAN scan complete.\n", "dim");
      }
  
      this.renderAuditSection("Loopback Findings (127.0.0.1)", loopbackResults);
  
      if (lanDetected) {
        this.renderAuditSection("LAN Findings", lanResults);
      }
  
      print("\nGenerating audit reports...", "system");
      await delay(900);
  
      print("Report saved: /reports/audit_loopback.txt", "dim");
      print("Report saved: /reports/audit_lan.txt", "dim");
      print("Report saved: /reports/audit.json", "dim");
  
      await delay(500);
  
      print("\nPress Enter to return to the main menu...", "system");
  
      CLI.resumeHandler = () => {
        renderMenu();
      };
  
      Engine.unlock();
      },
  
    renderAuditSection(label, results) {
      print(`\n${label}`, "system");
  
      for (const r of results) {
        const hasCVEs = Math.random() < 0.4;
  
        if (!hasCVEs) {
          print(
            `Port ${r.port} | Service: ${r.service} | Version: ${r.version} | No known CVEs`,
            "clean"
          );
          continue;
        }
  
        const severityPool = ["Low", "Medium", "High", "Critical"];
        const severity =
          severityPool[Math.floor(Math.random() * severityPool.length)];
  
        const cveCount = Math.floor(3 + Math.random() * 12);
  
        print(
          `Port ${r.port} | Service: ${r.service} | Version: ${r.version} | ${cveCount} CVEs found - highest: ${severity}`,
          severity.toLowerCase()
        );
  
        for (let i = 0; i < cveCount; i++) {
          const id = `CVE-${1999 + Math.floor(Math.random() * 6)}-${Math.floor(
            1000 + Math.random() * 9000
          )}`;
  
          print(`    ${id} | Severity: ${severity}`, severity.toLowerCase());
        }
      }
    },
  },
};


/**********************
 *  UTILITIES
 **********************/
function fakeLANIP() {
  return `192.168.1.${Math.floor(2 + Math.random() * 200)}`;
}

function fakePorts(min, max) {
  const basePorts = [
    {
      port: 22,
      service: "ssh",
      versions: ["OpenSSH 9.3", "OpenSSH 8.9"]
    },
    {
      port: 80,
      service: "http",
      versions: ["nginx 1.24", "Apache 2.4.58"]
    },
    {
      port: 443,
      service: "https",
      versions: ["nginx 1.24 (SSL)", "Apache 2.4.58 (OpenSSL)"]
    },
    {
      port: 631,
      service: "ipp",
      versions: ["CUPS 2.4", "CUPS 2.3"]
    },
  ];

  const count = Math.floor(min + Math.random() * (max - min));
  const shuffled = basePorts.sort(() => Math.random() - 0.5);

  return shuffled.slice(0, count).map((p) => {
    const version =
      p.versions[Math.floor(Math.random() * p.versions.length)];

    return {
      port: p.port,
      service: p.service,
      version,
    };
  });
}

async function spinner(message, duration = 2000) {
  const frames = ["|", "/", "-", "\\"];
  let i = 0;
  const start = Date.now();

  while (Date.now() - start < duration) {
    setStatus(`${message} ${frames[i % frames.length]}`);
    i++;
    await delay(100);
  }

  setStatus(`${message} done`);
}

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function renderMenu() {
  const out = document.querySelector(".cli-output");
  out.innerHTML = "";

  printMenu();
}

function printMenu() {
  const menu = `
Vulnerability Hunt & Scan // v1.0


  1. Quick Scan
  2. Full Scan
  3. Custom Range
  4. Update Database
  5. Help
  6. Full Local Audit
  7. Exit
`;

  const out = document.querySelector(".cli-output");
  const line = document.createElement("div");

  line.className = "cli-output cli-system";
  line.textContent = menu;

  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}


/**********************
 *  INPUT HANDLER
 **********************/
const input = document.getElementById("userInput");

input.addEventListener("keydown", async (e) => {
  if (e.key === "Enter") {
    try {
      const value = input.value.trim();
      input.value = "";

      await CLI.run(value);
    } catch (err) {
      print(`[ERROR] ${err.message}`, "critical");
    }
  }
});
