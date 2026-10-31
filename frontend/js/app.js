/**
 * TrustCTI: Frontend Application Controller
 * High-performance Vanilla JS Single-Page Application (SPA)
 */

const API_BASE = "/api";

// App State
const state = {
  token: localStorage.getItem("trustcti_token") || null,
  user: JSON.parse(localStorage.getItem("trustcti_user") || "null"),
  currentView: "dashboard",
  lastScanResult: null,
  records: [],
  receivedRecords: [],
  organizations: [],
  transactions: [],
  mlMetrics: null,
  globalImportance: [],
  activeCharts: {}
};

// Utilities
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerText = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function truncateHash(hash, len = 10) {
  if (!hash) return "N/A";
  if (hash.length <= len * 2) return hash;
  return `${hash.substring(0, len)}...${hash.substring(hash.length - len)}`;
}

async function apiRequest(endpoint, options = {}) {
  const headers = options.headers || {};
  if (state.token) {
    headers["Authorization"] = `Bearer ${state.token}`;
  }
  if (options.body && !(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  try {
    const res = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });
    if (res.status === 401) {
      logout();
      throw new Error("Session expired. Please sign in again.");
    }
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || data.message || "API request failed");
    }
    return data;
  } catch (err) {
    showToast(err.message, "danger");
    throw err;
  }
}

// Authentication
function setAuthSession(token, user) {
  state.token = token;
  state.user = user;
  localStorage.setItem("trustcti_token", token);
  localStorage.setItem("trustcti_user", JSON.stringify(user));
  updateUserUI();
  document.getElementById("auth-modal").classList.remove("active");
  document.getElementById("auth-modal").style.display = "none";
}

function logout() {
  state.token = null;
  state.user = null;
  localStorage.removeItem("trustcti_token");
  localStorage.removeItem("trustcti_user");
  document.getElementById("auth-modal").classList.add("active");
  document.getElementById("auth-modal").style.display = "flex";
}

function updateUserUI() {
  if (state.user) {
    const u = state.user;
    document.getElementById("sidebar-user-name").innerText = u.full_name || u.username;
    document.getElementById("sidebar-user-org").innerText = u.organization?.name || "SOC Analyst";
    const initials = (u.organization?.code || u.username || "US").substring(0, 2).toUpperCase();
    document.getElementById("sidebar-user-avatar").innerText = initials;
  }
}

// Navigation & Routing
function navigateTo(viewName, params = null) {
  state.currentView = viewName;
  document.querySelectorAll(".nav-item").forEach(item => {
    item.classList.toggle("active", item.getAttribute("data-view") === viewName);
  });

  // Destroy previous charts to avoid canvas reuse errors
  Object.values(state.activeCharts).forEach(chart => {
    if (chart && typeof chart.destroy === "function") chart.destroy();
  });
  state.activeCharts = {};

  const titles = {
    dashboard: "Executive Threat Intelligence Dashboard",
    scanner: "Deep URL Threat Scanner",
    results: "URL Intelligence & Risk Analysis",
    shap: "Explainable AI (SHAP) Model Attribution",
    "risk-trust": "Threat Risk vs CTI Trust Scoring Framework",
    repository: "Organizational CTI Repository",
    "record-details": "Cyber Threat Intelligence Record Deep Dive",
    share: "Cross-Sector CTI Sharing Console",
    received: "Received Partner Threat Intelligence",
    verify: "Ethereum Blockchain Integrity Verifier",
    transactions: "Immutable On-Chain Transaction Ledger",
    organizations: "Registered Threat Sharing Organizations",
    profile: "User Profile & Local Node Configuration"
  };

  document.getElementById("page-title").innerText = titles[viewName] || "TrustCTI Platform";
  const main = document.getElementById("main-container");
  main.innerHTML = `<div style="text-align: center; padding: 40px; color: var(--text-dim);">Loading view ${viewName}...</div>`;

  renderView(viewName, params);
}

async function renderView(viewName, params) {
  const main = document.getElementById("main-container");

  switch (viewName) {
    case "dashboard":
      await renderDashboardView(main);
      break;
    case "scanner":
      renderScannerView(main);
      break;
    case "results":
      renderResultsView(main, params || state.lastScanResult);
      break;
    case "shap":
      await renderShapView(main, params || state.lastScanResult);
      break;
    case "risk-trust":
      renderRiskTrustView(main, params || state.lastScanResult);
      break;
    case "repository":
      await renderRepositoryView(main);
      break;
    case "record-details":
      await renderRecordDetailsView(main, params);
      break;
    case "share":
      await renderShareView(main, params);
      break;
    case "received":
      await renderReceivedView(main);
      break;
    case "verify":
      await renderVerifyView(main, params);
      break;
    case "transactions":
      await renderTransactionsView(main);
      break;
    case "organizations":
      await renderOrganizationsView(main);
      break;
    case "profile":
      await renderProfileView(main);
      break;
    default:
      main.innerHTML = `<div class="card"><p>View not found.</p></div>`;
  }
}

// ==========================================
// VIEW 1: EXECUTIVE DASHBOARD
// ==========================================
async function renderDashboardView(container) {
  try {
    const [records, metrics, health, txs] = await Promise.all([
      apiRequest("/records"),
      apiRequest("/ml/metrics"),
      apiRequest("/health"),
      apiRequest("/blockchain/transactions")
    ]);

    state.records = records;
    state.mlMetrics = metrics;

    const totalRecords = records.length;
    const maliciousCount = records.filter(r => r.classification === "Malicious").length;
    const benignCount = records.filter(r => r.classification === "Benign").length;
    const verifiedOnChain = records.filter(r => r.blockchain_registered).length;
    const accuracy = metrics.evaluation ? (metrics.evaluation.accuracy * 100).toFixed(1) : "92.3";

    container.innerHTML = `
      <!-- Stats Grid -->
      <div class="stats-grid">
        <div class="stat-card">
          <span class="stat-label">Total CTI Records</span>
          <div class="stat-value">${totalRecords}</div>
          <span class="stat-subtext">Active repository entries</span>
        </div>
        <div class="stat-card danger">
          <span class="stat-label">Malicious Threats</span>
          <div class="stat-value" style="color: var(--danger);">${maliciousCount}</div>
          <span class="stat-subtext">Phishing / Malware / Defacement</span>
        </div>
        <div class="stat-card success">
          <span class="stat-label">Clean URLs Verified</span>
          <div class="stat-value" style="color: var(--success);">${benignCount}</div>
          <span class="stat-subtext">Safe institutional & web URLs</span>
        </div>
        <div class="stat-card blue">
          <span class="stat-label">On-Chain Registered</span>
          <div class="stat-value" style="color: var(--cyan-primary);">${verifiedOnChain}</div>
          <span class="stat-subtext">Ethereum SHA-256 anchored</span>
        </div>
      </div>

      <!-- Quick Action Scanner Banner -->
      <div class="card" style="background: linear-gradient(90deg, #131E36 0%, #192747 100%); border-color: var(--border-glow);">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
          <div>
            <h3 style="font-size: 16px; font-weight: 700; color: #fff;">Real-Time Cyber Threat Intelligence Scanner</h3>
            <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
              Input any URL for instant 65-feature extraction, XGBoost classification, SHAP explanations, and blockchain anchoring.
            </p>
          </div>
          <button class="btn btn-primary" onclick="navigateTo('scanner')">Launch URL Scanner</button>
        </div>
      </div>

      <!-- Charts Row -->
      <div class="grid-2">
        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">Threat Classification Breakdown</div>
              <div class="card-subtitle">Active distribution in organizational intelligence</div>
            </div>
          </div>
          <div style="height: 240px; position: relative;">
            <canvas id="chart-threat-pie"></canvas>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">XGBoost Evaluation Metrics</div>
              <div class="card-subtitle">Trained on 632,844 dataset records (Clean reproducible features)</div>
            </div>
          </div>
          <div style="height: 240px; position: relative;">
            <canvas id="chart-metrics-bar"></canvas>
          </div>
        </div>
      </div>

      <!-- Recent CTI Table -->
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Recent Intelligence Records</div>
            <div class="card-subtitle">Latest analyzed and anchored indicators</div>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="navigateTo('repository')">View All Records</button>
        </div>

        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Record ID</th>
                <th>Target URL</th>
                <th>Classification</th>
                <th>Threat Risk</th>
                <th>CTI Trust</th>
                <th>Blockchain Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${records.length === 0 ? `<tr><td colspan="7" style="text-align: center; color: var(--text-dim);">No CTI records found. Scan a URL to create the first record.</td></tr>` : 
                records.slice(0, 5).map(r => `
                  <tr>
                    <td class="code-font" style="color: var(--cyan-primary);">${r.id.substring(0, 8)}...</td>
                    <td style="max-width: 280px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                      ${r.url}
                    </td>
                    <td>
                      <span class="badge ${r.classification === 'Malicious' ? 'badge-malicious' : 'badge-benign'}">
                        ${r.threat_type || r.classification}
                      </span>
                    </td>
                    <td>
                      <span class="badge badge-${r.threat_risk_category.toLowerCase()}">${r.threat_risk_score}/100</span>
                    </td>
                    <td>
                      <span class="badge badge-low">${r.cti_trust_score}/100</span>
                    </td>
                    <td>
                      ${r.blockchain_registered ? `
                        <span class="badge badge-verified">
                          <span class="node-pill-dot" style="background:#10B981;"></span> Registered
                        </span>
                      ` : `
                        <span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-dim);">Unregistered</span>
                      `}
                    </td>
                    <td>
                      <button class="btn btn-secondary btn-sm" onclick="viewRecordDetails('${r.id}')">Inspect</button>
                    </td>
                  </tr>
                `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;

    // Initialize Charts
    initDashboardCharts(records, metrics);
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color: var(--danger);">Failed to load dashboard: ${err.message}</p></div>`;
  }
}

function initDashboardCharts(records, metrics) {
  // 1. Threat Pie Chart
  const pieCtx = document.getElementById("chart-threat-pie");
  if (pieCtx) {
    const counts = { Benign: 0, Phishing: 0, Malware: 0, Defacement: 0 };
    records.forEach(r => {
      const t = r.threat_type || r.classification;
      if (counts[t] !== undefined) counts[t]++;
      else counts.Phishing++;
    });

    state.activeCharts.threatPie = new Chart(pieCtx, {
      type: "doughnut",
      data: {
        labels: ["Benign", "Phishing", "Malware", "Defacement"],
        datasets: [{
          data: [counts.Benign, counts.Phishing, counts.Malware, counts.Defacement],
          backgroundColor: ["#10B981", "#EF4444", "#8B5CF6", "#F59E0B"],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "right", labels: { color: "#94A3B8", font: { size: 12 } } }
        }
      }
    });
  }

  // 2. Metrics Bar Chart
  const barCtx = document.getElementById("chart-metrics-bar");
  if (barCtx && metrics.evaluation) {
    const ev = metrics.evaluation;
    state.activeCharts.metricsBar = new Chart(barCtx, {
      type: "bar",
      data: {
        labels: ["Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"],
        datasets: [{
          label: "Performance (%)",
          data: [
            (ev.accuracy * 100).toFixed(1),
            (ev.precision * 100).toFixed(1),
            (ev.recall * 100).toFixed(1),
            (ev.f1_score * 100).toFixed(1),
            (ev.roc_auc * 100).toFixed(1)
          ],
          backgroundColor: "#06B6D4",
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { min: 80, max: 100, ticks: { color: "#64748B" }, grid: { color: "rgba(255,255,255,0.05)" } },
          x: { ticks: { color: "#94A3B8" }, grid: { display: false } }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
}

// ==========================================
// VIEW 2: URL SCANNER
// ==========================================
function renderScannerView(container) {
  container.innerHTML = `
    <div class="scan-container">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
        <h2 style="font-size: 18px; font-weight: 700; color: #fff;">Real-Time URL Threat Analysis</h2>
        <span class="badge badge-clean">Lexical Zero-Execution Guard</span>
      </div>
      <p style="font-size: 13px; color: var(--text-muted);">
        Submit suspicious URLs or potential indicators of compromise (IOCs). Features are parsed locally without executing or visiting the site.
      </p>

      <form class="scan-form" id="main-scan-form">
        <input type="text" id="scan-url-input" class="url-input" placeholder="e.g. http://br-icloud.com.br or https://security-login-auth.xyz/verify.php" required>
        <button type="submit" class="btn btn-primary" id="btn-submit-scan">
          <span>Analyze URL</span>
        </button>
      </form>

      <div style="margin-top: 18px;">
        <span style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700; display: block; margin-bottom: 8px;">
          One-Click Test Indicators from Dataset:
        </span>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button class="btn btn-secondary btn-sm preset-pill" data-url="http://br-icloud.com.br">Phishing: br-icloud.com.br</button>
          <button class="btn btn-secondary btn-sm preset-pill" data-url="http://signin.eby.de.zukruygxctzmmqi.civpro.co.za">Phishing: signin.eby.de...</button>
          <button class="btn btn-secondary btn-sm preset-pill" data-url="http://adventure-nicaragua.net/index.php?option=com_mailto&tmpl=component&link=aHR0cD">Malware: adventure-nicaragua.net</button>
          <button class="btn btn-secondary btn-sm preset-pill" data-url="https://en.wikipedia.org/wiki/Computer_security">Benign: wikipedia.org/wiki/Computer_security</button>
          <button class="btn btn-secondary btn-sm preset-pill" data-url="http://mp3raid.com/music/krizz_kaliko.html">Benign: mp3raid.com</button>
        </div>
      </div>
    </div>

    <div id="scan-loading-indicator" style="display: none; text-align: center; padding: 40px;">
      <div style="display: inline-block; width: 40px; height: 40px; border: 3px solid rgba(6,182,212,0.2); border-top-color: var(--cyan-primary); border-radius: 50%; animation: spin 0.8s linear infinite;"></div>
      <p style="color: var(--cyan-primary); margin-top: 12px; font-weight: 600;">Extracting 65 features & running TreeExplainer...</p>
    </div>
  `;

  // Attach Listeners
  document.getElementById("main-scan-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = document.getElementById("scan-url-input").value.trim();
    if (!url) return;
    await executeScan(url);
  });

  document.querySelectorAll(".preset-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.getElementById("scan-url-input").value = pill.getAttribute("data-url");
      document.getElementById("main-scan-form").dispatchEvent(new Event("submit"));
    });
  });
}

async function executeScan(url) {
  const loading = document.getElementById("scan-loading-indicator");
  if (loading) loading.style.display = "block";

  try {
    const result = await apiRequest("/scan", {
      method: "POST",
      body: JSON.stringify({ url })
    });
    state.lastScanResult = result;
    navigateTo("results", result);
  } finally {
    if (loading) loading.style.display = "none";
  }
}

// ==========================================
// VIEW 3: URL ANALYSIS RESULTS
// ==========================================
function renderResultsView(container, res) {
  if (!res) {
    container.innerHTML = `
      <div class="card" style="text-align: center; padding: 40px;">
        <p style="color: var(--text-muted); margin-bottom: 16px;">No recent analysis results to display.</p>
        <button class="btn btn-primary" onclick="navigateTo('scanner')">Scan a URL Now</button>
      </div>
    `;
    return;
  }

  const isMal = res.classification === "Malicious";

  container.innerHTML = `
    <!-- Top Classification Summary Banner -->
    <div class="card" style="border-left: 4px solid ${isMal ? 'var(--danger)' : 'var(--success)'};">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div>
          <span style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Analyzed Target URL</span>
          <h2 style="font-size: 18px; font-family: var(--font-mono); color: #fff; margin: 4px 0 8px; word-break: break-all;">
            ${res.url_normalized}
          </h2>
          <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
            <span class="badge ${isMal ? 'badge-malicious' : 'badge-benign'}" style="font-size: 13px; padding: 6px 12px;">
              ${res.classification}: ${res.threat_type}
            </span>
            <span style="font-size: 12px; color: var(--text-muted);">
              Prediction Certainty: <strong style="color: #fff;">${(res.confidence * 100).toFixed(2)}%</strong>
            </span>
          </div>
        </div>

        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
          <button class="btn btn-secondary" onclick="navigateTo('shap')">Inspect SHAP Values</button>
          <button class="btn btn-primary" id="btn-save-record-blockchain">Save & Anchor on Blockchain</button>
        </div>
      </div>
    </div>

    <!-- Dual Gauges: Threat Risk vs CTI Trust -->
    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Threat Risk Score</div>
            <div class="card-subtitle">How dangerous the indicator is (0 Clean - 100 Critical)</div>
          </div>
          <span class="badge badge-${res.threat_risk_category.toLowerCase()}">${res.threat_risk_category}</span>
        </div>

        <div class="gauge-box">
          <div class="gauge-val" style="color: ${isMal ? 'var(--danger)' : 'var(--success)'};">
            ${res.threat_risk_score}
          </div>
          <span style="font-size: 12px; color: var(--text-muted);">Composite Heuristic & ML Risk Rating</span>
        </div>

        <div style="margin-top: 16px;">
          <strong style="font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 8px;">Triggered Risk Indicators:</strong>
          ${res.risk_indicators.length === 0 ? `<p style="font-size: 12px; color: var(--text-dim);">No malicious heuristics detected.</p>` : `
            <div style="display: flex; flex-direction: column; gap: 6px;">
              ${res.risk_indicators.map(ind => `
                <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(0,0,0,0.2); padding: 8px 12px; border-radius: 4px; font-size: 12px;">
                  <span style="font-weight: 600; color: #fff;">${ind.indicator}</span>
                  <span class="badge ${ind.score_impact > 0 ? 'badge-malicious' : 'badge-benign'}">
                    ${ind.score_impact > 0 ? '+' : ''}${ind.score_impact} pts
                  </span>
                </div>
              `).join('')}
            </div>
          `}
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">CTI Trust Score</div>
            <div class="card-subtitle">Reliability and verifiable pedigree of this record</div>
          </div>
          <span class="badge badge-low">${res.cti_trust_category}</span>
        </div>

        <div class="gauge-box">
          <div class="gauge-val" style="color: var(--cyan-primary);">
            ${res.cti_trust_score}
          </div>
          <span style="font-size: 12px; color: var(--text-muted);">Decentralized Trust Factor</span>
        </div>

        <div style="margin-top: 16px;">
          <strong style="font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 8px;">Trust Components:</strong>
          <div style="display: flex; flex-direction: column; gap: 6px;">
            ${res.trust_indicators.map(comp => `
              <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(0,0,0,0.2); padding: 8px 12px; border-radius: 4px; font-size: 12px;">
                <span>${comp.component} (${(comp.weight * 100)}%)</span>
                <strong style="color: var(--cyan-primary);">${comp.weighted_score} / ${(comp.weight * 100)}</strong>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    </div>

    <!-- Quick SHAP Preview -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Top Contributing Features (Local SHAP Attribution)</div>
          <div class="card-subtitle">Exact mathematical influence pushing prediction toward Malicious (+) or Benign (-)</div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="navigateTo('shap')">Full Waterfall Analysis</button>
      </div>

      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Feature Name</th>
              <th>Extracted Value</th>
              <th>SHAP Attribution</th>
              <th>Directional Impact</th>
            </tr>
          </thead>
          <tbody>
            ${res.shap_summary.top_features ? res.shap_summary.top_features.slice(0, 6).map(feat => `
              <tr>
                <td class="code-font">${feat.feature}</td>
                <td>${feat.value}</td>
                <td class="code-font" style="color: ${feat.shap_value > 0 ? 'var(--danger)' : 'var(--success)'}; font-weight: 700;">
                  ${feat.shap_value > 0 ? '+' : ''}${feat.shap_value.toFixed(4)}
                </td>
                <td>
                  <span class="badge ${feat.shap_value > 0 ? 'badge-malicious' : 'badge-benign'}">
                    ${feat.impact}
                  </span>
                </td>
              </tr>
            `).join('') : `<tr><td colspan="4">No SHAP details available</td></tr>`}
          </tbody>
        </table>
      </div>
    </div>
  `;

  // Attach save button listener
  document.getElementById("btn-save-record-blockchain").addEventListener("click", async () => {
    try {
      const payload = {
        url: res.url,
        classification: res.classification,
        threat_type: res.threat_type,
        confidence: res.confidence,
        threat_risk_score: res.threat_risk_score,
        threat_risk_category: res.threat_risk_category,
        cti_trust_score: res.cti_trust_score,
        cti_trust_category: res.cti_trust_category,
        features_snapshot: res.features_snapshot,
        shap_summary: res.shap_summary,
        risk_indicators: res.risk_indicators,
        trust_indicators: res.trust_indicators,
        register_on_blockchain: true
      };

      const recordRes = await apiRequest("/records", {
        method: "POST",
        body: JSON.stringify(payload)
      });

      showToast("CTI Record stored and anchored on Ethereum Blockchain!", "success");
      navigateTo("record-details", recordRes.id);
    } catch (err) {
      showToast(err.message, "danger");
    }
  });
}

// ==========================================
// VIEW 4: SHAP EXPLAINABILITY
// ==========================================
async function renderShapView(container, res) {
  let globalImp = state.globalImportance;
  if (!globalImp || globalImp.length === 0) {
    try {
      globalImp = await apiRequest("/ml/global-importance");
      state.globalImportance = globalImp;
    } catch (e) {
      globalImp = [];
    }
  }

  const hasLocal = res && res.shap_summary && res.shap_summary.top_features;

  container.innerHTML = `
    <!-- Top Intro Card -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">XAI Architecture: TreeSHAP (SHapley Additive exPlanations)</div>
          <div class="card-subtitle">Game-theoretic feature attribution calculated directly on the trained XGBoost tree ensembles</div>
        </div>
        <span class="badge badge-clean">Mathematical Rigor</span>
      </div>
      <p style="font-size: 13px; color: var(--text-muted);">
        SHAP breaks down the model's prediction into additive feature contributions. Features with positive SHAP values push the model toward a <strong style="color: var(--danger);">Malicious</strong> decision, while negative values push toward <strong style="color: var(--success);">Benign</strong>.
      </p>
    </div>

    ${hasLocal ? `
      <!-- Local Prediction SHAP Waterfall Chart -->
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Local Prediction Attribution: ${res.url_normalized}</div>
            <div class="card-subtitle">Base Value (Mean Log-Odds): ${res.shap_summary.base_value}</div>
          </div>
        </div>

        <div style="height: 320px; position: relative;">
          <canvas id="chart-local-shap"></canvas>
        </div>
      </div>
    ` : `
      <div class="card" style="text-align: center; padding: 24px; color: var(--text-dim);">
        Scan a URL in the URL Scanner to visualize individual local prediction SHAP values.
      </div>
    `}

    <!-- Global Feature Importance Chart -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Global Feature Importance (Mean |SHAP| across Test Cohort)</div>
          <div class="card-subtitle">Top features universally driving model decisions on 632,844 records</div>
        </div>
      </div>

      <div style="height: 360px; position: relative;">
        <canvas id="chart-global-shap"></canvas>
      </div>
    </div>
  `;

  // Render Charts
  if (hasLocal) {
    const localCtx = document.getElementById("chart-local-shap");
    if (localCtx) {
      const topFeats = res.shap_summary.top_features.slice(0, 10).reverse();
      const labels = topFeats.map(f => `${f.feature} (${f.value})`);
      const data = topFeats.map(f => f.shap_value);
      const bgColors = data.map(v => v >= 0 ? "rgba(239, 68, 68, 0.85)" : "rgba(16, 185, 129, 0.85)");

      state.activeCharts.localShap = new Chart(localCtx, {
        type: "bar",
        data: {
          labels,
          datasets: [{
            label: "SHAP Value",
            data,
            backgroundColor: bgColors,
            borderRadius: 4
          }]
        },
        options: {
          indexAxis: "y",
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: { ticks: { color: "#94A3B8" }, grid: { color: "rgba(255,255,255,0.05)" } },
            y: { ticks: { color: "#F1F5F9", font: { family: "monospace" } }, grid: { display: false } }
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: (ctx) => `Impact: ${ctx.raw >= 0 ? '+' : ''}${ctx.raw.toFixed(4)} (${ctx.raw >= 0 ? 'Toward Malicious' : 'Toward Benign'})`
              }
            }
          }
        }
      });
    }
  }

  const globalCtx = document.getElementById("chart-global-shap");
  if (globalCtx && globalImp.length > 0) {
    const topGlobal = globalImp.slice(0, 12).reverse();
    const labels = topGlobal.map(f => f.feature);
    const data = topGlobal.map(f => f.importance);

    state.activeCharts.globalShap = new Chart(globalCtx, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label: "Mean Absolute SHAP Value",
          data,
          backgroundColor: "rgba(6, 182, 212, 0.85)",
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: "#94A3B8" }, grid: { color: "rgba(255,255,255,0.05)" } },
          y: { ticks: { color: "#F1F5F9", font: { family: "monospace" } }, grid: { display: false } }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
}

// ==========================================
// VIEW 5: RISK & TRUST ASSESSMENT
// ==========================================
function renderRiskTrustView(container, res) {
  container.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Mathematical Formulations: Threat Risk vs CTI Trust</div>
          <div class="card-subtitle">Transparent, documented distinction between threat danger and intelligence veracity</div>
        </div>
      </div>
      <p style="font-size: 13px; color: var(--text-muted); line-height: 1.6;">
        A critical principle of TrustCTI is distinguishing <strong>Threat Risk</strong> (how dangerous a URL appears to be) from <strong>CTI Trust</strong> (how reliable and authentic this report is). A verified benign URL can have low threat risk but high CTI trust, because the intelligence is verifiable and sourced from a high-reputation SOC.
      </p>
    </div>

    <div class="grid-2">
      <!-- Threat Risk Formula -->
      <div class="card">
        <div class="card-header">
          <div class="card-title" style="color: var(--danger);">Threat Risk Score Formula (0 - 100)</div>
          <span class="badge badge-malicious">Threat Severity</span>
        </div>
        <div style="background: rgba(0,0,0,0.3); padding: 14px; border-radius: 6px; font-family: var(--font-mono); font-size: 12px; margin-bottom: 16px;">
          RiskScore = min(100, max(0, BaseRisk + HeuristicPenalties))<br><br>
          Where:<br>
          • BaseRisk = P(Malicious) × 60 pts<br>
          • Direct IP Host: +10 pts<br>
          • Suspicious TLD (.xyz, .top, .tk): +8 pts<br>
          • Brand Spoofing / Hijacking: +8 pts<br>
          • Malicious Payload / Shell terms: +7 pts<br>
          • High Shannon Entropy (> 4.5): +4 pts<br>
          • Credential harvesting keywords: +2 to +5 pts
        </div>

        <h4 style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">Risk Severity Categorization</h4>
        <div style="display: flex; flex-direction: column; gap: 6px; font-size: 12px;">
          <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: rgba(0,0,0,0.2); border-radius: 4px;">
            <span>90 - 100</span><span class="badge badge-critical">CRITICAL</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: rgba(0,0,0,0.2); border-radius: 4px;">
            <span>70 - 89</span><span class="badge badge-high">HIGH</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: rgba(0,0,0,0.2); border-radius: 4px;">
            <span>40 - 69</span><span class="badge badge-medium">MEDIUM</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: rgba(0,0,0,0.2); border-radius: 4px;">
            <span>20 - 39</span><span class="badge badge-low">LOW</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: rgba(0,0,0,0.2); border-radius: 4px;">
            <span>0 - 19</span><span class="badge badge-clean">CLEAN</span>
          </div>
        </div>
      </div>

      <!-- CTI Trust Formula -->
      <div class="card">
        <div class="card-header">
          <div class="card-title" style="color: var(--cyan-primary);">CTI Trust Score Formula (0 - 100)</div>
          <span class="badge badge-clean">Pedigree & Integrity</span>
        </div>
        <div style="background: rgba(0,0,0,0.3); padding: 14px; border-radius: 6px; font-family: var(--font-mono); font-size: 12px; margin-bottom: 16px;">
          TrustScore = w1·C_pred + w2·R_source + w3·H_blockchain + w4·I_features<br><br>
          Weights & Factors:<br>
          • w1 = 0.35 : Model Confidence (|P - 0.5| × 200)<br>
          • w2 = 0.25 : Source Organization Reputation (0-100)<br>
          • w3 = 0.25 : Blockchain Integrity (100 if verified, 0 if tampered)<br>
          • w4 = 0.15 : Feature Reproducibility (Zero missing data)
        </div>

        <h4 style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">Trust Rating Categorization</h4>
        <div style="display: flex; flex-direction: column; gap: 6px; font-size: 12px;">
          <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: rgba(0,0,0,0.2); border-radius: 4px;">
            <span>85 - 100</span><span class="badge badge-verified">HIGHLY_TRUSTED</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: rgba(0,0,0,0.2); border-radius: 4px;">
            <span>70 - 84</span><span class="badge badge-low">TRUSTED</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: rgba(0,0,0,0.2); border-radius: 4px;">
            <span>50 - 69</span><span class="badge badge-medium">MODERATE</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: rgba(0,0,0,0.2); border-radius: 4px;">
            <span>0 - 49</span><span class="badge badge-tampered">LOW_TRUST</span>
          </div>
        </div>
      </div>
    </div>
  `;
}

// ==========================================
// VIEW 6: CTI REPOSITORY
// ==========================================
async function renderRepositoryView(container) {
  try {
    const records = await apiRequest("/records");
    state.records = records;

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Cyber Threat Intelligence Repository</div>
            <div class="card-subtitle">Stored structured CTI records for ${state.user?.organization?.name || 'Your Organization'}</div>
          </div>
          <button class="btn btn-primary btn-sm" onclick="navigateTo('scanner')">+ New Scan</button>
        </div>

        <!-- Filter Bar -->
        <div style="display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap;">
          <input type="text" id="repo-search" class="url-input" style="flex: 1; padding: 9px 14px;" placeholder="Search by URL, record ID, or hash...">
          <select id="repo-filter-class" class="url-input" style="width: 180px; padding: 9px 12px;">
            <option value="ALL">All Classifications</option>
            <option value="Malicious">Malicious</option>
            <option value="Benign">Benign</option>
          </select>
        </div>

        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Record ID</th>
                <th>URL</th>
                <th>Threat Classification</th>
                <th>Threat Risk</th>
                <th>CTI Trust</th>
                <th>Blockchain Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="repo-table-body">
              ${records.map(r => renderRepoRow(r)).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;

    // Filter listeners
    document.getElementById("repo-search").addEventListener("input", filterRepo);
    document.getElementById("repo-filter-class").addEventListener("change", filterRepo);

  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color:var(--danger);">${err.message}</p></div>`;
  }
}

function renderRepoRow(r) {
  return `
    <tr>
      <td class="code-font" style="color: var(--cyan-primary);">${r.id.substring(0, 8)}...</td>
      <td style="max-width: 240px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
        ${r.url}
      </td>
      <td>
        <span class="badge ${r.classification === 'Malicious' ? 'badge-malicious' : 'badge-benign'}">
          ${r.threat_type || r.classification}
        </span>
      </td>
      <td>
        <span class="badge badge-${r.threat_risk_category.toLowerCase()}">${r.threat_risk_score}</span>
      </td>
      <td>
        <span class="badge badge-low">${r.cti_trust_score}</span>
      </td>
      <td>
        ${r.blockchain_registered ? `
          <span class="badge badge-verified">Anchored</span>
        ` : `
          <span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-dim);">Unregistered</span>
        `}
      </td>
      <td style="font-size: 11px; color: var(--text-dim);">
        ${new Date(r.created_at).toLocaleDateString()}
      </td>
      <td>
        <div style="display: flex; gap: 6px;">
          <button class="btn btn-secondary btn-sm" onclick="viewRecordDetails('${r.id}')">Inspect</button>
          <button class="btn btn-secondary btn-sm" onclick="openShareModal('${r.id}')" title="Share with Partner SOC">Share</button>
          <button class="btn btn-secondary btn-sm" onclick="navigateTo('verify', '${r.id}')" title="Verify Blockchain Hash">Verify</button>
        </div>
      </td>
    </tr>
  `;
}

function filterRepo() {
  const q = document.getElementById("repo-search").value.toLowerCase();
  const filterClass = document.getElementById("repo-filter-class").value;

  const filtered = state.records.filter(r => {
    const matchesQ = r.url.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || (r.record_hash && r.record_hash.toLowerCase().includes(q));
    const matchesClass = filterClass === "ALL" || r.classification === filterClass;
    return matchesQ && matchesClass;
  });

  document.getElementById("repo-table-body").innerHTML = filtered.map(r => renderRepoRow(r)).join('');
}

// ==========================================
// VIEW 7: RECORD DETAILS VIEW
// ==========================================
async function renderRecordDetailsView(container, recordId) {
  try {
    const r = await apiRequest(`/records/${recordId}`);

    container.innerHTML = `
      <div style="margin-bottom: 16px;">
        <button class="btn btn-secondary btn-sm" onclick="navigateTo('repository')">← Back to Repository</button>
      </div>

      <!-- Top Header Card -->
      <div class="card" style="border-left: 4px solid ${r.classification === 'Malicious' ? 'var(--danger)' : 'var(--success)'};">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px;">
          <div>
            <span style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">
              CTI Record ID: ${r.id} (Version ${r.version || '1.0'})
            </span>
            <h2 style="font-size: 18px; font-family: var(--font-mono); color: #fff; margin: 6px 0;">
              ${r.url_normalized}
            </h2>
            <div style="display: flex; align-items: center; gap: 10px; margin-top: 8px;">
              <span class="badge ${r.classification === 'Malicious' ? 'badge-malicious' : 'badge-benign'}">
                ${r.classification}: ${r.threat_type}
              </span>
              <span class="badge badge-${r.threat_risk_category.toLowerCase()}">Risk: ${r.threat_risk_score}/100</span>
              <span class="badge badge-low">Trust: ${r.cti_trust_score}/100</span>
              <span style="font-size: 12px; color: var(--text-dim);">Created: ${new Date(r.created_at).toLocaleString()}</span>
            </div>
          </div>

          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            ${!r.blockchain_registered ? `
              <button class="btn btn-primary" onclick="registerRecordOnChain('${r.id}')">Anchor on Blockchain</button>
            ` : `
              <span class="badge badge-verified" style="font-size: 12px; padding: 8px 12px;">
                ✔ On-Chain Hash Verified
              </span>
            `}
            <button class="btn btn-secondary" onclick="openShareModal('${r.id}')">Share CTI</button>
            <button class="btn btn-secondary" onclick="navigateTo('verify', '${r.id}')">Integrity Audit</button>
          </div>
        </div>
      </div>

      <!-- Cryptographic Verification Block -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">Cryptographic Integrity Signatures</div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px; font-size: 13px;">
          <div>
            <span style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Canonical SHA-256 Hash</span>
            <div class="code-font" style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 4px; color: var(--cyan-primary); word-break: break-all; margin-top: 4px;">
              ${r.record_hash}
            </div>
          </div>

          ${r.blockchain_registered ? `
            <div>
              <span style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Blockchain Transaction Hash</span>
              <div class="code-font" style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 4px; color: #fff; word-break: break-all; margin-top: 4px;">
                ${r.blockchain_tx_hash}
              </div>
              <span style="font-size: 11px; color: var(--text-dim); margin-top: 4px; display: block;">
                Mined in Block #${r.blockchain_block_number || 'Latest'} | Anchored on local Ethereum CTIRegistry contract
              </span>
            </div>
          ` : `
            <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); padding: 12px; border-radius: 6px; font-size: 12px; color: var(--warning);">
              Notice: This record hash is currently stored only in PostgreSQL. Click "Anchor on Blockchain" to register it immutably on the Ethereum smart contract.
            </div>
          `}
        </div>
      </div>

      <!-- Canonical JSON Payload -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">Deterministic Canonical JSON (Source for Hashing)</div>
          <span class="badge badge-clean">Compact & Key-Sorted</span>
        </div>
        <pre class="code-font" style="background: rgba(0,0,0,0.4); padding: 16px; border-radius: 6px; color: #A7F3D0; overflow-x: auto; white-space: pre-wrap; font-size: 12px;">${JSON.stringify(JSON.parse(r.canonical_json), null, 2)}</pre>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color:var(--danger);">${err.message}</p></div>`;
  }
}

async function registerRecordOnChain(recordId) {
  try {
    const res = await apiRequest(`/records/${recordId}/register-blockchain`, { method: "POST" });
    if (res.success) {
      showToast("Successfully anchored record on Ethereum smart contract!", "success");
      renderRecordDetailsView(document.getElementById("main-container"), recordId);
    } else {
      showToast(`Registration failed: ${res.message}`, "danger");
    }
  } catch (err) {
    showToast(err.message, "danger");
  }
}

function viewRecordDetails(recordId) {
  navigateTo("record-details", recordId);
}

// ==========================================
// VIEW 8: SHARE CTI
// ==========================================
async function renderShareView(container, recordId) {
  try {
    const [sentShares, orgs, records] = await Promise.all([
      apiRequest("/shared/sent"),
      apiRequest("/organizations"),
      apiRequest("/records")
    ]);

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Intelligence Sharing Console</div>
            <div class="card-subtitle">Secure, authenticated CTI dissemination between partner organizations</div>
          </div>
        </div>

        <form id="standalone-share-form">
          <div style="margin-bottom: 16px;">
            <label style="font-size: 12px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">Select CTI Record to Share</label>
            <select id="share-select-record" class="url-input" style="width: 100%; padding: 10px;" required>
              <option value="">-- Choose Record --</option>
              ${records.map(r => `
                <option value="${r.id}" ${r.id === recordId ? 'selected' : ''}>
                  [${r.classification}] ${r.url} (Risk: ${r.threat_risk_score})
                </option>
              `).join('')}
            </select>
          </div>

          <div style="margin-bottom: 16px;">
            <label style="font-size: 12px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">Select Target Organizations</label>
            <div id="standalone-share-orgs" style="display: flex; flex-direction: column; gap: 8px; background: rgba(0,0,0,0.2); padding: 12px; border-radius: 6px;">
              ${orgs.filter(o => o.id !== state.user?.organization?.id).map(o => `
                <label style="display: flex; align-items: center; gap: 10px; cursor: pointer; font-size: 13px;">
                  <input type="checkbox" name="target_org" value="${o.id}">
                  <span><strong>${o.name}</strong> (${o.code}) - Rep: ${o.reputation_score}/100</span>
                </label>
              `).join('')}
            </div>
          </div>

          <div style="margin-bottom: 20px;">
            <label style="font-size: 12px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">Sharing Advisory / Notes</label>
            <textarea id="standalone-share-notes" class="url-input" style="width: 100%; height: 70px; padding: 10px;" placeholder="IOC advisory details..."></textarea>
          </div>

          <button type="submit" class="btn btn-primary">Transmit Threat Intelligence</button>
        </form>
      </div>

      <!-- Outbound Sharing Log -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">Outbound Sharing Audit History</div>
        </div>

        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Record ID</th>
                <th>Target Organization</th>
                <th>URL</th>
                <th>Advisory Notes</th>
                <th>Shared At</th>
              </tr>
            </thead>
            <tbody>
              ${sentShares.length === 0 ? `<tr><td colspan="5" style="text-align: center; color: var(--text-dim);">No outbound shared records recorded.</td></tr>` : 
                sentShares.map(s => `
                  <tr>
                    <td class="code-font" style="color: var(--cyan-primary);">${s.record_id.substring(0, 8)}...</td>
                    <td><strong>${s.target_organization_name}</strong> (${s.target_organization_code})</td>
                    <td style="max-width: 240px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${s.url}</td>
                    <td style="font-size: 12px; color: var(--text-muted);">${s.notes || 'None'}</td>
                    <td style="font-size: 11px; color: var(--text-dim);">${new Date(s.shared_at).toLocaleString()}</td>
                  </tr>
                `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;

    document.getElementById("standalone-share-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const recId = document.getElementById("share-select-record").value;
      const targetOrgs = Array.from(document.querySelectorAll("input[name='target_org']:checked")).map(cb => cb.value);
      const notes = document.getElementById("standalone-share-notes").value;

      if (!recId) {
        showToast("Please choose a CTI record to share.", "warning");
        return;
      }
      if (targetOrgs.length === 0) {
        showToast("Please select at least one recipient organization.", "warning");
        return;
      }

      await apiRequest("/share", {
        method: "POST",
        body: JSON.stringify({
          cti_record_id: recId,
          target_organization_ids: targetOrgs,
          notes
        })
      });

      showToast("Threat Intelligence shared with partner organizations!", "success");
      renderShareView(container);
    });

  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color:var(--danger);">${err.message}</p></div>`;
  }
}

// ==========================================
// VIEW 9: RECEIVED CTI
// ==========================================
async function renderReceivedView(container) {
  try {
    const received = await apiRequest("/shared/received");
    state.receivedRecords = received;

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Received Partner Threat Intelligence</div>
            <div class="card-subtitle">Verified external threat data shared with ${state.user?.organization?.name || 'Your Organization'}</div>
          </div>
        </div>

        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Transmitting SOC</th>
                <th>URL</th>
                <th>Classification</th>
                <th>Threat Risk</th>
                <th>CTI Trust</th>
                <th>Advisory Notes</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${received.length === 0 ? `<tr><td colspan="7" style="text-align: center; color: var(--text-dim);">No shared intelligence received from partner organizations yet.</td></tr>` : 
                received.map(r => `
                  <tr>
                    <td>
                      <strong>${r.share_metadata?.source_organization_name || r.organization_name || 'US-CERT'}</strong>
                      <span style="font-size: 10px; color: var(--cyan-primary); display: block;">(${r.share_metadata?.source_organization_code || r.organization_code})</span>
                    </td>
                    <td style="max-width: 240px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${r.url}</td>
                    <td>
                      <span class="badge ${r.classification === 'Malicious' ? 'badge-malicious' : 'badge-benign'}">
                        ${r.threat_type || r.classification}
                      </span>
                    </td>
                    <td><span class="badge badge-${r.threat_risk_category.toLowerCase()}">${r.threat_risk_score}</span></td>
                    <td><span class="badge badge-low">${r.cti_trust_score}</span></td>
                    <td style="font-size: 12px; color: var(--text-muted);">${r.share_metadata?.notes || 'Standard sharing feed'}</td>
                    <td>
                      <div style="display: flex; gap: 6px;">
                        <button class="btn btn-secondary btn-sm" onclick="viewRecordDetails('${r.id}')">Inspect</button>
                        <button class="btn btn-primary btn-sm" onclick="navigateTo('verify', '${r.id}')">Verify Hash</button>
                      </div>
                    </td>
                  </tr>
                `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color:var(--danger);">${err.message}</p></div>`;
  }
}

// ==========================================
// VIEW 10: BLOCKCHAIN INTEGRITY VERIFIER
// ==========================================
async function renderVerifyView(container, preselectedRecordId) {
  try {
    const records = await apiRequest("/records");

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Blockchain Cryptographic Integrity Verifier</div>
            <div class="card-subtitle">Zero-trust audit comparing database canonical record against Ethereum smart contract</div>
          </div>
          <span class="badge badge-clean">On-Chain Audit</span>
        </div>

        <div style="margin-bottom: 20px;">
          <label style="font-size: 12px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">Select Record to Audit</label>
          <select id="verify-select-record" class="url-input" style="width: 100%; padding: 10px;">
            <option value="">-- Choose Record to Verify --</option>
            ${records.map(r => `
              <option value="${r.id}" ${r.id === preselectedRecordId ? 'selected' : ''}>
                [${r.classification}] ${r.url} (ID: ${r.id.substring(0, 8)}...)
              </option>
            `).join('')}
          </select>
        </div>

        <button class="btn btn-primary" id="btn-run-verification">Execute Cryptographic Verification</button>
      </div>

      <!-- Verification Result Display Area -->
      <div id="verify-result-box" style="display: none;"></div>

      <!-- Interactive Tamper Simulator Tool -->
      <div class="card" style="margin-top: 24px; border-color: rgba(239, 68, 68, 0.3);">
        <div class="card-header">
          <div>
            <div class="card-title" style="color: var(--danger);">Interactive Tamper Simulation Test</div>
            <div class="card-subtitle">Test and prove blockchain integrity: modify a record field and verify detection</div>
          </div>
          <span class="badge badge-tampered">Security Proof Tool</span>
        </div>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">
          Adversaries often attempt to tamper with stored database records (e.g. changing classification from Malicious to Benign). This tool tests the smart contract verification by altering the canonical payload before recalculating SHA-256.
        </p>

        <div style="margin-bottom: 14px;">
          <label style="font-size: 12px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">Canonical JSON to Verify (Edit below to simulate tampering):</label>
          <textarea id="tamper-json-input" class="url-input" style="width: 100%; height: 140px; font-family: var(--font-mono); font-size: 12px; padding: 12px;"></textarea>
        </div>

        <button class="btn btn-danger" id="btn-test-tampering">Test Tampered Hash Against Smart Contract</button>
      </div>
    `;

    // Listeners
    const select = document.getElementById("verify-select-record");
    select.addEventListener("change", () => {
      const selectedId = select.value;
      const rec = records.find(r => r.id === selectedId);
      if (rec) {
        document.getElementById("tamper-json-input").value = rec.canonical_json;
      }
    });

    if (preselectedRecordId) {
      select.dispatchEvent(new Event("change"));
      executeVerification(preselectedRecordId);
    }

    document.getElementById("btn-run-verification").addEventListener("click", () => {
      const id = select.value;
      if (!id) {
        showToast("Please choose a record to verify.", "warning");
        return;
      }
      executeVerification(id);
    });

    document.getElementById("btn-test-tampering").addEventListener("click", () => {
      const id = select.value;
      if (!id) {
        showToast("Please choose a record first.", "warning");
        return;
      }
      const customJson = document.getElementById("tamper-json-input").value;
      executeVerification(id, customJson);
    });

  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color:var(--danger);">${err.message}</p></div>`;
  }
}

async function executeVerification(recordId, customCanonicalJson = null) {
  const box = document.getElementById("verify-result-box");
  box.style.display = "block";
  box.innerHTML = `<div class="card" style="text-align: center; color: var(--cyan-primary); padding: 30px;">Querying Ethereum smart contract...</div>`;

  try {
    const payload = { cti_record_id: recordId };
    if (customCanonicalJson) {
      payload.custom_canonical_json = customCanonicalJson;
    }

    const res = await apiRequest("/verify", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    const isVerified = res.result === "VERIFIED";
    const isTampered = res.result === "TAMPERED";

    box.innerHTML = `
      <div class="card" style="border-left: 4px solid ${isVerified ? 'var(--success)' : (isTampered ? 'var(--danger)' : 'var(--warning)')};">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;">
          <div>
            <span style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Audit Outcome</span>
            <h3 style="font-size: 20px; font-weight: 700; color: ${isVerified ? 'var(--success)' : (isTampered ? 'var(--danger)' : 'var(--warning)')};">
              ${isVerified ? '✔ INTEGRITY CONFIRMED (VERIFIED)' : (isTampered ? '⚠ TAMPERED / HASH MISMATCH' : 'BLOCKCHAIN UNAVAILABLE')}
            </h3>
          </div>
          <span class="badge ${isVerified ? 'badge-verified' : (isTampered ? 'badge-tampered' : 'badge-high')}" style="font-size: 13px; padding: 6px 12px;">
            ${res.result}
          </span>
        </div>

        <p style="font-size: 13px; color: #fff; margin-bottom: 18px;">${res.message}</p>

        <div class="grid-2">
          <div>
            <span style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Local Calculated SHA-256</span>
            <div class="code-font" style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 4px; color: ${isVerified ? 'var(--success)' : 'var(--danger)'}; word-break: break-all; margin-top: 4px;">
              ${res.computed_hash}
            </div>
          </div>
          <div>
            <span style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Registered Smart Contract Hash</span>
            <div class="code-font" style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 4px; color: var(--cyan-primary); word-break: break-all; margin-top: 4px;">
              ${res.blockchain_hash || 'Record not registered on-chain'}
            </div>
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    box.innerHTML = `<div class="card"><p style="color:var(--danger);">${err.message}</p></div>`;
  }
}

// ==========================================
// VIEW 11: BLOCKCHAIN TRANSACTIONS
// ==========================================
async function renderTransactionsView(container) {
  try {
    const [txs, status] = await Promise.all([
      apiRequest("/blockchain/transactions"),
      apiRequest("/blockchain/status")
    ]);

    container.innerHTML = `
      <div class="stats-grid">
        <div class="stat-card">
          <span class="stat-label">Total Transactions</span>
          <div class="stat-value">${txs.length}</div>
          <span class="stat-subtext">On-chain registration logs</span>
        </div>
        <div class="stat-card success">
          <span class="stat-label">RPC Node Status</span>
          <div class="stat-value" style="font-size: 18px; color: var(--success);">${status.connected ? 'ACTIVE' : 'OFFLINE'}</div>
          <span class="stat-subtext">${status.rpc_url}</span>
        </div>
        <div class="stat-card blue">
          <span class="stat-label">Contract Address</span>
          <div class="stat-value code-font" style="font-size: 13px; color: var(--cyan-primary); word-break: break-all;">${truncateHash(status.contract_address, 8)}</div>
          <span class="stat-subtext">CTIRegistry.sol</span>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">Immutable Transaction Ledger</div>
        </div>

        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Tx Hash</th>
                <th>Block #</th>
                <th>Gas Used</th>
                <th>Sender Address</th>
                <th>Status</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              ${txs.length === 0 ? `<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No transactions mined yet. Register a CTI record to create on-chain blocks.</td></tr>` : 
                txs.map(t => `
                  <tr>
                    <td class="code-font" style="color: var(--cyan-primary);">${truncateHash(t.tx_hash, 10)}</td>
                    <td><strong>#${t.block_number}</strong></td>
                    <td class="code-font">${t.gas_used.toLocaleString()}</td>
                    <td class="code-font" style="color: var(--text-muted);">${truncateHash(t.sender_address, 6)}</td>
                    <td><span class="badge badge-verified">${t.status}</span></td>
                    <td style="font-size: 11px; color: var(--text-dim);">${new Date(t.created_at).toLocaleString()}</td>
                  </tr>
                `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color:var(--danger);">${err.message}</p></div>`;
  }
}

// ==========================================
// VIEW 12: ORGANIZATIONS
// ==========================================
async function renderOrganizationsView(container) {
  try {
    const orgs = await apiRequest("/organizations");

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Participating Threat Sharing Organizations</div>
            <div class="card-subtitle">Vetted security operations centers and federated CERT teams</div>
          </div>
        </div>

        <div class="grid-3">
          ${orgs.map(o => `
            <div class="stat-card" style="border: 1px solid var(--border-color); padding: 20px;">
              <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                <span class="badge badge-clean">${o.code}</span>
                <span style="font-size: 11px; color: var(--cyan-primary); font-weight: 700;">Reputation: ${o.reputation_score}/100</span>
              </div>
              <h3 style="font-size: 15px; font-weight: 700; color: #fff; margin: 4px 0 8px;">${o.name}</h3>
              <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">${o.description || 'Federated partner SOC.'}</p>
              
              <div style="font-size: 11px; color: var(--text-dim); border-top: 1px solid rgba(255,255,255,0.05); padding-top: 10px;">
                Ethereum ID: <span class="code-font" style="color: var(--text-muted);">${truncateHash(o.eth_address || '0x...')}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color:var(--danger);">${err.message}</p></div>`;
  }
}

// ==========================================
// VIEW 13: PROFILE & SETTINGS
// ==========================================
async function renderProfileView(container) {
  try {
    const [me, bcStatus, health] = await Promise.all([
      apiRequest("/auth/me"),
      apiRequest("/blockchain/status"),
      apiRequest("/health")
    ]);

    const dbInfo = health.database_info || {
      display_name: "PostgreSQL (Production)",
      dialect: "postgresql",
      storage_mode: "Dedicated PostgreSQL database server",
      active_tables: ["organizations", "users", "cti_records", "verification_history", "cti_shares", "blockchain_transactions"]
    };

    container.innerHTML = `
      <div class="grid-2">
        <div class="card">
          <div class="card-header">
            <div class="card-title">Analyst Profile</div>
          </div>
          <div style="display: flex; flex-direction: column; gap: 12px; font-size: 13px;">
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Full Name</span>
              <div style="font-weight: 600; color: #fff;">${me.full_name}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Username</span>
              <div class="code-font" style="color: var(--cyan-primary);">${me.username}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Official Email</span>
              <div style="color: #fff;">${me.email}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Organization</span>
              <div style="font-weight: 600; color: #fff;">${me.organization?.name} (${me.organization?.code})</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Role</span>
              <div><span class="badge badge-clean">${me.role}</span></div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div class="card-title">Database & Persistence Configuration</div>
            <span class="badge badge-verified">Connected</span>
          </div>

          <div style="display: flex; flex-direction: column; gap: 12px; font-size: 13px;">
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Active Database Engine</span>
              <div class="code-font" style="color: var(--cyan-primary); font-weight: 700;">${dbInfo.display_name}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">SQL Dialect</span>
              <div class="code-font" style="color: #fff;">${dbInfo.dialect.toUpperCase()}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Storage Architecture</span>
              <div style="color: #fff;">${dbInfo.storage_mode}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Managed Schemas / Tables</span>
              <div class="code-font" style="color: var(--text-muted); font-size: 11px;">
                ${(dbInfo.active_tables || []).join(", ")}
              </div>
            </div>
          </div>
        </div>

        <div class="card" style="grid-column: span 2;">
          <div class="card-header">
            <div class="card-title">Blockchain & Node Configuration</div>
            <span class="badge ${bcStatus.connected ? 'badge-verified' : 'badge-tampered'}">
              ${bcStatus.connected ? 'RPC Online' : 'RPC Offline'}
            </span>
          </div>

          <div class="grid-2" style="font-size: 13px; gap: 16px;">
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">RPC Provider Endpoint</span>
              <div class="code-font" style="color: #fff;">${bcStatus.rpc_url}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Smart Contract Address (CTIRegistry.sol)</span>
              <div class="code-font" style="color: var(--cyan-primary); word-break: break-all;">${bcStatus.contract_address || 'Not deployed'}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Network Chain ID</span>
              <div class="code-font" style="color: #fff;">${bcStatus.network_id || '31337 (Local Hardhat)'}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Default Account</span>
              <div class="code-font" style="color: #fff;">${bcStatus.default_account || 'N/A'}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); font-size: 11px; text-transform: uppercase;">Test Account Balance</span>
              <div style="font-weight: 700; color: var(--success);">${bcStatus.account_balance_eth ? bcStatus.account_balance_eth.toFixed(4) : '0'} ETH</div>
            </div>
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color:var(--danger);">${err.message}</p></div>`;
  }
}

// ==========================================
// SHARING MODAL LOGIC
// ==========================================
async function openShareModal(recordId) {
  const modal = document.getElementById("share-modal");
  document.getElementById("modal-share-record-id").innerText = recordId;

  try {
    const orgs = await apiRequest("/organizations");
    const container = document.getElementById("modal-share-org-list");
    const myOrgId = state.user?.organization?.id;

    container.innerHTML = orgs.filter(o => o.id !== myOrgId).map(o => `
      <label style="display: flex; align-items: center; gap: 10px; cursor: pointer; font-size: 13px;">
        <input type="checkbox" name="modal_target_org" value="${o.id}">
        <span><strong>${o.name}</strong> (${o.code})</span>
      </label>
    `).join('');

    modal.classList.add("active");
  } catch (err) {
    showToast("Failed to load organizations", "danger");
  }
}

function closeShareModal() {
  document.getElementById("share-modal").classList.remove("active");
}

document.getElementById("close-share-modal")?.addEventListener("click", closeShareModal);
document.getElementById("cancel-share-modal")?.addEventListener("click", closeShareModal);

document.getElementById("modal-share-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const recordId = document.getElementById("modal-share-record-id").innerText;
  const targetOrgs = Array.from(document.querySelectorAll("input[name='modal_target_org']:checked")).map(cb => cb.value);
  const notes = document.getElementById("modal-share-notes").value;

  if (targetOrgs.length === 0) {
    showToast("Select at least one organization.", "warning");
    return;
  }

  try {
    await apiRequest("/share", {
      method: "POST",
      body: JSON.stringify({
        cti_record_id: recordId,
        target_organization_ids: targetOrgs,
        notes
      })
    });
    showToast("Threat Intelligence shared successfully!", "success");
    closeShareModal();
  } catch (err) {
    showToast(err.message, "danger");
  }
});

// ==========================================
// INITIALIZATION & EVENT WIRING
// ==========================================
document.addEventListener("DOMContentLoaded", async () => {
  // Navigation items
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
      const view = item.getAttribute("data-view");
      if (view) navigateTo(view);
    });
  });

  document.getElementById("btn-quick-scan")?.addEventListener("click", () => navigateTo("scanner"));

  // Auth toggle
  document.getElementById("toggle-to-register")?.addEventListener("click", (e) => {
    e.preventDefault();
    document.getElementById("login-form").style.display = "none";
    document.getElementById("register-form").style.display = "block";
    document.getElementById("auth-title").innerText = "Register New SOC";
  });

  document.getElementById("toggle-to-login")?.addEventListener("click", (e) => {
    e.preventDefault();
    document.getElementById("register-form").style.display = "none";
    document.getElementById("login-form").style.display = "block";
    document.getElementById("auth-title").innerText = "TrustCTI SOC Portal";
  });

  // Login submission
  document.getElementById("login-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;

    try {
      const res = await apiRequest("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password })
      });
      setAuthSession(res.access_token, res.user);
      showToast(`Welcome back, ${res.user.full_name || res.user.username}!`, "success");
      navigateTo("dashboard");
    } catch (err) {}
  });

  // Registration submission
  document.getElementById("register-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const orgName = document.getElementById("reg-org-name").value.trim();
    const orgCode = document.getElementById("reg-org-code").value.trim();
    const username = document.getElementById("reg-username").value.trim();
    const email = document.getElementById("reg-email").value.trim();
    const password = document.getElementById("reg-password").value;

    try {
      const res = await apiRequest("/auth/register", {
        method: "POST",
        body: JSON.stringify({
          organization_name: orgName,
          organization_code: orgCode,
          username,
          email,
          password
        })
      });
      setAuthSession(res.access_token, res.user);
      showToast("Organization registered successfully!", "success");
      navigateTo("dashboard");
    } catch (err) {}
  });

  document.getElementById("btn-logout")?.addEventListener("click", logout);

  // Check login state
  if (!state.token) {
    document.getElementById("auth-modal").classList.add("active");
    document.getElementById("auth-modal").style.display = "flex";
  } else {
    updateUserUI();
    navigateTo("dashboard");
  }

  // Periodic health check for blockchain node status
  checkNodeStatus();
  setInterval(checkNodeStatus, 15000);
});

async function checkNodeStatus() {
  try {
    const health = await apiRequest("/health");
    const pill = document.getElementById("blockchain-pill");
    const text = document.getElementById("blockchain-pill-text");
    if (health.blockchain && health.blockchain.connected) {
      pill.classList.remove("offline");
      text.innerText = `Ethereum Node: Block #${health.blockchain.latest_block}`;
    } else {
      pill.classList.add("offline");
      text.innerText = "Ethereum Node: Disconnected";
    }
  } catch (e) {}
}

