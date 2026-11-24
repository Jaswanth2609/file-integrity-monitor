// File Integrity Monitor (FIM) v2.3 - Web Dashboard Controller
// Strict security model: In-memory token storage (no localStorage persistence) & textContent DOM binding.

let currentFindings = [];
let apiToken = "";

// Ensure any previously persisted token in localStorage is purged
try {
    localStorage.removeItem("fim_api_token");
} catch (e) {}

function setApiToken(token) {
    apiToken = (token || "").trim();
    // Do NOT store token in localStorage to mitigate token theft via XSS or browser storage extraction
    refreshData();
}

async function fetchJson(endpoint, options = {}) {
    try {
        const headers = options.headers || {};
        if (apiToken) {
            headers["Authorization"] = `Bearer ${apiToken}`;
            headers["X-API-Key"] = apiToken;
        }
        options.headers = headers;

        const resp = await fetch(endpoint, options);
        if (resp.status === 401) {
            promptForToken();
            return null;
        }
        if (!resp.ok) return null;
        return await resp.json();
    } catch (e) {
        console.error("Fetch error:", e);
        return null;
    }
}

async function downloadReport(format) {
    try {
        const headers = {};
        if (apiToken) {
            headers["Authorization"] = `Bearer ${apiToken}`;
            headers["X-API-Key"] = apiToken;
        }
        const resp = await fetch(`/api/reports/${format}`, { headers });
        if (resp.status === 401) {
            promptForToken();
            return;
        }
        if (!resp.ok) {
            alert(`Failed to download report (${resp.status})`);
            return;
        }

        const blob = await resp.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.style.display = "none";
        a.href = url;
        a.download = `fim_report_default.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (e) {
        console.error("Download report error:", e);
        alert("Error generating or downloading report.");
    }
}

function promptForToken() {
    const entered = prompt("Enter FIM Dashboard API Token (Bearer Token):", apiToken || "");
    if (entered !== null) {
        setApiToken(entered);
    }
}

async function refreshData() {
    const updatedEl = document.getElementById("last-updated");
    if (updatedEl) updatedEl.innerText = "Updating...";

    // 1. Fetch baselines
    const baseData = await fetchJson("/baselines");
    const baselines = baseData?.baselines || [];
    const baseValEl = document.getElementById("val-baselines");
    if (baseValEl) baseValEl.innerText = baselines.length;
    renderBaselines(baselines);

    // 2. Fetch findings
    const findingsData = await fetchJson("/findings");
    currentFindings = findingsData?.findings || [];
    renderFindings(currentFindings);

    // 3. Fetch audit chain
    const auditData = await fetchJson("/audit");
    if (auditData) {
        const chainEl = document.getElementById("val-chain");
        if (chainEl) {
            chainEl.innerText = auditData.chain_valid ? "VERIFIED" : "TAMPERED";
            chainEl.className = "metric-value " + (auditData.chain_valid ? "text-success" : "text-crit");
        }
        renderAudit(auditData.events || []);
    }

    // Update metrics
    const critCount = currentFindings.filter(f => f.severity === "CRITICAL").length;
    const modCount = currentFindings.filter(f => ["MODIFIED", "ADDED"].includes(f.change_type)).length;
    const critValEl = document.getElementById("val-critical");
    const modValEl = document.getElementById("val-modified");
    if (critValEl) critValEl.innerText = critCount;
    if (modValEl) modValEl.innerText = modCount;

    if (updatedEl) updatedEl.innerText = `Updated: ${new Date().toLocaleTimeString()}`;
}

function renderFindings(findings) {
    const tbody = document.getElementById("findings-table-body");
    if (!tbody) return;
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    if (!findings || findings.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 6;
        td.className = "text-center py-4 text-muted";
        td.textContent = "No integrity violations detected. Clean baseline state.";
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }

    findings.forEach(f => {
        const tr = document.createElement("tr");

        // 1. Severity Badge
        const tdSev = document.createElement("td");
        const spanSev = document.createElement("span");
        const sevClass = (f.severity || "info").toLowerCase();
        spanSev.className = `badge badge-${sevClass}`;
        spanSev.textContent = f.severity || "INFO";
        tdSev.appendChild(spanSev);
        tr.appendChild(tdSev);

        // 2. Change Type
        const tdType = document.createElement("td");
        const strongType = document.createElement("strong");
        strongType.textContent = f.change_type || "";
        tdType.appendChild(strongType);
        tr.appendChild(tdType);

        // 3. File Path (safe textContent and safe title attribute to prevent attribute breakout)
        const tdPath = document.createElement("td");
        tdPath.className = "code-font";
        const pathStr = String(f.path || "");
        tdPath.setAttribute("title", pathStr);
        tdPath.textContent = pathStr.length > 40 ? "..." + pathStr.slice(-37) : pathStr;
        tr.appendChild(tdPath);

        // 4. Description (safe textContent to prevent stored XSS)
        const tdDesc = document.createElement("td");
        tdDesc.textContent = String(f.description || "");
        tr.appendChild(tdDesc);

        // 5. MITRE ATT&CK
        const tdAttack = document.createElement("td");
        const codeAttack = document.createElement("code");
        codeAttack.textContent = f.attack_id || "—";
        tdAttack.appendChild(codeAttack);
        tr.appendChild(tdAttack);

        // 6. Action Button (event listener instead of inline onclick)
        const tdActions = document.createElement("td");
        const btn = document.createElement("button");
        btn.className = "btn btn-secondary btn-sm";
        btn.textContent = "Accept";
        btn.addEventListener("click", () => acceptFinding(f.id));
        tdActions.appendChild(btn);
        tr.appendChild(tdActions);

        tbody.appendChild(tr);
    });
}

function renderBaselines(baselines) {
    const tbody = document.getElementById("baselines-table-body");
    if (!tbody) return;
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    if (!baselines || baselines.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 5;
        td.className = "text-center py-4 text-muted";
        td.textContent = "No baselines registered. Run 'fim baseline create' to create one.";
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }

    baselines.forEach(b => {
        const tr = document.createElement("tr");

        const tdName = document.createElement("td");
        const strongName = document.createElement("strong");
        strongName.textContent = b.name || "";
        tdName.appendChild(strongName);
        tr.appendChild(tdName);

        const tdCount = document.createElement("td");
        tdCount.textContent = b.file_count || 0;
        tr.appendChild(tdCount);

        const tdAlgo = document.createElement("td");
        const codeAlgo = document.createElement("code");
        codeAlgo.textContent = b.algo || "sha256";
        tdAlgo.appendChild(codeAlgo);
        tr.appendChild(tdAlgo);

        const tdPaths = document.createElement("td");
        tdPaths.className = "code-font";
        tdPaths.textContent = (b.root_paths || []).join(", ");
        tr.appendChild(tdPaths);

        const tdCreated = document.createElement("td");
        tdCreated.textContent = b.created_at ? new Date(b.created_at * 1000).toLocaleString() : "—";
        tr.appendChild(tdCreated);

        tbody.appendChild(tr);
    });
}

function renderAudit(records) {
    const tbody = document.getElementById("audit-table-body");
    if (!tbody) return;
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    if (!records || records.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 4;
        td.className = "text-center py-4 text-muted";
        td.textContent = "Audit log empty.";
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }

    records.forEach(r => {
        const tr = document.createElement("tr");

        const tdId = document.createElement("td");
        tdId.textContent = `#${r.id}`;
        tr.appendChild(tdId);

        const tdEvent = document.createElement("td");
        const strongEvent = document.createElement("strong");
        strongEvent.textContent = r.event || "";
        tdEvent.appendChild(strongEvent);
        tr.appendChild(tdEvent);

        const tdTime = document.createElement("td");
        tdTime.textContent = r.timestamp ? new Date(r.timestamp * 1000).toLocaleString() : "—";
        tr.appendChild(tdTime);

        const tdHash = document.createElement("td");
        const codeHash = document.createElement("code");
        codeHash.className = "code-font text-xs";
        codeHash.textContent = r.entry_hash ? r.entry_hash.slice(0, 24) + "..." : "—";
        tdHash.appendChild(codeHash);
        tr.appendChild(tdHash);

        tbody.appendChild(tr);
    });
}

function filterFindings() {
    const inputEl = document.getElementById("filter-search");
    const term = (inputEl ? inputEl.value || "" : "").toLowerCase();
    const filtered = currentFindings.filter(f =>
        (f.path || "").toLowerCase().includes(term) ||
        (f.description || "").toLowerCase().includes(term) ||
        (f.attack_id || "").toLowerCase().includes(term)
    );
    renderFindings(filtered);
}

async function triggerCheck(e) {
    const btn = document.getElementById("btn-check") || (e ? e.target : null);
    if (btn) {
        btn.disabled = true;
        btn.innerText = "Checking...";
    }
    await fetchJson("/checks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
    });
    await refreshData();
    if (btn) {
        btn.disabled = false;
        btn.innerText = "⚡ Run Integrity Check";
    }
}

async function acceptFinding(id) {
    if (!confirm("Are you sure you want to accept and acknowledge this finding?")) return;
    // Server-side identity configuration dictates reviewer attribution to prevent audit forgery
    await fetchJson(`/findings/${id}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
    });
    await refreshData();
}

function switchTab(tab) {
    document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
    const activeNav = document.getElementById(`nav-${tab}`);
    if (activeNav) activeNav.classList.add("active");

    document.querySelectorAll(".data-card").forEach(el => el.classList.add("hidden"));
    const targetSection = document.getElementById(`section-${tab === "overview" ? "findings" : tab}`);
    if (targetSection) targetSection.classList.remove("hidden");

    const titles = {
        overview: "Security Overview",
        baselines: "Baseline Profiles",
        findings: "Integrity Findings",
        audit: "Cryptographic Audit Ledger"
    };
    const titleEl = document.getElementById("page-title");
    if (titleEl) titleEl.innerText = titles[tab] || "Security Overview";
}

// Initial load & unobtrusive event binding (adhering to strict Content-Security-Policy)
document.addEventListener("DOMContentLoaded", () => {
    // Navigation items
    document.getElementById("nav-overview")?.addEventListener("click", () => switchTab("overview"));
    document.getElementById("nav-baselines")?.addEventListener("click", () => switchTab("baselines"));
    document.getElementById("nav-findings")?.addEventListener("click", () => switchTab("findings"));
    document.getElementById("nav-audit")?.addEventListener("click", () => switchTab("audit"));

    // Report download buttons
    document.getElementById("link-download-html")?.addEventListener("click", () => downloadReport("html"));
    document.getElementById("link-download-csv")?.addEventListener("click", () => downloadReport("csv"));
    document.getElementById("link-download-json")?.addEventListener("click", () => downloadReport("json"));

    // Top action buttons
    document.getElementById("btn-token")?.addEventListener("click", promptForToken);
    document.getElementById("btn-refresh")?.addEventListener("click", refreshData);
    document.getElementById("btn-check")?.addEventListener("click", triggerCheck);

    // Search input
    document.getElementById("filter-search")?.addEventListener("input", filterFindings);

    refreshData();
    // Auto-refresh every 15 seconds
    setInterval(refreshData, 15000);
});
