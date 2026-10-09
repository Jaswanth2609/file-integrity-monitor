let currentFindings = [];
let apiToken = localStorage.getItem("fim_api_token") || "";

function setApiToken(token) {
    apiToken = (token || "").trim();
    if (apiToken) {
        localStorage.setItem("fim_api_token", apiToken);
    } else {
        localStorage.removeItem("fim_api_token");
    }
    updateDownloadLinks();
    refreshData();
}

function updateDownloadLinks() {
    const tokenQuery = apiToken ? `?token=${encodeURIComponent(apiToken)}` : "";
    const htmlBtn = document.getElementById("link-download-html");
    const csvBtn = document.getElementById("link-download-csv");
    const jsonBtn = document.getElementById("link-download-json");
    if (htmlBtn) htmlBtn.href = `/api/reports/html${tokenQuery}`;
    if (csvBtn) csvBtn.href = `/api/reports/csv${tokenQuery}`;
    if (jsonBtn) jsonBtn.href = `/api/reports/json${tokenQuery}`;
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

function promptForToken() {
    const entered = prompt("Enter FIM Dashboard API Token (Bearer Token):", apiToken);
    if (entered !== null) {
        setApiToken(entered);
    }
}

async function refreshData() {
    document.getElementById("last-updated").innerText = "Updating...";
    updateDownloadLinks();

    // 1. Fetch baselines
    const baseData = await fetchJson("/baselines");
    const baselines = baseData?.baselines || [];
    document.getElementById("val-baselines").innerText = baselines.length;
    renderBaselines(baselines);

    // 2. Fetch findings
    const findingsData = await fetchJson("/findings");
    currentFindings = findingsData?.findings || [];
    renderFindings(currentFindings);

    // 3. Fetch audit chain
    const auditData = await fetchJson("/audit");
    if (auditData) {
        document.getElementById("val-chain").innerText = auditData.chain_valid ? "VERIFIED" : "TAMPERED";
        document.getElementById("val-chain").className = "metric-value " + (auditData.chain_valid ? "text-success" : "text-crit");
        renderAudit(auditData.events || []);
    }

    // Update metrics
    const critCount = currentFindings.filter(f => f.severity === "CRITICAL").length;
    const modCount = currentFindings.filter(f => ["MODIFIED", "ADDED"].includes(f.change_type)).length;
    document.getElementById("val-critical").innerText = critCount;
    document.getElementById("val-modified").innerText = modCount;

    document.getElementById("last-updated").innerText = `Updated: ${new Date().toLocaleTimeString()}`;
}

function renderFindings(findings) {
    const tbody = document.getElementById("findings-table-body");
    if (!findings || findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4" style="color:var(--text-muted);">No integrity violations detected. Clean baseline state.</td></tr>`;
        return;
    }

    tbody.innerHTML = findings.map(f => `
        <tr>
            <td><span class="badge badge-${(f.severity || 'info').toLowerCase()}">${f.severity || 'INFO'}</span></td>
            <td><strong>${f.change_type}</strong></td>
            <td class="code-font" title="${f.path}">${f.path.length > 40 ? '...' + f.path.slice(-37) : f.path}</td>
            <td>${f.description || ''}</td>
            <td><code>${f.attack_id || '—'}</code></td>
            <td>
                <button class="btn btn-secondary" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="acceptFinding(${f.id})">Accept</button>
            </td>
        </tr>
    `).join("");
}

function renderBaselines(baselines) {
    const tbody = document.getElementById("baselines-table-body");
    if (!baselines || baselines.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center py-4" style="color:var(--text-muted);">No baselines registered. Run 'fim baseline create' to create one.</td></tr>`;
        return;
    }

    tbody.innerHTML = baselines.map(b => `
        <tr>
            <td><strong>${b.name}</strong></td>
            <td>${b.file_count || 0}</td>
            <td><code>${b.algo || 'sha256'}</code></td>
            <td class="code-font">${(b.root_paths || []).join(', ')}</td>
            <td>${new Date(b.created_at * 1000).toLocaleString()}</td>
        </tr>
    `).join("");
}

function renderAudit(records) {
    const tbody = document.getElementById("audit-table-body");
    if (!records || records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4" style="color:var(--text-muted);">Audit log empty.</td></tr>`;
        return;
    }

    tbody.innerHTML = records.map(r => `
        <tr>
            <td>#${r.id}</td>
            <td><strong>${r.event}</strong></td>
            <td>${new Date(r.timestamp * 1000).toLocaleString()}</td>
            <td><code class="code-font" style="font-size:0.75rem;">${r.entry_hash ? r.entry_hash.slice(0, 24) + '...' : '—'}</code></td>
        </tr>
    `).join("");
}

function filterFindings() {
    const term = (document.getElementById("filter-search").value || "").toLowerCase();
    const filtered = currentFindings.filter(f => 
        (f.path || "").toLowerCase().includes(term) ||
        (f.description || "").toLowerCase().includes(term) ||
        (f.attack_id || "").toLowerCase().includes(term)
    );
    renderFindings(filtered);
}

async function triggerCheck() {
    const btn = event.target;
    btn.disabled = true;
    btn.innerText = "Checking...";
    await fetchJson("/checks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
    });
    await refreshData();
    btn.disabled = false;
    btn.innerText = "⚡ Run Integrity Check";
}

async function acceptFinding(id) {
    if (!confirm("Are you sure you want to accept and acknowledge this finding?")) return;
    await fetchJson(`/findings/${id}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: "dashboard-operator" })
    });
    await refreshData();
}

function switchTab(tab) {
    document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
    document.getElementById(`nav-${tab}`).classList.add("active");

    document.querySelectorAll(".data-card").forEach(el => el.classList.add("hidden"));
    document.getElementById(`section-${tab === "overview" ? "findings" : tab}`).classList.remove("hidden");

    const titles = {
        overview: "Security Overview",
        baselines: "Baseline Profiles",
        findings: "Integrity Findings",
        audit: "Cryptographic Audit Ledger"
    };
    document.getElementById("page-title").innerText = titles[tab] || "Security Overview";
}

// Initial load
document.addEventListener("DOMContentLoaded", () => {
    updateDownloadLinks();
    refreshData();
    // Auto-refresh every 15 seconds
    setInterval(refreshData, 15000);
});
