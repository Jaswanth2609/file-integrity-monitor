let currentFindings = [];

async function fetchJson(endpoint, options = {}) {
    try {
        const resp = await fetch(endpoint, options);
        if (!resp.ok) return null;
        return await resp.json();
    } catch (e) {
        console.error("Fetch error:", e);
        return null;
    }
}

async function refreshData() {
    document.getElementById("last-updated").innerText = "Updating...";

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
        renderAudit(auditData.audit_records || []);
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
            <td><code class="code-font" style="font-size:0.75rem;">${r.entry_hash.slice(0, 24)}...</code></td>
        </tr>
    `).join("");
}

function filterFindings() {
    const query = document.getElementById("filter-search").value.toLowerCase();
    const filtered = currentFindings.filter(f => 
        (f.path && f.path.toLowerCase().includes(query)) ||
        (f.description && f.description.toLowerCase().includes(query)) ||
        (f.new_hash && f.new_hash.toLowerCase().includes(query))
    );
    renderFindings(filtered);
}

async function triggerCheck() {
    const res = await fetchJson("/checks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile: "default" })
    });
    if (res) {
        alert(`Integrity check finished! Exit code: ${res.exit_code}. Changes found: ${res.changes_found}`);
        refreshData();
    }
}

async function acceptFinding(id) {
    if (!id) return;
    await fetchJson(`/findings/${id}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: "web-dashboard" })
    });
    refreshData();
}

function switchTab(tabName) {
    document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
    document.getElementById(`nav-${tabName}`).classList.add("active");

    document.getElementById("section-findings").classList.add("hidden");
    document.getElementById("section-baselines").classList.add("hidden");
    document.getElementById("section-audit").classList.add("hidden");

    if (tabName === "overview" || tabName === "findings") {
        document.getElementById("section-findings").classList.remove("hidden");
        document.getElementById("page-title").innerText = tabName === "overview" ? "Security Overview" : "Integrity Findings";
    } else if (tabName === "baselines") {
        document.getElementById("section-baselines").classList.remove("hidden");
        document.getElementById("page-title").innerText = "Monitored Baselines";
    } else if (tabName === "audit") {
        document.getElementById("section-audit").classList.remove("hidden");
        document.getElementById("page-title").innerText = "Immutable Audit Ledger";
    }
}

document.addEventListener("DOMContentLoaded", () => {
    refreshData();
    setInterval(refreshData, 10000);
});
