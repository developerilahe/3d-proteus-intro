let currentData = null;
let currentReport = "";
let activeFilter = "ALL";
let selectedDomain = null;
let activeMapTab = "geo";
let activeOsintDomain = null;
let currentScanId = null;
let pollInterval = null;

document.addEventListener("DOMContentLoaded", () => {
    const scanBtn = document.getElementById("scan-btn");
    if (!scanBtn) {
        console.error("PROTEUS: #scan-btn not found — index.html is stale.");
        return;
    }
    scanBtn.onclick = runScan;

    document.querySelectorAll(".nav-links a").forEach(a => {
        a.onclick = (e) => {
            e.preventDefault();
            document.querySelectorAll(".nav-links a").forEach(x => x.classList.remove("active"));
            document.querySelectorAll(".view").forEach(x => x.classList.remove("active"));
            e.target.classList.add("active");
            const view = document.getElementById(e.target.dataset.view);
            if (view) view.classList.add("active");
            if (e.target.dataset.view === "view-constellation") renderMap();
            if (e.target.dataset.view === "view-osint") renderOsintMatrixView();
        };
    });

    document.querySelectorAll(".pill").forEach(p => {
        p.onclick = () => {
            document.querySelectorAll(".pill").forEach(x => x.classList.remove("active"));
            p.classList.add("active");
            activeFilter = p.dataset.filter;
            renderTriageList();
        };
    });
});

async function runScan() {
    const brandInput = document.getElementById("brand-input");
    const passInput = document.getElementById("scan-pass");
    const onlineInput = document.getElementById("online-toggle");
    const inspectInput = document.getElementById("inspect-toggle");
    const btn = document.getElementById("scan-btn");
    const drawer = document.getElementById("investigation-drawer");
    const progressContainer = document.getElementById("scan-progress");

    if (!brandInput || !btn) {
        console.error("PROTEUS: required DOM nodes missing.");
        return;
    }

    const brand = brandInput.value.trim() || "acmecorp.com";
    const scanPass = parseInt((passInput && passInput.value) || "1", 10);
    const online = !!(onlineInput && onlineInput.checked);
    const inspect = !!(inspectInput && inspectInput.checked);

    const searchInput = document.getElementById("search-input");
    if (searchInput) searchInput.value = "";
    if (drawer) drawer.innerHTML = `<div class="empty-state">Initializing scan…</div>`;
    if (progressContainer) progressContainer.classList.remove("hidden");

    btn.textContent = "Starting...";
    btn.disabled = true;

    clearInterval(pollInterval);
    pollInterval = null;

    try {
        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ brand, scan_pass: scanPass, online_enrich: online, inspect_websites: inspect }),
        });

        if (!res.ok) {
            const text = await res.text();
            throw new Error(`HTTP ${res.status} — ${text.slice(0, 200)}`);
        }

        const startData = await res.json();
        currentScanId = startData.scan_id;
        console.log("PROTEUS scan started:", currentScanId);

        await pollScanProgress(currentScanId);

        const resultsRes = await fetch(`/api/scan/${currentScanId}/results`);
        if (!resultsRes.ok) {
            const text = await resultsRes.text();
            throw new Error(`HTTP ${resultsRes.status} — ${text.slice(0, 200)}`);
        }

        currentData = await resultsRes.json();
        console.log("PROTEUS scan complete:", currentData);

        if (progressContainer) progressContainer.classList.add("hidden");

        if (!currentData.findings || currentData.findings.length === 0) {
            if (drawer) drawer.innerHTML = `<div class="empty-state">Scan returned zero findings. Brand has no matching fixture entries.</div>`;
            renderKPIs();
            renderTriageList();
            return;
        }

        renderKPIs();
        renderTriageList();
        renderHistory();
        renderMap();
        renderOsintMatrixView();

        const firstRow = document.querySelector(".finding-row");
        if (firstRow) firstRow.click();
    } catch (err) {
        console.error("PROTEUS scan failed:", err);
        if (progressContainer) progressContainer.classList.add("hidden");
        if (drawer) {
            drawer.innerHTML = `
                <div class="empty-state" style="color:var(--crit);">
                    <strong>Scan failed:</strong> ${err.message}<br>
                    <span style="color:var(--text-mute);font-size:12px;">Check the browser console and the uvicorn terminal.</span>
                </div>`;
        }
        const list = document.getElementById("findings-list");
        if (list) {
            list.innerHTML = `<div class="empty-state" style="color:var(--crit);">Error: ${err.message}</div>`;
        }
    } finally {
        btn.textContent = "Execute";
        btn.disabled = false;
        clearInterval(pollInterval);
        pollInterval = null;
    }
}

async function pollScanProgress(scanId) {
    const progressContainer = document.getElementById("scan-progress");
    const progressBar = document.getElementById("progress-bar");
    const progressText = document.getElementById("progress-text");
    const progressStep = document.getElementById("progress-step");
    const progressCounts = document.getElementById("progress-counts");

    return new Promise((resolve, reject) => {
        pollInterval = setInterval(async () => {
            try {
                const res = await fetch(`/api/scan/${scanId}/status`);
                if (!res.ok) {
                    const text = await res.text();
                    throw new Error(`HTTP ${res.status} — ${text.slice(0, 200)}`);
                }
                const status = await res.json();

                if (progressBar) progressBar.style.width = `${status.progress_pct}%`;
                if (progressText) progressText.textContent = `${status.progress_pct}%`;
                if (progressStep) progressStep.textContent = status.current_step;
                if (progressCounts) {
                    progressCounts.textContent = `${status.domains_processed}/${status.domains_total} domains • ${status.findings_so_far} findings`;
                }

                if (status.status === "complete") {
                    clearInterval(pollInterval);
                    pollInterval = null;
                    resolve();
                } else if (status.status === "failed") {
                    clearInterval(pollInterval);
                    pollInterval = null;
                    reject(new Error(status.error || "Scan failed"));
                }
            } catch (err) {
                clearInterval(pollInterval);
                pollInterval = null;
                reject(err);
            }
        }, 1000);
    });
}

function highlightConfusables(domain) {
    return domain.replace(/[^\x00-\x7F]/g, m => `<span class="confusable">${m}</span>`);
}

function importanceClass(imp) {
    if (imp === "Very High") return "imp-vhigh";
    if (imp === "High") return "imp-high";
    if (imp === "Medium") return "imp-med";
    return "imp-low";
}

function renderKPIs() {
    const bar = document.getElementById("kpi-bar");
    if (!bar || !currentData) return;
    const imp = currentData.impact || {};
    const liveCount = (currentData.findings || []).filter(
        f => f.status === "LIVE INFRA" || f.status === "DRIFT DETECTED"
    ).length;
    const driftCount = (currentData.findings || []).filter(f => f.drift || f.precrime).length;
    const clusterCount = (currentData.clusters || []).length;

    bar.innerHTML = `
        <div class="kpi-box"><span class="kpi-label">Total Candidates</span><span class="kpi-value">${currentData.generated || 0}</span></div>
        <div class="kpi-box"><span class="kpi-label">Live Threats</span><span class="kpi-value" style="color:var(--crit)">${liveCount}</span></div>
        <div class="kpi-box"><span class="kpi-label">Campaign Clusters</span><span class="kpi-value">${clusterCount}</span></div>
        <div class="kpi-box"><span class="kpi-label">Drift / PreCrime</span><span class="kpi-value" style="color:var(--watch)">${driftCount}</span></div>
        <div class="kpi-box"><span class="kpi-label">Est. Triage Saved</span><span class="kpi-value">${imp.triage_hours || 0} hrs</span></div>
    `;
}

function renderTriageList() {
    const list = document.getElementById("findings-list");
    if (!list || !currentData) return;
    list.innerHTML = "";
    let filtered = currentData.findings || [];

    if (activeFilter !== "ALL") {
        if (activeFilter === "LIVE") filtered = filtered.filter(f => f.status === "LIVE INFRA");
        else if (activeFilter === "DRIFT") filtered = filtered.filter(f => f.status === "DRIFT DETECTED");
        else if (activeFilter === "PRECRIME") filtered = filtered.filter(f => f.status === "PRECRIME");
        else filtered = filtered.filter(f => f.tier === activeFilter);
    }

    const searchInput = document.getElementById("search-input");
    const q = (searchInput && searchInput.value ? searchInput.value : "").toLowerCase();
    if (q) {
        filtered = filtered.filter(f =>
            f.domain.toLowerCase().includes(q) ||
            (f.candidate && f.candidate.technique || "").toLowerCase().includes(q) ||
            (f.candidate && f.candidate.technique.replace("_", " ").title() || "").toLowerCase().includes(q)
        );
    }

    if (filtered.length === 0) {
        list.innerHTML = `<div class="empty-state">No findings match this filter.</div>`;
        return;
    }

    filtered.forEach(f => {
        const el = document.createElement("div");
        el.className = `finding-row tier-${f.tier}`;
        if (selectedDomain === f.domain) el.classList.add("active");

        const badgeClass = f.status === "DRIFT DETECTED" ? "badge drift"
            : f.status === "LIVE INFRA" ? "badge live"
            : f.status === "UNRESOLVED" ? "badge mute"
            : "badge";

        const techniqueLabel = f.candidate ? f.candidate.technique.replace("_", " ").title() : f.technique_label;
        const initialImportance = f.candidate ? f.candidate.importance : f.initial_importance;
        const initialWeight = f.candidate ? f.candidate.weight : f.initial_weight;

        el.innerHTML = `
            <div class="f-row-left">
                <span class="f-domain">${highlightConfusables(f.domain)}</span>
                <div class="f-tags">
                    <span class="badge">${f.tier}</span>
                    <span class="${badgeClass}">${f.status}</span>
                    <span class="technique-tag ${importanceClass(initialImportance)}">${techniqueLabel} · ${initialImportance} (${initialWeight}/100)</span>
                </div>
                <div class="f-subrow">
                    <span class="sub-label">Sim ${f.similarity_pct}%</span>
                    <span class="sub-label">${f.mutation_type}</span>
                </div>
            </div>
            <span class="f-score">${f.score}</span>
        `;
        el.onclick = () => {
            selectedDomain = f.domain;
            activeOsintDomain = f.domain;
            document.querySelectorAll(".finding-row").forEach(r => r.classList.remove("active"));
            el.classList.add("active");
            renderDossier(f);
            renderOsintMatrixView();
        };
        list.appendChild(el);
    });
}

function switchDossierTab(tabId) {
    document.querySelectorAll(".dossier-tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(t => t.classList.remove("active"));
    const tab = document.querySelector(`[data-tab="${tabId}"]`);
    const pane = document.getElementById(tabId);
    if (tab) tab.classList.add("active");
    if (pane) pane.classList.add("active");
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[char]);
}

function lookupRows(label, result, fields = []) {
    const status = {
        found: "Found", no_records: "No records found", lookup_failed: "Lookup failed",
        source_unavailable: "Source unavailable", not_collected: "Data not collected"
    }[result.status];
    const retry = result.retry_after_seconds == null
        ? null : "Retry after " + result.retry_after_seconds + "s";
    const provenance = [status, result.source, result.checked_at, result.detail, retry].filter(Boolean);
    const rows = [[label, provenance.join(" · ")], ...fields].filter(([, value]) =>
        value != null && value !== "" && (!Array.isArray(value) || value.length)
    );
    return '<div class="data-block">' + rows.map(([key, value]) =>
        '<div class="data-row"><span class="data-label">' + escapeHtml(key)
        + '</span><span style="overflow-wrap:anywhere">' + escapeHtml(
            Array.isArray(value) ? value.join(", ") : value
        ) + '</span></div>'
    ).join("") + '</div>';
}

function liveDnsRows(enrichment) {
    const registration = enrichment.rdap.data || {};
    const fields = [
        ["Registrar", registration.registrar], ["Registered", registration.registration_date],
        ["Expires", registration.expiration_date], ["Domain status", registration.domain_statuses],
        ["Registry nameservers", registration.nameservers]
    ];
    const dns = Object.entries(enrichment.dns).map(([type, result]) =>
        lookupRows(type.toUpperCase(), result, [["Records", result.data]])
    ).join("");
    const certificates = enrichment.certificates.data || [];
    const certFields = certificates.length ? [["Entries", certificates.length]] : [];
    certificates.slice(0, 5).forEach(cert => {
        certFields.push(["Names", cert.names], ["Issuer", cert.issuer],
            ["Logged", cert.logged_at], ["Valid from", cert.not_before], ["Valid until", cert.not_after]);
    });
    if (certificates.length > 5) certFields.push(["Full list", "Available in the JSON export"]);
    const note = enrichment.collection_note ? '<p>' + escapeHtml(enrichment.collection_note) + '</p>' : "";
    return note + lookupRows("RDAP", enrichment.rdap, fields) + dns
        + lookupRows("Certificate Transparency", enrichment.certificates, certFields);
}

function liveIpRows(infrastructure) {
    if (!infrastructure.length) return '<p>No addresses available for infrastructure lookup.</p>';
    return infrastructure.map(ip => {
        const network = ip.registration.data || {};
        return lookupRows(ip.address + " registration", ip.registration, [
            ["Allocation name", network.name], ["Registry handle", network.handle],
            ["Range start", network.start_address], ["Range end", network.end_address],
            ["Registration country", network.country_code]
        ]) + lookupRows(ip.address + " PTR", ip.ptr, [["Names", ip.ptr.data]]);
    }).join("");
}

function reputationRows(result) {
    const data = result.data || {};
    return lookupRows("Reputation", result, [
        ["Malicious", data.malicious], ["Suspicious", data.suspicious], ["Harmless", data.harmless],
        ["Undetected", data.undetected], ["Matched URLs", data.matched_url_count],
        ["Last analysis", data.last_analysis_at]
    ]);
}

function renderDossier(f) {
    const drawer = document.getElementById("investigation-drawer");
    if (!drawer || !currentData) return;
    const impact = currentData.impact || {};
    const live = currentData.online_enrich ? f.enrichment : null;

    const signalsHtml = (f.signals || []).map(s => `
        <div class="signal-item">
            <span style="color:var(--text-dim)">${escapeHtml(s.label)}${s.evidence ? ` <span class="evidence">— ${escapeHtml(s.evidence)}</span>` : ""}</span>
            <span class="signal-pts">+${s.points}</span>
        </div>
    `).join("");

    const newsHtml = ((f.osint && f.osint.intel) || []).map(n => `
        <div class="news-card">
            <div class="news-header">
                <div>
                    <div class="news-source">${n.source}</div>
                    <div class="news-type">${n.type} · ${n.sentiment}</div>
                </div>
                <span class="news-badge ${n.kind}">${n.kind === "live" ? "LIVE PUBLIC" : "OFFLINE FIXTURE"}</span>
            </div>
            <div class="news-title">${n.title}</div>
            <div class="news-summary">${n.summary}</div>
            <div class="news-meta" style="display:flex; justify-content:space-between; align-items:center; margin-top:12px;">
                <span>${n.date.slice(0,19).replace("T"," ")} UTC</span>
                ${n.link && n.link !== "#" ? `<a href="${n.link}" target="_blank" rel="noopener noreferrer" class="intel-link">View Source ↗</a>` : ""}
            </div>
        </div>
    `).join("") || `<p style="color:var(--text-mute);">No external news or advisories observed.</p>`;

    const osintLinksHtml = Object.entries((f.osint && f.osint.links) || {}).map(([category, links]) => `
        <div class="osint-category">
            <div class="osint-cat-title">${category.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</div>
            ${links.map(l => `
                <div class="osint-link-item">
                    <div style="display:flex; justify-content:space-between; align-items:center; width:100%;">
                        <span class="osint-source">${l.source}</span>
                        <a href="${l.url}" target="_blank" rel="noopener noreferrer" class="intel-link">Open ↗</a>
                    </div>
                    <span class="osint-desc">${l.desc}</span>
                </div>
            `).join("")}
        </div>
    `).join("");

    const timelineHtml = (f.timeline || []).map(t => `
        <div class="timeline-item">
            <span class="timeline-date">${t.time.slice(0,10)}</span>
            <span class="timeline-event"><span class="timeline-kind">${t.kind}</span>${t.event}</span>
        </div>
    `).join("");

    const driftHtml = f.drift ? `
        <div class="drift-box">
            <div style="color:var(--text-mute); margin-bottom:6px; font-size:11px; text-transform:uppercase;">Scan #1</div>
            <div>${f.drift_data.before}</div>
            <div style="color:var(--text-mute); margin-top:14px; margin-bottom:6px; font-size:11px; text-transform:uppercase;">Scan #2</div>
            <div style="color:var(--crit)">${f.drift_data.after}</div>
        </div>
    ` : `<p style="color:var(--text-mute);">No drift between scan passes.</p>`;

    const isEligible = f.status === "LIVE INFRA" || f.status === "DRIFT DETECTED";
    const mispHref = currentScanId ? `/api/export/misp/${encodeURIComponent(f.domain)}?scan_id=${currentScanId}` : `/api/export/misp/${encodeURIComponent(f.domain)}`;
    const actionHtml = isEligible
        ? `<div style="display:flex; gap:8px; flex-wrap:wrap;">
              <button onclick="openTakedown('${f.domain}')">Generate Takedown Report</button>
              <a class="btn-outline" style="text-decoration:none; padding:8px 12px;" href="${mispHref}" download>Download MISP JSON</a>
           </div>`
        : `<div style="font-family:var(--font-data); font-size:13px; color:var(--text-mute); padding:16px; border:1px dashed var(--border); text-align:center; border-radius:2px;">No active hosting observed. Takedown not applicable.</div>`;

    const dns = f.facts || {};
    const rdap = f.facts ? {
        registrar: f.facts.registrar,
        created_days_ago: f.facts.created_days_ago
    } : {};
    const tls = f.facts ? {
        issuer: f.facts.tls_issuer,
        subject: f.facts.tls_subject,
        fingerprint: f.facts.tls_fingerprint,
        not_before: f.facts.tls_not_before,
        not_after: f.facts.tls_not_after,
        sans: f.facts.tls_sans
    } : {};
    const pastIpsHtml = (f.facts && f.facts.past_ips && f.facts.past_ips.length > 0)
        ? f.facts.past_ips.map(p => `<div class="data-row"><span class="data-label">Past IP</span><span>${p.ip} · ${(p.seen || "").slice(0,10)}</span></div>`).join("")
        : `<div class="data-row"><span class="data-label">Past IPs</span><span>None recorded</span></div>`;

    const dataSource = f.facts ? f.facts.source : "NO DATA";
    const inspectionBadge = f.inspection ? `<span class="badge" style="background:var(--low);color:var(--bg);">LIVE INSPECTION</span>` : `<span class="badge mute">FIXTURE MODEL</span>`;

    drawer.innerHTML = `
        <div class="dossier-header">
            <div class="dossier-domain">${highlightConfusables(f.domain)}</div>
            <div class="dossier-meta">
                <span>${f.candidate ? f.candidate.ascii_form : f.punycode}</span><span>·</span><span>${f.status}</span><span>·</span><span>${f.candidate ? f.candidate.registrable : f.registrable}</span>
                ${inspectionBadge}
            </div>
            <div class="dossier-score">${f.score}<span style="font-size:16px; color:var(--text-mute)"> / 100</span></div>
            <div style="font-family:var(--font-data); font-size:13px; color:var(--accent); margin-top:6px;">
                Name Similarity ${f.similarity_pct}% · ${f.mutation_type}
            </div>
            <div class="technique-banner ${importanceClass(f.candidate ? f.candidate.importance : f.initial_importance)}">
                <span class="technique-name">${f.candidate ? f.candidate.technique.replace("_", " ").title() : f.technique_label}</span>
                <span class="technique-meta">Initial importance: <strong>${f.candidate ? f.candidate.importance : f.initial_importance}</strong> · Initial heuristic weight: <strong>${f.candidate ? f.candidate.weight : f.initial_weight}/100</strong> · <em>Adjusted by context & observed evidence</em></span>
            </div>
        </div>

        <div class="dossier-tabs">
            <div class="dossier-tab active" data-tab="tab-overview" onclick="switchDossierTab('tab-overview')">Overview & Impact</div>
            <div class="dossier-tab" data-tab="tab-dns" onclick="switchDossierTab('tab-dns')">DNS, Mail & TLS</div>
            <div class="dossier-tab" data-tab="tab-network" onclick="switchDossierTab('tab-network')">IP, ASN & Geo</div>
            <div class="dossier-tab" data-tab="tab-dna" onclick="switchDossierTab('tab-dna')">Brand DNA & Drift</div>
            <div class="dossier-tab" data-tab="tab-osint" onclick="switchDossierTab('tab-osint')">OSINT & Threat Intel</div>
            <div class="dossier-tab" data-tab="tab-actions" onclick="switchDossierTab('tab-actions')">Takedown & MISP</div>
        </div>

        <div class="dossier-content">
            <div id="tab-overview" class="tab-pane active">
                <div class="section-title">Risk Signals</div>
                ${signalsHtml}
                <div class="section-title">Business Impact (Modeled)</div>
                <div class="data-grid">
                    <div class="data-block">
                        <div class="data-row"><span class="data-label">Harm Category</span><span>${impact.harm_category || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">Triage Hours Saved</span><span>${impact.triage_hours || 0} hrs</span></div>
                    </div>
                    <div class="data-block">
                        <div class="data-row"><span class="data-label">Exposure (Modeled)</span><span>${impact.exposure_low || "N/A"} - ${impact.exposure_high || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">Defensive Cost</span><span>${impact.defensive_cost || "N/A"}</span></div>
                    </div>
                </div>
                ${live ? "" : `<div class="section-title">Historical Timeline</div><div class="timeline">${timelineHtml}</div>`}
            </div>

            <div id="tab-dns" class="tab-pane">
                ${live ? liveDnsRows(live) : `
                <div class="section-title">DNS & Mail Posture</div>
                <div class="data-grid">
                    <div class="data-block">
                        <div class="data-row"><span class="data-label">A Records</span><span>${(dns.a_records || []).join(", ") || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">AAAA Records</span><span>${(dns.aaaa_records || []).join(", ") || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">MX Records</span><span>${(dns.mx_records || []).join(", ") || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">NS Records</span><span>${(dns.ns_records || []).join(", ") || "N/A"}</span></div>
                    </div>
                    <div class="data-block">
                        <div class="data-row"><span class="data-label">SPF</span><span>${dns.spf ? "✅ Present" : "❌ Missing"}</span></div>
                        <div class="data-row"><span class="data-label">DMARC</span><span>${dns.dmarc ? "✅ Present" : "❌ Missing"}</span></div>
                        <div class="data-row"><span class="data-label">Registrar</span><span>${rdap.registrar || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">Created</span><span>${rdap.created_days_ago !== null && rdap.created_days_ago !== undefined ? rdap.created_days_ago + " days ago" : "N/A"}</span></div>
                    </div>
                </div>
                <div class="section-title">TLS / SSL Certificate</div>
                <div class="data-grid">
                    <div class="data-block">
                        <div class="data-row"><span class="data-label">Issuer</span><span>${tls.issuer || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">Subject CN</span><span>${tls.subject || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">Fingerprint</span><span style="word-break:break-all;">${tls.fingerprint || "N/A"}</span></div>
                    </div>
                    <div class="data-block">
                        <div class="data-row"><span class="data-label">Not Before</span><span>${tls.not_before && tls.not_before !== "N/A" ? tls.not_before.slice(0,10) : "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">Not After</span><span>${tls.not_after && tls.not_after !== "N/A" ? tls.not_after.slice(0,10) : "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">SANs</span><span>${(tls.sans || []).join(", ") || "N/A"}</span></div>
                    </div>
                </div>
                <div class="section-title">Data Source</div>
                <div class="data-block">
                    <div class="data-row"><span class="data-label">Source</span><span>${dataSource}</span></div>
                </div>
            </div>

            <div id="tab-network" class="tab-pane">
                ${live ? liveIpRows(live.infrastructure) : `
                <div class="section-title">IP & ASN Ownership</div>
                <div class="data-grid">
                    <div class="data-block">
                        <div class="data-row"><span class="data-label">ASN</span><span>${dns.asn || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">ASN Org</span><span>${dns.asn_org || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">Country</span><span>${dns.country || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">Role</span><span>${dns.infra_role || "N/A"}</span></div>
                    </div>
                    <div class="data-block">
                        <div class="data-row"><span class="data-label">Netblock</span><span>${dns.netblock || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">rDNS / PTR</span><span>${dns.rdns || "N/A"}</span></div>
                        <div class="data-row"><span class="data-label">Abuse Contact</span><span>${dns.abuse_contact || "N/A"}</span></div>
                    </div>
                </div>
                <div class="section-title">Historical IPs</div>
                <div class="data-block">${pastIpsHtml}</div>
                `}
            </div>

            <div id="tab-dna" class="tab-pane">
                ${live ? '<p>Brand DNA and drift were not collected.</p>' : f.dna ? `
                <div class="section-title">Brand DNA Match</div>
                <div class="data-grid">
                    <div class="data-block">
                        <div class="data-row"><span class="data-label">Impersonation Similarity</span><strong>${f.dna.similarity_pct}%</strong></div>
                        <div class="data-row"><span class="data-label">Logo Match</span><span>${f.dna.logo_match ? "✅ YES" : "❌ NO"}</span></div>
                    </div>
                    <div class="data-block">
                        <div class="data-row"><span class="data-label">Login Form</span><span>${f.dna.login_form ? "✅ YES" : "❌ NO"}</span></div>
                        <div class="data-row"><span class="data-label">Visual Match</span><span>${f.dna.visual_match ? "✅ YES" : "❌ NO"}</span></div>
                    </div>
                </div>
                <div style="font-family:var(--font-data); font-size:12px; color:var(--text-dim); margin-top:12px; padding:12px; background:var(--bg); border:1px solid var(--border); border-radius:2px;">
                    Matched phrases: ${(f.dna.matched_phrases || []).join(", ")}
                </div>
                <div class="section-title">Identity Drift</div>
                ${driftHtml}
                ` : `<p style="color:var(--text-mute);">Not observed — domain is inactive.</p>`}
            </div>

            <div id="tab-osint" class="tab-pane">
                ${live ? reputationRows(live.reputation) : `<div class="section-title">News & Advisories</div>${newsHtml}`}
                <div class="section-title">External OSINT Sources</div>
                <div class="osint-grid">${osintLinksHtml}</div>
            </div>

            <div id="tab-actions" class="tab-pane">
                <div class="section-title">Takedown & Threat Intel</div>
                ${actionHtml}
            </div>
        </div>
    `;
}

function renderHistory() {
    const grid = document.getElementById("drift-matrix");
    if (!grid || !currentData) return;
    grid.innerHTML = "";

    const drift = (currentData.findings || []).filter(f => f.drift);
    const precrime = (currentData.findings || []).filter(f => f.precrime && !f.drift);

    if (drift.length === 0 && precrime.length === 0) {
        grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1">No history or PreCrime data in this scan. Try Scan #2 (Drift Check).</div>`;
        return;
    }

    drift.forEach(f => {
        const card = document.createElement("div");
        card.className = "matrix-card";
        card.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <div class="f-domain" style="font-size:15px;">${highlightConfusables(f.domain)}</div>
                <span class="badge drift">DRIFT DETECTED</span>
            </div>
            <div class="technique-tag ${importanceClass(f.candidate ? f.candidate.importance : f.initial_importance)}" style="margin-bottom:12px;">
                ${f.candidate ? f.candidate.technique.replace("_", " ").title() : f.technique_label} · ${f.candidate ? f.candidate.importance : f.initial_importance} (${f.candidate ? f.candidate.weight : f.initial_weight}/100)
            </div>
            <div style="font-family:var(--font-data); font-size:11px; color:var(--text-mute); margin-bottom:6px; text-transform:uppercase;">Scan #1</div>
            <div style="font-family:var(--font-data); font-size:13px; color:var(--text-dim); margin-bottom:12px;">
                ${(f.drift_data && f.drift_data.before) || "N/A"}
            </div>
            <div style="font-family:var(--font-data); font-size:11px; color:var(--text-mute); margin-bottom:6px; text-transform:uppercase;">Scan #2</div>
            <div style="font-family:var(--font-data); font-size:13px; color:var(--crit);">
                ${(f.drift_data && f.drift_data.after) || "N/A"}
            </div>
        `;
        card.onclick = () => {
            selectedDomain = f.domain;
            activeOsintDomain = f.domain;
            document.querySelectorAll(".finding-row").forEach(r => r.classList.remove("active"));
            const row = [...document.querySelectorAll(".finding-row")].find(r =>
                r.querySelector(".f-domain") && r.querySelector(".f-domain").textContent.includes(f.domain)
            );
            if (row) row.classList.add("active");
            renderDossier(f);
            renderOsintMatrixView();
        };
        grid.appendChild(card);
    });

    precrime.forEach(f => {
        const card = document.createElement("div");
        card.className = "matrix-card";
        card.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <div class="f-domain" style="font-size:15px;">${highlightConfusables(f.domain)}</div>
                <span class="badge" style="background:var(--watch); color:var(--bg);">PRECRIME</span>
            </div>
            <div class="technique-tag ${importanceClass(f.candidate ? f.candidate.importance : f.initial_importance)}" style="margin-bottom:12px;">
                ${f.candidate ? f.candidate.technique.replace("_", " ").title() : f.technique_label} · ${f.candidate ? f.candidate.importance : f.initial_importance} (${f.candidate ? f.candidate.weight : f.initial_weight}/100)
            </div>
            <div style="font-family:var(--font-data); font-size:11px; color:var(--text-mute); margin-bottom:6px; text-transform:uppercase;">PreCrime Risk</div>
            <div style="font-family:var(--font-data); font-size:13px; color:var(--watch);">
                ${f.precrime}% pre-weaponization likelihood
            </div>
        `;
        card.onclick = () => {
            selectedDomain = f.domain;
            activeOsintDomain = f.domain;
            renderDossier(f);
        };
        grid.appendChild(card);
    });
}

function switchMapTab(tab) {
    activeMapTab = tab;
    document.querySelectorAll(".map-tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".map-pane").forEach(t => t.classList.remove("active"));
    const tabEl = document.querySelector(`[data-map="${tab}"]`);
    const pane = document.getElementById(`map-${tab}`);
    if (tabEl) tabEl.classList.add("active");
    if (pane) pane.classList.add("active");
    if (tab === "geo") renderGeoMap();
}

function renderMap() {
    renderGeoMap();
    renderClusters();
    renderIPMatrix();
}

function renderGeoMap() {
    if (!currentData || !currentData.geo) return;
    const pinsGroup = document.getElementById("country-pins");
    if (!pinsGroup) return;
    pinsGroup.innerHTML = "";

    const legend = document.getElementById("geo-legend");
    if (legend) {
        legend.innerHTML = `
            <div class="legend-item"><div class="legend-dot" style="background:var(--crit)"></div>Critical threat cluster</div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--watch)"></div>Watch/High</div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--low)"></div>Low/Baseline</div>
            <div class="legend-item" style="margin-left:auto;">${currentData.geo.length} countries · ${currentData.geo.reduce((s,g)=>s+g.count,0)} domains</div>
        `;
    }

    const W = 1000, H = 500;
    currentData.geo.forEach(g => {
        const x = g.coords[0] * W;
        const y = g.coords[1] * H;
        const r = Math.max(6, Math.min(28, 6 + g.count * 1.5));
        const color = g.threats > 0 ? (g.threats > 3 ? "pin-crit" : "pin-watch") : "pin-low";

        const gEl = document.createElementNS("http://www.w3.org/2000/svg", "g");
        gEl.setAttribute("class", "pin");
        gEl.innerHTML = `
            <circle cx="${x}" cy="${y}" r="${r}" class="${color}" opacity="0.85"/>
            <text x="${x}" y="${y - r - 6}" text-anchor="middle" class="pin-label">${g.code} · ${g.count}</text>
            <title>${g.name} · ${g.count} domains · ${g.threats} threats</title>
        `;
        gEl.onclick = () => {
            const box = document.getElementById("geo-inspector");
            if (!box) return;
            box.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <strong style="font-family:var(--font-display); font-size:16px;">${g.name} (${g.code})</strong>
                    <span class="badge">${g.count} domains · ${g.threats} threats</span>
                </div>
                <div style="font-family:var(--font-data); font-size:12px; color:var(--text-mute); margin-bottom:8px;">
                    ASNs: ${g.asns.join(", ") || "N/A"}
                </div>
                <div style="font-family:var(--font-data); font-size:12px; line-height:1.7;">
                    ${g.domains.map(d => `<div>${highlightConfusables(d)}</div>`).join("")}
                </div>
            `;
            box.classList.add("visible");
        };
        pinsGroup.appendChild(gEl);
    });
}

function renderClusters() {
    const container = document.getElementById("clusters-container");
    if (!container || !currentData) return;
    if (!currentData.clusters || currentData.clusters.length === 0) {
        container.innerHTML = `<div class="empty-state" style="grid-column:1/-1">No shared infrastructure detected.</div>`;
        return;
    }
    container.innerHTML = "";
    currentData.clusters.forEach(c => {
        const card = document.createElement("div");
        card.className = "cluster-card";
        const members = c.members.map(m => `
            <div class="cluster-member">
                <span>${highlightConfusables(m.domain)}</span>
                <span style="color:${m.tier === "CRITICAL" ? "var(--crit)" : m.tier === "HIGH" ? "var(--high)" : "var(--text-mute)"}">${m.score}</span>
            </div>
        `).join("");
        card.innerHTML = `
            <div class="cluster-header">
                <div>
                    <div class="cluster-ip">${c.ip}</div>
                    <div class="cluster-meta">${c.asn} · ${c.org}</div>
                    <div class="cluster-meta">${c.country} · ${c.role}</div>
                </div>
                <div class="cluster-conf">${c.confidence}%<br>confidence</div>
            </div>
            <div style="font-family:var(--font-data); font-size:11px; color:var(--text-mute); text-transform:uppercase; margin-bottom:8px;">${c.members.length} domains · ${c.threats} threats</div>
            ${members}
            <div class="cluster-caveat">⚠ ${c.caveat}</div>
        `;
        container.appendChild(card);
    });
}

function renderIPMatrix() {
    const tbody = document.querySelector("#ip-table tbody");
    if (!tbody || !currentData) return;
    if (!currentData.clusters || currentData.clusters.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-mute); padding:32px;">No shared infrastructure detected.</td></tr>`;
        return;
    }
    tbody.innerHTML = "";
    currentData.clusters.forEach(c => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td style="color:var(--accent)">${c.ip}</td>
            <td>${c.asn}</td>
            <td>${c.org}</td>
            <td>${c.country}</td>
            <td>${c.role}</td>
            <td>${c.members.map(m => m.domain).join(", ")}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderOsintMatrixView() {
    const container = document.getElementById("osint-matrix-container");
    if (!container || !currentData) return;
    if (!currentData.findings || currentData.findings.length === 0) {
        container.innerHTML = `<div class="empty-state">Run a scan first to populate the OSINT matrix.</div>`;
        return;
    }

    let target = currentData.findings.find(f => f.domain === activeOsintDomain);
    if (!target) target = currentData.findings[0];
    const matrix = target.osint_matrix || { sections: [], conclusions: {} };

    const selectorOptions = currentData.findings.slice(0, 40).map(f =>
        `<option value="${f.domain}" ${f.domain === target.domain ? "selected" : ""}>${f.domain} · ${f.tier} (${f.score})</option>`
    ).join("");

    const conclusionsHtml = Object.entries(matrix.conclusions || {}).map(([k, v]) => `
        <div class="conclusion-item">
            <span class="conclusion-key">${k.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</span>
            <span class="conclusion-val">${v}</span>
        </div>
    `).join("");

    const sectionsHtml = (matrix.sections || []).map(sec => `
        <div class="osint-section">
            <div class="osint-section-head">
                <div class="osint-section-title">${sec.category}</div>
                <span class="relevance rel-${sec.relevance.toLowerCase().replace(/[^a-z]/g,"")}">Relevance: ${sec.relevance}</span>
            </div>
            <div class="osint-sources">
                ${sec.sources.map(s => `
                    <div class="osint-source-row">
                        <div class="osint-source-name">
                            ${s.name}
                            <span class="news-badge offline">${s.tag}</span>
                        </div>
                        <div class="osint-source-conclusion">${s.conclusion}</div>
                        <a class="intel-link" href="${s.link}" target="_blank" rel="noopener noreferrer">Open ↗</a>
                    </div>
                `).join("")}
            </div>
        </div>
    `).join("");

    container.innerHTML = `
        <div class="osint-selector-row">
            <label for="osint-domain-select" style="color:var(--text-dim);">Selected domain:</label>
            <select id="osint-domain-select" onchange="activeOsintDomain = this.value; renderOsintMatrixView();">
                ${selectorOptions}
            </select>
            <span class="badge">${target.tier} · ${target.score}/100 · ${target.candidate ? target.candidate.technique.replace("_", " ").title() : target.technique_label}</span>
        </div>
        ${currentData.online_enrich && target.enrichment ? reputationRows(target.enrichment.reputation)
            + liveDnsRows(target.enrichment) + liveIpRows(target.enrichment.infrastructure) : `
        <div class="osint-conclusions">
            <div class="osint-section-title" style="margin-bottom:12px;">Discovery Matrix Conclusions</div>
            ${conclusionsHtml}
        </div>
        ${sectionsHtml}
        `}
    `;
}

async function openTakedown(domain) {
    selectedDomain = domain;
    await refreshTakedown();
    const modal = document.getElementById("takedown-modal");
    if (modal) modal.classList.remove("hidden");
}

async function refreshTakedown() {
    if (!selectedDomain || !currentScanId) return;
    const channelEl = document.getElementById("takedown-channel");
    const channel = channelEl ? channelEl.value : "Domain Registrar";
    const reportEl = document.getElementById("modal-report-text");
    if (!reportEl) return;
    try {
        const res = await fetch(`/api/takedown/${encodeURIComponent(selectedDomain)}?channel=${encodeURIComponent(channel)}&scan_id=${currentScanId}`);
        const data = await res.json();
        if (data.error) {
            reportEl.textContent = data.error;
            return;
        }
        currentReport = data.report;
        reportEl.textContent = data.report;
    } catch (err) {
        reportEl.textContent = "Failed to fetch report: " + err.message;
    }
}

function closeModal() {
    const modal = document.getElementById("takedown-modal");
    if (modal) modal.classList.add("hidden");
}

function copyReport() {
    if (!currentReport) return;
    navigator.clipboard.writeText(currentReport).then(() => {
        const reportEl = document.getElementById("modal-report-text");
        if (!reportEl) return;
        const note = document.createElement("div");
        note.textContent = "Copied to clipboard.";
        note.style.cssText = "color:var(--low);font-size:11px;margin-top:6px;";
        reportEl.parentElement.appendChild(note);
        setTimeout(() => note.remove(), 1800);
    });
}

function downloadReport() {
    if (!currentReport) return;
    const blob = new Blob([currentReport], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `proteus_takedown_${selectedDomain || "report"}.txt`;
    a.click();
}

function downloadCSV() {
    if (!currentScanId) return;
    window.location.href = `/api/export/csv?scan_id=${currentScanId}`;
}

function downloadJSON() {
    if (!currentScanId) return;
    window.location.href = `/api/export/json?scan_id=${currentScanId}`;
}

function downloadMISPSelected() {
    const domain = selectedDomain || (currentData && currentData.findings[0] && currentData.findings[0].domain);
    if (!domain || !currentScanId) return;
    window.location.href = `/api/export/misp/${encodeURIComponent(domain)}?scan_id=${currentScanId}`;
}
