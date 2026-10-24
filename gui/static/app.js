let editor;
let currentDecorations = [];
let suppressHighlightClearOnce = false;

const openFiles = {};
let openTabs = [];
let currentFilename = "main.c";
let repairOriginalCode = null;
let isAutocorrectEnabled = true;

require.config({
    paths: {
        vs: "https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs"
    }
});

require(["vs/editor/editor.main"], function () {
    editor = monaco.editor.create(document.getElementById("editor"), {
        value: `int main() {
    int a = 10
    return 0;
}`,
        language: "c",
        theme: "vs",
        automaticLayout: true,
        minimap: { enabled: false },
        fontSize: 15,
        lineNumbers: "on",
        roundedSelection: false,
        scrollBeyondLastLine: false,
        glyphMargin: true
    });

    openFiles["main.c"] = editor.getValue();
    openTabs = ["main.c"];
    currentFilename = "main.c";
    renderTabs();

    editor.onDidChangeModelContent(() => {
        openFiles[currentFilename] = editor.getValue();

        if (suppressHighlightClearOnce) {
            suppressHighlightClearOnce = false;
            return;
        }

        clearChangedLineHighlights();
    });

    refreshExamples();
    fetchAAIMetrics();
    initSidebarResize();
    initRightPanelResize();
    initBottomResize();
    initTestcaseResize();
});

function handleAutocorrectChange(enabled) {
    isAutocorrectEnabled = !!enabled;
    const label = document.getElementById("autocorrect-label");
    const badge = document.getElementById("mode-badge");

    if (label) {
        label.innerText = isAutocorrectEnabled ? "Autocorrect: ON" : "Autocorrect: OFF";
    }
    if (badge) {
        badge.innerText = isAutocorrectEnabled ? "Auto-Fix Mode" : "Suggestion Mode";
        badge.className = isAutocorrectEnabled ? "badge badge-primary" : "badge badge-info";
    }

    if (isAutocorrectEnabled) {
        hideSuggestions();
    }
}

function fillList(id, items, formatter = null) {
    const el = document.getElementById(id);
    if (!el) return;

    el.innerHTML = "";

    if (!items || items.length === 0) {
        const li = document.createElement("li");
        li.innerText = "None";
        el.appendChild(li);
        return;
    }

    items.forEach(item => {
        const li = document.createElement("li");
        li.innerText = formatter ? formatter(item) : item;
        el.appendChild(li);
    });
}

function renderStats(stats) {
    const box = document.getElementById("stats");
    if (!box) return;

    box.innerHTML = "";

    if (!stats) {
        box.innerText = "No stats";
        return;
    }

    const rows = [
        `Lexical fixes: ${stats.lex_fixes ?? 0}`,
        `Syntax repairs: ${stats.rule_fixes ?? 0}`,
        `AI fixes: ${stats.ai_fixes ?? 0}`,
        `Symbol fixes: ${stats.sym_fixes ?? 0}`,
        `Semantic fixes: ${stats.sem_fixes ?? 0}`,
        `Iterations: ${stats.iterations ?? 0}`
    ];

    rows.forEach(text => {
        const div = document.createElement("div");
        div.className = "statrow";
        div.innerText = text;
        box.appendChild(div);
    });
}

/* -------------------------------------------------- */
/* GREEN REPORT PANEL */
/* -------------------------------------------------- */
function ensureGreenPanel() {
    let panel = document.getElementById("greenPanel");
    if (panel) return panel;

    const resultPanel = document.getElementById("resultpanel");
    if (!resultPanel) return null;

    panel = document.createElement("div");
    panel.id = "greenPanel";
    panel.className = "panelbox";
    panel.style.marginTop = "14px";
    panel.style.padding = "14px";
    panel.style.borderRadius = "10px";
    panel.style.background = "#ffffff";
    panel.style.color = "#111111";
    panel.style.border = "1px solid #d9d9d9";
    panel.style.boxShadow = "0 2px 8px rgba(0,0,0,0.08)";

    resultPanel.appendChild(panel);
    return panel;
}

function renderGreenReport(report) {
    const panel = ensureGreenPanel();
    if (!panel) return;

    if (!report || Object.keys(report).length === 0) {
        panel.innerHTML = `
            <div style="font-size:24px;font-weight:700;margin-bottom:10px;">Green Compiler</div>
            <div>No green metrics yet.</div>
        `;
        return;
    }

    const score = report.green_score ?? 0;
    const runtime = report.total_runtime_ms ?? 0;
    const hotspot = report.hotspot ?? "unknown";
    const suggestion = report.suggestion ?? "No recommendation.";
    const phase = report.phase_ms || {};
    const values = report.values || {};

    const co2 = values.co2_kg;
    const cpu = values.cpu_percent;
    const memory = values.memory_mb;
    const peakMemory = values.peak_memory_mb;

    let color = "#16a34a";
    if (score < 70) color = "#d97706";
    if (score < 45) color = "#dc2626";

    const scorePercent = Math.max(0, Math.min(100, score));

    const rankedPhases = Object.entries(phase)
        .filter(([k]) => k !== "total")
        .sort((a, b) => Number(b[1]) - Number(a[1]));

    const maxPhase = rankedPhases.length > 0 ? Number(rankedPhases[0][1]) : 1;

    const phaseBars = rankedPhases.map(([name, value]) => {
        const v = Number(value) || 0;
        const pct = maxPhase > 0 ? (v / maxPhase) * 100 : 0;
        const isHotspot = name === hotspot;

        return `
            <div style="margin:8px 0;">
                <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:3px;">
                    <span>${name}${isHotspot ? " 🔥" : ""}</span>
                    <span>${v.toFixed(2)} ms</span>
                </div>
                <div style="height:10px;background:#e5e7eb;border-radius:999px;overflow:hidden;">
                    <div style="
                        width:${pct}%;
                        height:100%;
                        background:${isHotspot ? "#ff8c42" : "#2ecc71"};
                    "></div>
                </div>
            </div>
        `;
    }).join("");

    const metricBars = [
        {
            label: "CPU",
            value: cpu == null ? null : Number(cpu),
            max: 100,
            unit: "%"
        },
        {
            label: "Memory",
            value: memory == null ? null : Number(memory),
            max: peakMemory && peakMemory > 0 ? Number(peakMemory) : (memory || 1),
            unit: " MB"
        },
        {
            label: "Peak Memory",
            value: peakMemory == null ? null : Number(peakMemory),
            max: peakMemory && peakMemory > 0 ? Number(peakMemory) : 1,
            unit: " MB"
        }
    ].map(item => {
        if (item.value == null) {
            return `
                <div style="margin:8px 0;">
                    <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:3px;">
                        <span>${item.label}</span>
                        <span>N/A</span>
                    </div>
                    <div style="height:10px;background:#e5e7eb;border-radius:999px;"></div>
                </div>
            `;
        }

        const pct = item.max > 0 ? Math.max(0, Math.min(100, (item.value / item.max) * 100)) : 0;

        return `
            <div style="margin:8px 0;">
                <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:3px;">
                    <span>${item.label}</span>
                    <span>${item.value.toFixed(2)}${item.unit}</span>
                </div>
                <div style="height:10px;background:#e5e7eb;border-radius:999px;overflow:hidden;">
                    <div style="
                        width:${pct}%;
                        height:100%;
                        background:#4da3ff;
                    "></div>
                </div>
            </div>
        `;
    }).join("");

    panel.innerHTML = `
    <div style="font-size:24px;font-weight:700;margin-bottom:12px;">
        Green Compiler
    </div>

    <div style="font-size:32px;font-weight:800;color:${color};margin-bottom:8px;">
        ${score}/100
    </div>

    <div style="margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px;">
            <span>Green Score</span>
            <span>${scorePercent.toFixed(0)}%</span>
        </div>
        <div style="height:14px;background:#e5e7eb;border-radius:999px;overflow:hidden;">
            <div style="
                width:${scorePercent}%;
                height:100%;
                background:${color};
            "></div>
        </div>
    </div>

    <div style="margin-bottom:6px;">Runtime: ${Number(runtime).toFixed(2)} ms</div>
    <div style="margin-bottom:6px;">CO₂: ${co2 == null ? "N/A" : Number(co2).toExponential(3)} kg</div>
    <div style="margin-bottom:6px;">Hotspot: <b>${hotspot}</b></div>

    <div style="margin-bottom:12px;">
        <b>Suggestion:</b><br>${suggestion}
    </div>

    <div style="margin-top:16px;margin-bottom:6px;font-size:18px;font-weight:700;">
        System Metrics Graph
    </div>
    ${metricBars}
`;
}

function highlightLines(changedLines, securityLines) {
    if (!editor) return;

    currentDecorations = editor.deltaDecorations(currentDecorations, []);

    const changed = changedLines || [];
    const security = new Set(securityLines || []);
    const allLines = [...new Set([...changed, ...(securityLines || [])])];

    if (allLines.length === 0) return;

    const decorations = allLines.map(line => ({
        range: new monaco.Range(line, 1, line, 1),
        options: {
            isWholeLine: true,
            className: security.has(line) ? "securityHighlight" : "normalHighlight",
            glyphMarginClassName: security.has(line) ? "securityGlyph" : "changedGlyph"
        }
    }));

    currentDecorations = editor.deltaDecorations([], decorations);
}

function clearChangedLineHighlights() {
    if (!editor) return;
    currentDecorations = editor.deltaDecorations(currentDecorations, []);
}

function setStatus(statusText) {
    const el = document.getElementById("status");
    if (!el) return;

    el.innerText = statusText || "Unknown";
    el.className = "";

    if (statusText === "SUCCESS") el.classList.add("status-success");
    else if (statusText === "SUGGESTIONS_READY") el.classList.add("status-success");
    else if (statusText === "SUCCESS_WITH_WARNINGS") el.classList.add("status-warning");
    else if (statusText === "BLOCKED_SECURITY") el.classList.add("status-danger");
    else if (statusText === "BLOCKED_AAI_ATTACK") el.classList.add("status-danger");
    else if (statusText === "SEM_ISSUES") el.classList.add("status-warning");
    else if (statusText === "UNFIXABLE" || statusText === "STOPPED") el.classList.add("status-danger");
}

function setProgress(percent, text) {
    const bar = document.getElementById("repairProgressBar");
    const label = document.getElementById("repairProgressText");

    if (bar) {
        const safe = Math.max(0, Math.min(100, percent || 0));
        bar.style.width = `${safe}%`;
    }

    if (label) label.innerText = text || "Running...";
}

function resetProgress() {
    setProgress(0, "Idle");
}

function resetPanels() {
    fillList("steps", []);
    fillList("errors", []);
    fillList("semantic", []);
    fillList("security", []);
    fillList("logs", []);

    renderStats({
        lex_fixes: 0,
        rule_fixes: 0,
        ai_fixes: 0,
        sym_fixes: 0,
        sem_fixes: 0,
        iterations: 0
    });

    renderGreenReport({});
    clearChangedLineHighlights();
    resetProgress();
    hideSuggestions();
}

function renderTabs() {
    const tabbar = document.getElementById("tabbar");
    if (!tabbar) return;

    tabbar.innerHTML = "";

    openTabs.forEach(filename => {
        const tab = document.createElement("div");
        tab.className = "filetab" + (filename === currentFilename ? " active" : "");
        tab.onclick = () => switchTab(filename);

        const name = document.createElement("span");
        name.innerText = filename.split("/").pop();

        const close = document.createElement("span");
        close.className = "filetab-close";
        close.innerText = "×";
        close.onclick = (e) => {
            e.stopPropagation();
            closeTab(filename);
        };

        tab.appendChild(name);
        tab.appendChild(close);
        tabbar.appendChild(tab);
    });

    const label = document.getElementById("active-file-label");
    if (label) label.innerText = currentFilename;
}

function switchTab(filename) {
    if (!editor || !openFiles.hasOwnProperty(filename)) return;

    openFiles[currentFilename] = editor.getValue();
    currentFilename = filename;

    suppressHighlightClearOnce = true;
    editor.setValue(openFiles[filename] ?? "");
    renderTabs();
    resetPanels();
    setStatus("Switched tab");
}

function closeTab(filename) {
    if (openTabs.length === 1) return;

    const idx = openTabs.indexOf(filename);
    if (idx !== -1) openTabs.splice(idx, 1);

    delete openFiles[filename];

    if (currentFilename === filename) {
        currentFilename = openTabs[Math.max(0, idx - 1)] || openTabs[0];
        suppressHighlightClearOnce = true;
        editor.setValue(openFiles[currentFilename] ?? "");
    }

    renderTabs();
    resetPanels();
}

function openFileInTab(filename, code) {
    if (!openTabs.includes(filename)) openTabs.push(filename);

    openFiles[filename] = code;
    currentFilename = filename;

    suppressHighlightClearOnce = true;
    editor.setValue(code);
    renderTabs();
    resetPanels();
}

function computeChangedLines(beforeCode, afterCode) {
    const before = (beforeCode || "").split("\n");
    const after = (afterCode || "").split("\n");

    const maxLen = Math.max(before.length, after.length);
    const changed = [];

    for (let i = 0; i < maxLen; i++) {
        if ((before[i] || "") !== (after[i] || "")) changed.push(i + 1);
    }

    return changed;
}

function renderRepairResult(data) {
    const beforeCode = repairOriginalCode ?? "";
    const isAutocorrect = data.autocorrect !== false;

    // Handle AAI Attack Blocked State
    if (data.status === "BLOCKED_AAI_ATTACK") {
        setStatus("BLOCKED_AAI_ATTACK");
        const shieldBadge = document.getElementById("aai-shield-status");
        if (shieldBadge) {
            shieldBadge.innerText = "Attack Blocked 🛑";
            shieldBadge.className = "badge badge-danger";
        }
        fillList("errors", data.errors || ["Malicious input blocked by AAI Guardrail."]);
        fillList("logs", data.logs || []);
        fetchAAIMetrics();
        repairOriginalCode = null;
        return;
    }

    setStatus(data.status || "Unknown");

    // Autocorrect ON: Update editor content directly
    if (isAutocorrect && data.corrected_code) {
        suppressHighlightClearOnce = true;
        editor.setValue(data.corrected_code);
        openFiles[currentFilename] = data.corrected_code;

        const changedLines = computeChangedLines(beforeCode, data.corrected_code);
        highlightLines(changedLines, data.security_changed_lines || []);
        hideSuggestions();
    } else {
        // Autocorrect OFF: Never modify editor code; render suggestions list
        clearChangedLineHighlights();
        renderSuggestions(data.suggestions || []);
    }

    fillList("steps", data.applied_steps || []);
    fillList("errors", data.errors || []);

    fillList(
        "semantic",
        data.semantic_issues || [],
        (item) => {
            const kind = item.kind || "issue";
            const line = item.line ?? "?";
            const col = item.col ?? "?";
            const msg = item.msg || "";
            const name = item.name ? ` (${item.name})` : "";
            return `${kind}${name} at L${line}:${col} -> ${msg}`;
        }
    );

    fillList("security", data.security_warnings || []);
    fillList("logs", data.logs || []);
    renderStats(data.stats || {});
    renderGreenReport(data.green_report || {});

    repairOriginalCode = null;
}

async function runRepair() {
    if (!editor) return;

    repairOriginalCode = editor.getValue();
    openFiles[currentFilename] = repairOriginalCode;

    resetPanels();
    setStatus("RUNNING");
    setProgress(2, isAutocorrectEnabled ? "Starting repair..." : "Analyzing code for suggestions...");

    const response = await fetch("/api/repair_stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            code: repairOriginalCode,
            filename: currentFilename,
            autocorrect: isAutocorrectEnabled
        })
    });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split("\n\n");
        buffer = chunks.pop();

        for (const chunk of chunks) {
            if (!chunk.startsWith("data: ")) continue;

            const data = JSON.parse(chunk.slice(6));

            if (data.type === "guardrail") {
                setProgress(2, data.message || "Scanning input with AAI Guardrail...");
            }

            if (data.type === "guardrail_blocked") {
                setProgress(100, data.message || "Blocked by AAI Guardrail");
                setStatus("BLOCKED_AAI_ATTACK");
            }

            if (data.type === "start") {
                setProgress(5, data.message || "Started...");
            }

            if (data.type === "detect") {
                const iter = data.stats?.iterations ?? 0;
                const percent = Math.min(85, 5 + iter);
                setProgress(percent, data.message || "Error detected...");
                renderStats(data.stats || {});
                fillList("steps", data.applied_steps || []);
            }

            if (data.type === "fix") {
                const totalRepairs = data.total_repairs ?? 0;
                const percent = Math.min(95, 8 + totalRepairs);
                setProgress(percent, data.message || "Applied fix...");
                renderStats(data.stats || {});
                fillList("steps", data.applied_steps || []);
            }

            if (data.type === "done") {
                setProgress(100, `Done - ${data.total_repairs || 0} repairs`);
                renderRepairResult(data);
            }
        }
    }
}

/* -------------------------------------------------- */
/* SUGGESTIONS & SELECTIVE FIX LOGIC (Autocorrect OFF) */
/* -------------------------------------------------- */

function hideSuggestions() {
    const card = document.getElementById("suggestions-card");
    if (card) card.style.display = "none";
}

function renderSuggestions(suggestions) {
    const card = document.getElementById("suggestions-card");
    const countBadge = document.getElementById("suggestions-count");
    const list = document.getElementById("suggestions-list");
    const feedback = document.getElementById("suggestions-feedback");

    if (!card || !list) return;

    if (feedback) feedback.style.display = "none";

    if (!suggestions || suggestions.length === 0) {
        card.style.display = "block";
        if (countBadge) countBadge.innerText = "0 suggestions";
        list.innerHTML = `<div style="font-size: 13px; color: #64748b; padding: 8px;">No syntax or structural fixes needed. Code passed analysis.</div>`;
        return;
    }

    card.style.display = "block";
    if (countBadge) countBadge.innerText = `${suggestions.length} suggestion${suggestions.length > 1 ? "s" : ""}`;

    list.innerHTML = "";

    suggestions.forEach((sug, idx) => {
        const item = document.createElement("div");
        item.className = "suggestion-card";
        item.id = `sug-card-${idx}`;

        const catBadgeClass = sug.category === "SECURITY" ? "badge-danger" : (sug.category === "SEMANTIC" ? "badge-warning" : "badge-primary");

        item.innerHTML = `
            <div class="sug-header">
                <span class="sug-title">Line ${sug.line}: ${escapeHtml(sug.title || "Fix required")}</span>
                <span class="badge ${catBadgeClass}">${escapeHtml(sug.category || "SYNTAX")}</span>
            </div>
            <div class="sug-explanation">${escapeHtml(sug.explanation || "")}</div>
            <div class="sug-diff">
                <div class="diff-del">- ${escapeHtml(sug.original_snippet || "")}</div>
                <div class="diff-ins">+ ${escapeHtml(sug.suggested_snippet || "")}</div>
            </div>
            <button class="apply-btn" id="btn-apply-${idx}" onclick="applySingleSuggestion('${escapeJs(sug.id)}', ${sug.line}, '${escapeJs(sug.original_snippet)}', '${escapeJs(sug.suggested_snippet)}', ${idx})">
                Apply This Fix
            </button>
        `;
        list.appendChild(item);
    });
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function escapeJs(str) {
    if (!str) return "";
    return String(str).replace(/\\/g, "\\\\").replace(/'/g, "\\'").replace(/\n/g, "\\n");
}

async function applySingleSuggestion(sugId, line, expectedOriginal, replacement, cardIdx) {
    if (!editor) return;

    const btn = document.getElementById(`btn-apply-${cardIdx}`);
    if (btn) {
        btn.disabled = true;
        btn.innerText = "Applying...";
    }

    const feedback = document.getElementById("suggestions-feedback");

    try {
        const response = await fetch("/api/apply_suggestion", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code: editor.getValue(),
                suggestion_id: sugId,
                line: line,
                expected_original: expectedOriginal,
                replacement: replacement
            })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            suppressHighlightClearOnce = true;
            editor.setValue(data.updated_code);
            openFiles[currentFilename] = data.updated_code;

            highlightLines([line], []);

            if (btn) {
                btn.innerText = "Applied ✓";
                btn.style.background = "#16a34a";
            }

            if (feedback) {
                feedback.className = "feedback-msg feedback-success";
                feedback.innerText = `Applied fix to line ${line} successfully.`;
                feedback.style.display = "block";
            }
        } else {
            if (btn) {
                btn.disabled = false;
                btn.innerText = "Apply This Fix";
            }

            const errorMsg = data.error === "STALE_SOURCE"
                ? `Cannot apply fix: source code at line ${line} has changed since suggestions were generated. Please re-run analysis.`
                : (data.message || "Failed to apply suggestion.");

            if (feedback) {
                feedback.className = "feedback-msg feedback-error";
                feedback.innerText = errorMsg;
                feedback.style.display = "block";
            }
        }
    } catch (err) {
        if (btn) {
            btn.disabled = false;
            btn.innerText = "Apply This Fix";
        }
        if (feedback) {
            feedback.className = "feedback-msg feedback-error";
            feedback.innerText = `Error applying suggestion: ${err.message}`;
            feedback.style.display = "block";
        }
    }
}

/* -------------------------------------------------- */
/* AAI ATTACK SIMULATOR & METRICS TELEMETRY */
/* -------------------------------------------------- */

async function runAttackSimulation() {
    const select = document.getElementById("aai-scenario-select");
    const btn = document.getElementById("sim-btn");
    const feedback = document.getElementById("aai-sim-feedback");

    if (!select) return;
    const scenario = select.value;

    if (btn) {
        btn.disabled = true;
        btn.innerText = "Simulating...";
    }

    try {
        const response = await fetch("/api/aai_simulate_attack", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario: scenario })
        });

        const data = await response.json();

        if (feedback) {
            feedback.style.display = "block";
            if (data.threat_detected) {
                feedback.className = "aai-feedback-box feedback-error";
                feedback.innerHTML = `
                    <div style="font-weight: 700; margin-bottom: 3px;">🛑 Attack Intercepted (${escapeHtml(data.verdict)})</div>
                    <div><b>Type:</b> ${escapeHtml(data.attack_type)} | <b>Risk:</b> ${escapeHtml(data.risk_level)}</div>
                    <div><b>Action:</b> ${escapeHtml(data.mitigation_action)} (${data.latency_ms} ms)</div>
                    <div style="margin-top: 4px; font-size: 11px;"><b>Reason:</b> ${escapeHtml(data.reason)}</div>
                `;
            } else {
                feedback.className = "aai-feedback-box feedback-success";
                feedback.innerHTML = `
                    <div style="font-weight: 700; margin-bottom: 3px;">🟢 Non-Adversarial Input Allowed (${escapeHtml(data.verdict)})</div>
                    <div><b>Action:</b> ${escapeHtml(data.mitigation_action)} (${data.latency_ms} ms)</div>
                    <div style="margin-top: 4px; font-size: 11px;"><b>Verification:</b> ${escapeHtml(data.reason)}</div>
                `;
            }
        }

        if (data.metrics) {
            renderMetricsBoxes(data.metrics);
        }

        fetchAAIMetrics();
    } catch (err) {
        if (feedback) {
            feedback.className = "aai-feedback-box feedback-error";
            feedback.innerText = `Simulation request failed: ${err.message}`;
            feedback.style.display = "block";
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerText = "Simulate Attack";
        }
    }
}

async function fetchAAIMetrics() {
    try {
        const response = await fetch("/api/aai_metrics");
        const data = await response.json();

        if (data.benchmark_metrics) {
            renderMetricsBoxes(data.benchmark_metrics);
        }

        if (data.audit_log) {
            renderAuditLog(data.audit_log);
        }
    } catch (err) {
        console.error("Failed to fetch AAI metrics:", err);
    }
}

function renderMetricsBoxes(m) {
    const elAdr = document.getElementById("metric-adr");
    const elBsr = document.getElementById("metric-bsr");
    const elFpr = document.getElementById("metric-fpr");
    const elLat = document.getElementById("metric-latency");

    if (elAdr) elAdr.innerText = `${m.adr_percent ?? "--"}%`;
    if (elBsr) elBsr.innerText = m.bsr_percent !== null && m.bsr_percent !== undefined ? `${m.bsr_percent}%` : "N/A";
    if (elFpr) elFpr.innerText = `${m.fpr_percent ?? "--"}%`;
    if (elLat) elLat.innerText = `${m.avg_latency_ms ?? "--"} ms`;
}

function renderAuditLog(auditEntries) {
    const list = document.getElementById("aai-audit-list");
    if (!list) return;

    if (!auditEntries || auditEntries.length === 0) {
        list.innerHTML = `<li>No attacks blocked in current session.</li>`;
        return;
    }

    list.innerHTML = "";
    auditEntries.forEach(entry => {
        const li = document.createElement("li");
        const isBlocked = entry.verdict === "BLOCKED_INPUT";
        const badgeClass = isBlocked ? "audit-badge audit-blocked" : "audit-badge audit-quarantine";
        const label = isBlocked ? "BLOCKED" : "QUARANTINED";

        li.innerHTML = `
            <span class="${badgeClass}">${label}</span>
            <b>${escapeHtml(entry.attack_type || "UNKNOWN")}:</b> ${escapeHtml(entry.reason || "")}
            <div style="font-size: 10px; color: #64748b; margin-top: 2px;">
                ${escapeHtml(entry.timestamp || "")} (${entry.latency_ms} ms)
            </div>
        `;
        list.appendChild(li);
    });
}

/* -------------------------------------------------- */
/* TEST CASE & EXAMPLES RUNNER */
/* -------------------------------------------------- */

async function runTestCase() {
    const input = document.getElementById("testcase-input").value;
    const output = document.getElementById("testcase-output");

    output.value = "Running...";

    const response = await fetch("/api/testcase", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            code: input,
            filename: "test_case.c",
            autocorrect: isAutocorrectEnabled
        })
    });

    const data = await response.json();

    output.value =
        `STATUS: ${data.status || "Unknown"}\n\n` +
        `CORRECTED CODE:\n${data.corrected_code || ""}\n\n` +
        `GREEN SCORE: ${data.green_report?.green_score ?? "NA"}\n\n`;
}

async function refreshExamples() {
    const listRes = await fetch("/api/examples");
    const files = await listRes.json();

    const tree = document.getElementById("file-tree");
    if (!tree) return;

    tree.innerHTML = "";

    files.forEach(filename => {
        const item = document.createElement("div");
        item.className = "file-item";
        item.innerText = filename;
        item.dataset.filename = filename;

        item.onclick = async () => {
            const res = await fetch("/api/example/" + encodeURIComponent(filename));
            const data = await res.json();
            openFileInTab(data.filename || filename, data.code || "");
        };

        tree.appendChild(item);
    });
}

/* Keep your resize functions unchanged */
function newFile(){ location.reload(); }
function initSidebarResize(){}
function initRightPanelResize(){}
function initBottomResize(){}
function initTestcaseResize(){}