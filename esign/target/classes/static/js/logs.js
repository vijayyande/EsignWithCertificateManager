/* Audit Logs console — /api/esign-logs */

let currentPage = 0;
let totalPages = 0;

function outcomeChip(outcome) {
    const cls = { SUCCESS: "ok", PENDING: "warn", REJECTED: "bad", ERROR: "bad" }[outcome] || "";
    return chip(outcome || "?", cls);
}

/* ─── table ────────────────────────────────────────────────────────── */

async function loadLogs() {
    const params = new URLSearchParams();
    if (val("q")) params.set("q", val("q"));
    if (val("f-type")) params.set("type", val("f-type"));
    if (val("f-outcome")) params.set("outcome", val("f-outcome"));
    if (val("f-from")) params.set("from", val("f-from") + ":00");
    if (val("f-to")) params.set("to", val("f-to") + ":59");
    params.set("page", currentPage);
    params.set("size", 25);

    const res = await getJson("/api/esign-logs?" + params.toString());
    const tbody = $("#logTableBody");
    if (!res.json) {
        tbody.innerHTML = `<tr><td colspan="8">HTTP ${res.httpStatus}</td></tr>`;
        return;
    }
    totalPages = res.json.totalPages;
    $("#pageInfo").textContent =
        `${res.json.totalElements} entr${res.json.totalElements === 1 ? "y" : "ies"} — page ${res.json.page + 1} of ${Math.max(totalPages, 1)}`;

    if (!res.json.content.length) {
        tbody.innerHTML = `<tr><td colspan="8" class="hint">No log entries match the current filters.</td></tr>`;
        return;
    }

    tbody.innerHTML = res.json.content.map(l => `
        <tr style="cursor:pointer" onclick="showDetail('${l.id}')">
            <td>${esc((l.createdAt || "").replace("T", " ").slice(0, 19))}</td>
            <td>${chip(l.endpoint, l.endpoint === "SIGN" ? "" : "dim")}</td>
            <td><code>${esc(l.transactionId || "—")}</code></td>
            <td>${esc(l.aspId || "—")}<span class="hint"> ${esc(l.signerId ? "/ " + l.signerId : "")}</span></td>
            <td>${outcomeChip(l.outcome)}</td>
            <td>${l.httpStatus}</td>
            <td>${esc(l.errorCode || "")}${l.errorMessage ? ` <span class="hint">${esc(l.errorMessage)}</span>` : ""}</td>
            <td>${l.documentCount ?? 0}</td>
        </tr>`).join("");
}

/* ─── detail ───────────────────────────────────────────────────────── */

async function showDetail(id) {
    const res = await getJson("/api/esign-logs/" + id);
    if (!res.json || res.httpStatus !== 200) return;
    const l = res.json;

    $("#detailBlock").open = true;
    $("#detailTitle").textContent = `${l.endpoint} · ${l.transactionId || "(no txn)"} · ${l.outcome}`;
    if (typeof $("#detailBlock").scrollIntoView === "function")
        $("#detailBlock").scrollIntoView({ behavior: "smooth", block: "nearest" });

    /* parse request XML if present */
    const req = parseAuditRequestXml(l.requestXml);

    /* parse response snippet XML */
    const resp = parseResponseXml(l.responseSnippet);

    /* build the full detail panel */
    let html = "";

    /* ── row 1: chips ── */
    html += `<div class="chips" style="margin-bottom:12px">`;
    html += chip("HTTP " + l.httpStatus, l.httpStatus < 400 ? "ok" : "bad");
    html += outcomeChip(l.outcome);
    if (l.endpoint) html += chip(l.endpoint, l.endpoint === "SIGN" ? "" : "dim");
    html += chip(`ip ${l.remoteIp || "?"}`);
    html += chip(`${l.requestBytes ?? 0} bytes`);
    html += `</div>`;

    /* ── row 2: error explanation ── */
    if (l.errorCode || l.errorMessage) {
        html += `<div class="audit-error-box">`;
        if (l.errorCode) {
            const meaning = ESIGN_ERROR_MEANINGS[l.errorCode] || "Unknown error code";
            html += `<div class="audit-error-code">Error ${esc(l.errorCode)}</div>`;
            html += `<div class="audit-error-meaning">${esc(meaning)}</div>`;
        }
        if (l.errorMessage) {
            html += `<div class="audit-error-detail">${esc(l.errorMessage)}</div>`;
        }
        html += suggestionForCode(l.errorCode, l.requestXml);
        html += `</div>`;
    }

    /* ── row 3: metadata grid ── */
    html += `<div class="audit-meta-grid">`;
    html += metaBlock("Transaction", l.transactionId || "—");
    html += metaBlock("ASP ID", l.aspId || "—");
    html += metaBlock("Signer ID", l.signerId || "—");
    html += metaBlock("Timestamp (server)", l.createdAt ? formatIst(l.createdAt) : "—");
    if (req && req.ts) {
        const drift = computeDrift(l.createdAt, req.ts);
        html += metaBlock("Timestamp (request)", esc(req.ts), drift ? `<span class="${Math.abs(drift) > 600 ? 'bad-text' : 'ok-text'}">${driftLabel(drift)}</span>` : "");
    }
    html += metaBlock("Version", req.ver || "—");
    html += metaBlock("Signing Algo", req.signingAlgorithm || "—");
    html += metaBlock("Max Wait", req.maxWaitPeriod ? (req.maxWaitPeriod / 1000) + "s" : "—");
    html += metaBlock("Documents", String(l.documentCount ?? req.docCount ?? "—"));
    html += `</div>`;

    /* ── row 4: request fields ── */
    if (req && req.fields && req.fields.length) {
        html += `<div class="section-label">Request Fields</div>`;
        html += `<table class="dir audit-fields-table"><thead><tr>
                    <th>Field</th><th>Value</th><th>Status</th></tr></thead><tbody>`;
        for (const f of req.fields) {
            html += `<tr>
                <td><code>${esc(f.name)}</code></td>
                <td style="word-break:break-all">${esc(f.value || "—")}</td>
                <td>${fieldStatus(f)}</td>
            </tr>`;
        }
        html += `</tbody></table>`;
    }

    /* ── row 5: document hashes ── */
    if (req && req.docs && req.docs.length) {
        html += `<div class="section-label">Document Hashes</div>`;
        html += `<table class="dir audit-fields-table"><thead><tr>
                    <th>#</th><th>Hash Algorithm</th><th>Hash Value (truncated)</th>
                    <th>docInfo</th><th>docUrl</th><th>responseSigType</th></tr></thead><tbody>`;
        for (const d of req.docs) {
            html += `<tr>
                <td>${esc(d.id || "?")}</td>
                <td>${esc(d.hashAlgorithm || "?")}</td>
                <td style="font-family:var(--mono);font-size:11px;word-break:break-all">${esc((d.hashValue || "—").substring(0, 40))}${(d.hashValue || "").length > 40 ? "…" : ""}</td>
                <td>${esc(d.docInfo || "—")}</td>
                <td>${esc(d.docUrl || "—")}</td>
                <td>${esc(d.responseSigType || "—")}</td>
            </tr>`;
        }
        html += `</tbody></table>`;
    }

    /* ── row 6: response ── */
    html += `<div class="section-label">Response (snippet)</div>`;
    if (resp) {
        html += `<div class="chips" style="margin-bottom:6px">`;
        html += chip("status=" + (resp.status || "?"),
            resp.status === "1" ? "ok" : resp.status === "2" ? "warn" : "bad");
        if (resp.resCode) html += chip("resCode=" + resp.resCode);
        if (resp.error) {
            const m = ESIGN_ERROR_MEANINGS[resp.error] || "Unknown";
            html += chip(`error ${resp.error} — ${m}`, "bad");
        }
        html += `</div>`;
    }
    html += `<pre class="xml">${esc(prettyXml(l.responseSnippet || "(none)"))}</pre>`;

    /* ── row 7: raw request XML ── */
    html += `<div class="section-label">Raw Request XML</div>`;
    html += `<div style="display:flex;gap:8px;margin-bottom:4px">
        <button class="secondary small" onclick="copyText('audit-req-xml')">Copy XML</button>
        <button class="secondary small" onclick="copyText('audit-req-json')">Copy as JSON</button>
    </div>`;
    html += `<pre class="xml" id="audit-req-xml">${esc(prettyXml(l.requestXml || "(not stored)"))}</pre>`;
    html += `<textarea id="audit-req-json" style="display:none">${esc(JSON.stringify(l, null, 2))}</textarea>`;

    $("#detailBody").innerHTML = html;
}

/* ─── XML parsing helpers ──────────────────────────────────────────── */

function parseAuditRequestXml(xml) {
    if (!xml) return null;
    try {
        const doc = new DOMParser().parseFromString(xml, "text/xml");
        if (doc.querySelector("parsererror")) return null;
        const root = doc.documentElement;
        const fields = [];
        for (const a of root.attributes) {
            fields.push({ name: `@${a.name}`, value: a.value, required: false });
        }
        const docs = [];
        const inputHashes = root.querySelectorAll("InputHash");
        for (const ih of inputHashes) {
            docs.push({
                id: ih.getAttribute("id"),
                hashAlgorithm: ih.getAttribute("hashAlgorithm"),
                hashValue: ih.textContent?.trim() || "",
                docInfo: ih.getAttribute("docInfo"),
                docUrl: ih.getAttribute("docUrl"),
                responseSigType: ih.getAttribute("responseSigType"),
            });
        }
        return {
            ver: root.getAttribute("ver"),
            ts: root.getAttribute("ts"),
            txn: root.getAttribute("txn"),
            aspId: root.getAttribute("aspId"),
            signerId: root.getAttribute("signerid"),
            signingAlgorithm: root.getAttribute("signingAlgorithm"),
            maxWaitPeriod: root.getAttribute("maxWaitPeriod"),
            responseUrl: root.getAttribute("responseUrl"),
            redirectUrl: root.getAttribute("redirectUrl"),
            docCount: docs.length,
            fields,
            docs,
        };
    } catch (e) { return null; }
}

function parseResponseXml(xml) {
    if (!xml) return null;
    try {
        const doc = new DOMParser().parseFromString(xml, "text/xml");
        if (doc.querySelector("parsererror")) return null;
        const root = doc.documentElement;
        return {
            name: root.nodeName,
            status: root.getAttribute("status"),
            resCode: root.getAttribute("resCode"),
            error: root.getAttribute("error"),
            txn: root.getAttribute("txn"),
            ver: root.getAttribute("ver"),
        };
    } catch (e) { return null; }
}

function prettyXml(xml) {
    if (!xml || xml.trim().startsWith("{")) return xml || "(none)";
    try {
        const doc = new DOMParser().parseFromString(xml, "text/xml");
        if (doc.querySelector("parsererror")) return xml;
        return formatXml(doc.documentElement);
    } catch (e) { return xml; }
}

/* ─── timing helpers ───────────────────────────────────────────────── */

function formatIst(isoStr) {
    if (!isoStr) return "—";
    try {
        const d = new Date(isoStr);
        const fmt = new Intl.DateTimeFormat("en-GB", {
            timeZone: "Asia/Kolkata",
            year: "numeric", month: "2-digit", day: "2-digit",
            hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
        });
        return fmt.format(d);
    } catch (e) { return isoStr; }
}

function computeDrift(serverIso, requestTs) {
    try {
        const server = new Date(serverIso);
        const req = new Date(requestTs);
        return Math.round((req.getTime() - server.getTime()) / 1000);
    } catch (e) { return null; }
}

function driftLabel(secs) {
    const abs = Math.abs(secs);
    const unit = abs < 120 ? `${abs}s` : `${Math.round(abs / 60)}m`;
    return secs === 0 ? "clocks in sync" : (secs > 0 ? `request +${unit} ahead` : `request ${unit} behind`);
}

/* ─── error suggestions ────────────────────────────────────────────── */

function suggestionForCode(code, requestXml) {
    const suggestions = {
        "110": `<b>Fix:</b> Ensure the <code>ts</code> attribute is in IST (UTC+5:30) and within ±30 minutes of the server clock. The browser must not add extra timezone offsets.`,
        "106": `<b>Fix:</b> Register the ASP via <a href="/asp.html" style="color:var(--accent-2)">ASP Management</a> or set <code>esign.asp-registry.validation-enabled=false</code> in application.yml.`,
        "107": `<b>Fix:</b> The <code>&lt;Signature&gt;</code> element must contain a valid Base64-encoded digital signature from the ASP's registered certificate.`,
        "101": `<b>Fix:</b> Check the XML structure — it must conform to eSign API v3.3. Use <a href="/esign.html" style="color:var(--accent-2)">eSign console</a> to generate a valid request.`,
        "201": `<b>Fix:</b> Each <code>&lt;InputHash&gt;</code> must contain a valid Base64-encoded SHA-256 hash of the document.`,
        "204": `<b>Fix:</b> <code>docInfo</code> is required, must be non-blank and ≤50 characters.`,
        "205": `<b>Fix:</b> Hash algorithm must be <code>SHA256</code> (case-insensitive).`,
        "203": `<b>Fix:</b> <code>docUrl</code> is required and must be non-blank.`,
        "105": `<b>Fix:</b> <code>txn</code> must be unique per request. Use a UUID or timestamp-based ID.`,
        "112": `<b>Fix:</b> This transaction ID was already used. Generate a new unique <code>txn</code> value.`,
        "113": `<b>Fix:</b> The user did not complete authentication within <code>maxWaitPeriod</code>. Increase the timeout or prompt the user faster.`,
        "114": `<b>Fix:</b> eKYC authentication failed — check user credentials, OTP, or PIN.`,
    };
    const msg = suggestions[code];
    if (!msg) return "";
    return `<div class="audit-suggestion">${msg}</div>`;
}

/* ─── field status indicators ──────────────────────────────────────── */

function fieldStatus(f) {
    if (!f.value || f.value === "—" || f.value === "null") {
        return `<span class="chip warn">missing</span>`;
    }
    if (f.name === "@ts") {
        try {
            const drift = computeDrift(new Date().toISOString(), f.value);
            if (drift !== null && Math.abs(drift) > 1800) {
                return `<span class="chip bad">drift ${Math.round(drift / 60)}m</span>`;
            }
            return `<span class="chip ok">ok</span>`;
        } catch (e) { return `<span class="chip warn">unparseable</span>`; }
    }
    return `<span class="chip ok">present</span>`;
}

/* ─── copy helper ──────────────────────────────────────────────────── */

function copyText(elId) {
    const el = document.getElementById(elId);
    if (!el) return;
    const text = el.tagName === "TEXTAREA" ? el.value : el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = el.previousElementSibling?.querySelector("button") || el.closest("div")?.querySelector("button");
        if (btn) { const orig = btn.textContent; btn.textContent = "Copied!"; setTimeout(() => btn.textContent = orig, 1500); }
    });
}

function metaBlock(label, value, extra) {
    return `<div class="audit-meta-item">
        <div class="audit-meta-label">${esc(label)}</div>
        <div class="audit-meta-value">${value}</div>
        ${extra ? `<div class="audit-meta-extra">${extra}</div>` : ""}
    </div>`;
}

/* ─── boot ─────────────────────────────────────────────────────────── */

$("#searchBtn").addEventListener("click", () => { currentPage = 0; loadLogs(); });
$("#refreshBtn").addEventListener("click", () => loadLogs());
$("#prevBtn").addEventListener("click", () => { if (currentPage > 0) { currentPage--; loadLogs(); } });
$("#nextBtn").addEventListener("click", () => { if (currentPage < totalPages - 1) { currentPage++; loadLogs(); } });
["q", "f-type", "f-outcome"].forEach(id => {
    const el = $("#" + id);
    if (el) el.addEventListener("keydown", e => { if (e.key === "Enter") { currentPage = 0; loadLogs(); } });
});

loadLogs();
