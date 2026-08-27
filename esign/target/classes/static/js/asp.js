/* ASP management page logic */

let editingAspId = null;   // null => create mode
let currentTxnAsp = null;

async function refreshTable() {
    const q = val("asp-search");
    const url = q ? `/api/asps?q=${encodeURIComponent(q)}` : "/api/asps";
    const res = await getJson(url);
    const rows = res.json || [];
    const tbody = $("#aspTableBody");

    if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="6" class="hint" style="text-align:center;padding:24px">
            No ASPs registered${q ? " for this search" : ""}. Use “Register new ASP”.</td></tr>`;
        return;
    }

    // Fetch stats lazily per row
    tbody.innerHTML = "";
    for (const a of rows) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><code>${esc(a.aspId)}</code></td>
            <td>${esc(a.organisationName)}<br>
                <span class="hint">${esc(a.contactEmail || "")}${a.contactEmail && a.contactPhone ? " · " : ""}${esc(a.contactPhone || "")}</span></td>
            <td><span class="chip status-${esc(a.status.toLowerCase())}">${esc(a.status)}</span></td>
            <td class="js-txn-count hint">…</td>
            <td class="hint">${esc((a.registeredAt || "").replace("T", " ").substring(0, 16))}</td>
            <td>
                <button class="small secondary" onclick="editAsp('${esc(a.aspId)}')">Edit</button>
                <button class="small secondary" onclick="toggleStatus('${esc(a.aspId)}', '${esc(a.status)}')">
                    ${a.status === "ACTIVE" ? "Suspend" : "Activate"}</button>
                <button class="small secondary js-view" data-asp="${esc(a.aspId)}">Transactions</button>
                <button class="small danger" onclick="deleteAsp('${esc(a.aspId)}')">Delete</button>
            </td>`;
        tbody.appendChild(tr);

        getJson(`/api/asps/${encodeURIComponent(a.aspId)}/stats`).then(s => {
            const cell = tr.querySelector(".js-txn-count");
            if (cell && s.json) cell.textContent = `${s.json.total} total`;
        });
    }
}

function openCreate() {
    editingAspId = null;
    $("#formTitle").textContent = "Register new ASP";
    ["f-organisationName", "f-contactEmail", "f-contactPhone", "f-certificatePem",
     "f-allowedResponseUrlPrefix", "f-notes"].forEach(id => setVal(id, ""));
    setVal("f-aspId", "");
    $("#f-aspId").disabled = false;
    setVal("f-status", "ACTIVE");
}

window.editAsp = async function (aspId) {
    const res = await getJson("/api/asps/" + encodeURIComponent(aspId));
    if (!res.json || res.json.error) { alert(res.json.error); return; }
    const a = res.json;
    editingAspId = aspId;
    $("#formTitle").textContent = "Edit ASP: " + aspId;
    setVal("f-aspId", a.aspId);
    $("#f-aspId").disabled = true;
    setVal("f-organisationName", a.organisationName);
    setVal("f-contactEmail", a.contactEmail || "");
    setVal("f-contactPhone", a.contactPhone || "");
    setVal("f-certificatePem", a.certificatePem || "");
    setVal("f-allowedResponseUrlPrefix", a.allowedResponseUrlPrefix || "");
    setVal("f-status", a.status);
    setVal("f-notes", a.notes || "");
    $("#aspFormCard").open = true;
    $("#aspFormCard").scrollIntoView({ behavior: "smooth", block: "start" });
};

$("#saveAspBtn").addEventListener("click", async () => {
    const body = {
        aspId: val("f-aspId"),
        organisationName: val("f-organisationName"),
        contactEmail: val("f-contactEmail") || null,
        contactPhone: val("f-contactPhone") || null,
        certificatePem: $("#f-certificatePem").value.trim() || null,
        allowedResponseUrlPrefix: val("f-allowedResponseUrlPrefix") || null,
        status: val("f-status"),
        notes: $("#f-notes").value.trim() || null
    };

    let result;
    if (editingAspId) {
        result = await new Promise(resolve =>
            fetch(`/api/asps/${encodeURIComponent(editingAspId)}`, {
                method: "PUT", headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body)
            }).then(async r => resolve({ httpStatus: r.status, json: await r.json().catch(() => null), text: "" }))
        );
    } else {
        result = await postJson("/api/asps", body);
    }

    renderTextResult("formResult", result, true);
    if (result.httpStatus < 300) {
        if (!editingAspId) openCreate();
        await refreshTable();
    }
});

window.toggleStatus = async function (aspId, current) {
    const next = current === "ACTIVE" ? "SUSPENDED" : "ACTIVE";
    if (!confirm(`${next} ${aspId}?`)) return;
    const res = await postJson(`/api/asps/${encodeURIComponent(aspId)}/status?status=${next}`, {});
    if (res.httpStatus >= 300) alert(res.json && res.json.error);
    await refreshTable();
};

window.deleteAsp = async function (aspId) {
    if (!confirm(`Delete ASP ${aspId}? Its transactions remain in history.`)) return;
    const res = await new Promise(resolve =>
        fetch(`/api/asps/${encodeURIComponent(aspId)}`, { method: "DELETE" })
            .then(async r => resolve({ httpStatus: r.status, json: await r.json().catch(() => null), text: "" }))
    );
    renderTextResult("formResult", res, true);
    await refreshTable();
};

document.addEventListener("click", async (e) => {
    const btn = e.target.closest(".js-view");
    if (!btn) return;
    await showTransactions(btn.dataset.asp);
});

window.showTransactions = async function (aspId) {
    currentTxnAsp = aspId;
    $("#txnPanelTitle").textContent = "Recent transactions — " + aspId;
    const block = $("#txnPanelBlock");
    block.classList.add("visible");
    $("#txnTableWrap").innerHTML = `<p class="hint">Loading…</p>`;

    const [statsRes, txnRes] = await Promise.all([
        getJson(`/api/asps/${encodeURIComponent(aspId)}/stats`),
        getJson(`/api/asps/${encodeURIComponent(aspId)}/transactions`)
    ]);

    let statsHtml = "";
    if (statsRes.json) {
        statsHtml = Object.entries(statsRes.json)
            .filter(([k]) => k !== "aspId")
            .map(([k, v]) => chip(`${k}: ${v}`, k === "total" ? "" : v > 0 && k !== "completed" ? "warn" : ""))
            .join("");
    }

    const rows = txnRes.json || [];
    let tableHtml;
    if (!rows.length) {
        tableHtml = `<p class="hint">No transactions yet for ${esc(aspId)}.</p>`;
    } else {
        tableHtml = `<table class="dir"><tr>
            <th>Txn</th><th>Status</th><th>Signer</th><th>Created</th><th>Error</th></tr>` +
            rows.map(t => `<tr>
                <td><code>${esc(t.transactionId)}</code></td>
                <td><span class="chip ${t.status === "COMPLETED" ? "ok" : t.status === "FAILED" || t.status === "EXPIRED" || t.status === "CANCELLED" ? "bad" : "warn"}">${esc(t.status)}</span></td>
                <td>${esc(t.signerId || "—")}</td>
                <td class="hint">${esc((t.createdAt || "").replace("T", " ").substring(0, 19))}</td>
                <td>${esc(t.errorCode || "")}</td></tr>`).join("") +
            `</table>`;
    }
    $("#txnTableWrap").innerHTML =
        `<div class="chips" style="margin-bottom:10px">${statsHtml}</div>` + tableHtml;
};

$("#refreshBtn").addEventListener("click", refreshTable);
$("#newAspBtn").addEventListener("click", () => { openCreate(); $("#aspFormCard").open = true; });
$("#asp-search").addEventListener("keydown", e => { if (e.key === "Enter") refreshTable(); });
$("#searchBtn").addEventListener("click", refreshTable);

openCreate();
refreshTable();