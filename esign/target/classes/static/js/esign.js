/* eSign endpoints test page logic */

const SIG_TYPES = ["raw", "PKCS7", "PKCS7pdf", "PKCS7complete"];
const HASH_ALGOS = ["SHA256", "SHA1", "SHA384", "SHA512"];

function initDefaults() {
    setVal("req-ver", "3.3");
    setVal("req-ts", istTimestamp());
    setVal("req-txn", randTxn("ESN"));
    setVal("req-maxwait", "120000");
    setVal("req-aspid", "ASP001");
    setVal("req-responseurl", location.origin + "/esign/auth/callback");
    setVal("req-redirecturl", location.origin + "/esign/auth/callback");
    setVal("req-algo", "RSA");

    setVal("st-ver", "3.3");
    setVal("st-ts", istTimestamp());
    setVal("st-txn", val("req-txn"));
    setVal("st-aspid", "ASP001");

    addDocRow();
}

function addDocRow() {
    const idx = $all("#docsList .doc-row").length;
    const row = document.createElement("div");
    row.className = "doc-row";
    row.innerHTML = `
        <span class="doc-title">Document ${idx + 1}</span>
        <button class="small secondary doc-remove" title="Remove">✕</button>
        <div class="grid">
            <div class="field"><label>id</label><input class="js-doc-id" value="${idx + 1}"></div>
            <div class="field"><label>hashAlgorithm</label>
                <select class="js-doc-hashalgo">${HASH_ALGOS.map(a => `<option${a === "SHA256" ? " selected" : ""}>${a}</option>`).join("")}</select></div>
            <div class="field"><label>responseSigType</label>
                <select class="js-doc-sigtype">${SIG_TYPES.map(a => `<option${a === "raw" ? " selected" : ""}>${a}</option>`).join("")}</select></div>
            <div class="field"><label>docInfo (required, max 50 chars)</label>
                <input class="js-doc-info" value="DemoAgreement.pdf"></div>
            <div class="field wide"><label>docUrl</label>
                <input class="js-doc-url" value="https://acme.example/docs/demo-agreement-${idx + 1}.pdf"></div>
            <div class="field wide"><label>hashValue (hex)</label><input class="js-doc-hash" placeholder="64-char SHA-256 hex digest of the document"></div>
        </div>`;
    row.querySelector(".doc-remove").addEventListener("click", () => row.remove());
    $("#docsList").appendChild(row);
    sampleSha256().then(h => { $(".js-doc-hash", row).value = h; });
}

async function sampleSha256() {
    // Compute a real SHA-256 of a demo payload via subtle crypto
    try {
        const data = new TextEncoder().encode("demo-document-" + Date.now());
        const digest = await crypto.subtle.digest("SHA-256", data);
        return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
    } catch (e) {
        return "ab3f6c8d5e21f4a09b77c2de10fe55aa66bb88dd00cc11ee22ff33aa44bb55cc";
    }
}

$("#addDocBtn").addEventListener("click", addDocRow);
$("#fillSampleHashes").addEventListener("click", async () => {
    for (const input of $all("#docsList .js-doc-hash")) {
        input.value = await sampleSha256();
    }
});
$("#regenTs").addEventListener("click", () => {
    setVal("req-ts", istTimestamp());
    setVal("req-txn", randTxn("ESN"));
});

function buildEsignRequestXml() {
    const docs = $all("#docsList .doc-row").map(row => ({
        id: $(".js-doc-id", row).value.trim(),
        algo: $(".js-doc-hashalgo", row).value,
        sigType: $(".js-doc-sigtype", row).value,
        info: $(".js-doc-info", row).value.trim(),
        url: $(".js-doc-url", row).value.trim(),
        hash: $(".js-doc-hash", row).value.trim()
    }));

    let xml = `<Esign ver="${esc(val("req-ver"))}" ts="${esc(val("req-ts"))}" txn="${esc(val("req-txn"))}"`;
    if (val("req-signerid")) xml += ` signerid="${esc(val("req-signerid"))}"`;
    xml += ` maxWaitPeriod="${esc(val("req-maxwait"))}" aspId="${esc(val("req-aspid"))}"`;
    xml += ` responseUrl="${esc(val("req-responseurl"))}"`;
    if (val("req-redirecturl")) xml += ` redirectUrl="${esc(val("req-redirecturl"))}"`;
    xml += ` signingAlgorithm="${esc(val("req-algo"))}">\n<Docs>\n`;

    for (const d of docs) {
        xml += `<InputHash id="${esc(d.id)}" hashAlgorithm="${esc(d.algo)}" docInfo="${esc(d.info)}" docUrl="${esc(d.url)}" responseSigType="${esc(d.sigType)}">${esc(d.hash)}</InputHash>\n`;
    }
    xml += `</Docs>\n<Signature></Signature>\n</Esign>`;
    return xml;
}

/** Mirrors the server-side document validation so problems are explained
 *  before the request is even sent. Returns a list of human-readable issues. */
function validateDocs(docs) {
    const issues = [];
    docs.forEach((d, i) => {
        const label = `Document ${i + 1}`;
        if (!d.info) issues.push(`${label}: docInfo is required (error 204)`);
        else if (d.info.length > 50) issues.push(`${label}: docInfo exceeds 50 chars (error 204)`);
        if (!d.url) issues.push(`${label}: docUrl is required (error 203)`);
        if (!d.hash) issues.push(`${label}: hashValue is required (error 201)`);
        if (d.algo !== "SHA256") issues.push(`${label}: only SHA256 is accepted (error 205)`);
        if (Number(d.id) !== i + 1) issues.push(`${label}: id must equal its position (${i + 1}) (error 201)`);
    });
    return issues;
}

$("#sendEsign").addEventListener("click", async () => {
    const xml = buildEsignRequestXml();
    showRequestPreview("reqPreviewBlock", xml);

    // client-side mirror of the server's validation
    const docs = $all("#docsList .doc-row").map(row => ({
        id: $(".js-doc-id", row).value.trim(),
        algo: $(".js-doc-hashalgo", row).value,
        info: $(".js-doc-info", row).value.trim(),
        url: $(".js-doc-url", row).value.trim(),
        hash: $(".js-doc-hash", row).value.trim()
    }));
    const issues = validateDocs(docs);
    if (issues.length) {
        const block = $("#reqResult");
        block.classList.add("visible");
        block.innerHTML =
            `<div class="chips">${chip("NOT SENT — fix these first", "bad")}</div>` +
            `<div class="section-label">Validation</div>` +
            issues.map(i => `<div class="hint">${esc(i)}</div>`).join("");
        return;
    }

    const result = await sendXml("/esign/request", xml);
    renderXmlResult("reqResult", result);
});

$("#buildStatus").addEventListener("click", () => {
    setVal("st-ts", istTimestamp());
    const xml = `<EsignStatus ver="${esc(val("st-ver"))}" ts="${esc(val("st-ts"))}" txn="${esc(val("st-txn"))}" aspId="${esc(val("st-aspid"))}">\n<Signature></Signature>\n</EsignStatus>`;
    showRequestPreview("stPreviewBlock", xml);
});

$("#sendStatus").addEventListener("click", async () => {
    const xml = `<EsignStatus ver="${esc(val("st-ver"))}" ts="${esc(val("st-ts"))}" txn="${esc(val("st-txn"))}" aspId="${esc(val("st-aspid"))}">\n<Signature></Signature>\n</EsignStatus>`;
    showRequestPreview("stPreviewBlock", xml);
    const result = await sendXml("/esign/status", xml);
    renderXmlResult("stResult", result);
});

$("#sendGetTxn").addEventListener("click", async () => {
    const id = val("gt-txn-id");
    if (!id) { alert("Enter a transaction id"); return; }
    const result = await getJson("/esign/transaction/" + encodeURIComponent(id));
    renderTextResult("gtResult", result, true);
});

$("#sendCallback").addEventListener("click", async () => {
    const txn = val("cb-txn"), code = val("cb-code") || "1";
    if (!txn) { alert("Enter a transaction id"); return; }
    const txnref = b64(`${txn}|${code}`);
    $("#cb-preview").textContent = "txnref = base64(\"" + txn + "|" + code + "\") = " + txnref;
    const res = await fetch(`/esign/auth/callback?txnref=${encodeURIComponent(txnref)}`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: ""
    });
    renderTextResult("cbResult", { httpStatus: res.status, text: await res.text() }, false);
});

initDefaults();