/* Shared helpers for the eSign test console */

function $(sel, root) { return (root || document).querySelector(sel); }
function $all(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

function esc(value) {
    return String(value == null ? "" : value)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

/** Current time in IST, format yyyy-MM-dd'T'HH:mm:ss+05:30 */
function istTimestamp() {
    const fmt = new Intl.DateTimeFormat("en-GB", {
        timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit",
        day: "2-digit", hour: "2-digit", minute: "2-digit",
        second: "2-digit", hour12: false
    });
    const p = {};
    for (const part of fmt.formatToParts(new Date())) p[part.type] = part.value;
    return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}+05:30`;
}

function randTxn(prefix) {
    return (prefix || "TXN") + "_" + Date.now() + "_" +
        Math.random().toString(36).substring(2, 7).toUpperCase();
}

function b64(str) {
    return btoa(unescape(encodeURIComponent(str)));
}

async function sendXml(path, xml) {
    const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/xml" },
        body: xml
    });
    return { httpStatus: res.status, text: await res.text() };
}

async function getJson(path) {
    const res = await fetch(path);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch (e) { /* ignore */ }
    return { httpStatus: res.status, json, text };
}

async function postJson(path, obj) {
    const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(obj)
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch (e) { /* ignore */ }
    return { httpStatus: res.status, json, text };
}

function val(id) { const el = $("#" + id); return el ? el.value.trim() : ""; }
function setVal(id, v) { const el = $("#" + id); if (el) el.value = v; }

/** Extract interesting attributes from a response XML string. */
function summarizeXml(text) {
    try {
        const doc = new DOMParser().parseFromString(text, "text/xml");
        if (doc.querySelector("parsererror")) return null;
        const root = doc.documentElement;
        const attrs = {};
        for (const attr of root.attributes) attrs[attr.name] = attr.value;
        return { name: root.nodeName, attrs };
    } catch (e) {
        return null;
    }
}

function chip(text, cls) {
    return `<span class="chip ${cls || ""}">${esc(text)}</span>`;
}

/** CCA eSign v3.3 error codes -> human-readable meanings (shown next to error chips) */
const ESIGN_ERROR_MEANINGS = {
    "101": "invalid request format", "102": "invalid signer ID", "103": "invalid version",
    "104": "XML signature validation failed", "105": "invalid transaction ID",
    "106": "invalid ASP ID", "107": "invalid digital signature",
    "108": "minimum one document required", "109": "too many documents",
    "110": "invalid timestamp", "111": "invalid max wait period",
    "112": "duplicate transaction ID", "113": "user timeout", "114": "authentication failed",
    "199": "unknown ESP error", "201": "invalid document hash",
    "202": "invalid response signature type", "203": "invalid document URL",
    "204": "invalid document info (blank or >50 chars)",
    "205": "hash algorithm not allowed (use SHA256)", "206": "document cancelled by user",
    "299": "unknown document error", "301": "invalid status request format",
    "302": "transaction not found", "303": "invalid status version", "399": "unknown status error"
};

function describeErrorCode(code) {
    return ESIGN_ERROR_MEANINGS[code] || null;
}

function renderXmlResult(containerId, result) {
    const block = $("#" + containerId);
    block.classList.add("visible");

    const chips = [chip("HTTP " + result.httpStatus,
        result.httpStatus >= 200 && result.httpStatus < 300 ? "ok" : "bad")];

    const summary = summarizeXml(result.text);
    if (summary) {
        chips.push(chip("<" + summary.name + ">", ""));
        const statusAttr = summary.attrs["status"];
        if (statusAttr !== undefined) {
            chips.push(chip("status=" + statusAttr,
                statusAttr === "1" ? "ok" : statusAttr === "2" ? "warn" : "bad"));
        }
        for (const key of ["error", "resCode", "responseCode", "txn", "ver"]) {
            if (summary.attrs[key] !== undefined) {
                if (key === "error") {
                    const meaning = describeErrorCode(summary.attrs[key]);
                    chips.push(chip(`error ${summary.attrs[key]}${meaning ? " — " + meaning : ""}`, "bad"));
                } else {
                    chips.push(chip(`${key}=${summary.attrs[key]}`, ""));
                }
            }
        }
    }

    let pretty = result.text;
    try {
        const doc = new DOMParser().parseFromString(result.text, "text/xml");
        if (!doc.querySelector("parsererror")) {
            pretty = formatXml(doc.documentElement);
        }
    } catch (e) { /* raw fallback */ }

    block.innerHTML =
        `<div class="chips">${chips.join("")}</div>` +
        `<div class="section-label">Response</div>` +
        `<pre class="xml">${esc(pretty)}</pre>`;
}

function renderTextResult(containerId, result, isJson) {
    const block = $("#" + containerId);
    block.classList.add("visible");
    const chips = [chip("HTTP " + result.httpStatus,
        result.httpStatus >= 200 && result.httpStatus < 300 ? "ok" : "bad")];

    let body = result.text;
    if (isJson && result.json) {
        try { body = JSON.stringify(result.json, null, 2); } catch (e) { /* keep raw */ }
        if (result.json && result.json.error) chips.push(chip("error: " + result.json.error, "bad"));
        if (result.json && result.json.status && !result.json.error) {
            chips.push(chip("status=" + result.json.status, "ok"));
        }
    }

    block.innerHTML =
        `<div class="chips">${chips.join("")}</div>` +
        `<div class="section-label">Response</div>` +
        `<pre class="xml">${esc(body)}</pre>`;
}

function formatXml(node) {
    // Minimal XML serializer with indentation
    function walk(n, depth) {
        const pad = "  ".repeat(depth);
        if (n.nodeType === 3) {
            const t = n.nodeValue.trim();
            return t ? t : "";
        }
        let out = `${pad}<${n.nodeName}`;
        for (const a of n.attributes) out += ` ${a.name}="${a.value}"`;
        const children = Array.from(n.childNodes).filter(c =>
            c.nodeType === 1 || (c.nodeType === 3 && c.nodeValue.trim()));
        if (!children.length) return out + "/>";
        out += ">";
        const inlineText = children.length === 1 && children[0].nodeType === 3;
        if (inlineText) {
            return out + children[0].nodeValue.trim() + `</${n.nodeName}>`;
        }
        for (const c of children) out += "\n" + walk(c, depth + 1);
        return out + `\n${pad}</${n.nodeName}>`;
    }
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + walk(node, 0);
}

function showRequestPreview(previewId, xml) {
    $("#" + previewId).textContent = xml;
}
