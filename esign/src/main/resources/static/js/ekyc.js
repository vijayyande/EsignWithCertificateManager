/* eKYC endpoints test page logic */

function initDefaults() {
    setVal("au-ver", "3.3");
    setVal("au-ts", istTimestamp());
    setVal("au-txn", randTxn("EKY"));
    setVal("sf-ver", "3.3");
    setVal("sf-ts", istTimestamp());
    setVal("sf-consent", "Y");
    setVal("bk-country", "IN");
    $("#bk-dob").value = "1990-01-15";
}

/* ---------- Dev tools ---------- */

$("#createUserBtn").addEventListener("click", async () => {
    const body = {
        username: val("cu-username"),
        pin: val("cu-pin"),
        name: val("cu-name"),
        mobile: val("cu-mobile"),
        email: val("cu-email"),
        address: val("cu-address"),
        stateProvince: val("cu-state"),
        country: val("cu-country") || "IN",
        postalCode: val("cu-postal"),
        dob: $("#cu-dob").value,
        gender: val("cu-gender"),
        pan: val("cu-pan"),
        aadhaarLast4: val("cu-aadhaar"),
        ekycType: val("cu-ekyctype")
    };
    renderTextResult("cuResult", await postJson("/esign/dev/users", body), true);
});

$("#getUserBtn").addEventListener("click", async () => {
    const u = val("gu-username");
    if (!u) { alert("Enter a username"); return; }
    renderTextResult("guResult", await getJson("/esign/dev/users/" + encodeURIComponent(u)), true);
});

$("#computePinHash").addEventListener("click", async () => {
    const u = val("ph-username"), pin = val("ph-pin"), txn = val("ph-txn") || val("au-txn");
    if (!u || !pin) { alert("Username and PIN required"); return; }
    const result = await getJson(`/esign/dev/pin-hash?username=${encodeURIComponent(u)}&pin=${encodeURIComponent(pin)}&txn=${encodeURIComponent(txn)}`);
    renderTextResult("phResult", result, true);
    if (result.json && result.json.pinHash) {
        setVal("au-pinhash", result.json.pinHash);
        setVal("au-signerid", u);
        setVal("sf-signerid", u);
        if (result.json.pinValid === false && $("#phResult .chips")) {
            $("#phResult .chips").insertAdjacentHTML("beforeend",
                `<span class="chip warn">PIN did not match stored hash — hash computed anyway</span>`);
        }
    }
});

/* ---------- eKYC Auth ---------- */

$("#toggleSecondFactor").addEventListener("change", (e) => {
    $("#authSecondFactorSub").classList.toggle("visible", e.target.checked);
});

/**
 * Builds a SecondFactorRequest XML.
 * idSuffix "" reads the embedded (composite) fields; "2" reads the standalone form fields.
 */
function buildSecondFactorXml(o) {
    const v = (base) => val(base + o.suffix);
    let xml = `<SecondFactorRequest ver="${esc(o.ver)}" signerid="${esc(o.signerid)}" ts="${esc(o.ts)}" txn="${esc(o.txn)}"`;
    xml += ` authenticationType="${esc(o.type)}" consent="${esc(val("sf-consent"))}">\n`;

    if (o.type === "SMSOTP" && v("sf-smsotp")) xml += `<SMSOTP>${esc(v("sf-smsotp"))}</SMSOTP>\n`;
    if (o.type === "TOTP" && v("sf-totp")) xml += `<TOTP>${esc(v("sf-totp"))}</TOTP>\n`;
    if (o.type === "MAT" && v("sf-mat")) xml += `<MAT>${esc(v("sf-mat"))}</MAT>\n`;
    if (o.type === "FIDO" && v("sf-fido")) xml += `<FIDO>${esc(v("sf-fido"))}</FIDO>\n`;
    if (o.type === "PUBSIGN" && v("sf-pubsign")) xml += `<PUBSIGN>${esc(v("sf-pubsign"))}</PUBSIGN>\n`;

    xml += `<Signature></Signature>\n</SecondFactorRequest>`;
    return xml;
}

$("#sendAuth").addEventListener("click", async () => {
    setVal("au-ts", istTimestamp());
    let xml = `<eKycReq ver="${esc(val("au-ver"))}" signerid="${esc(val("au-signerid"))}" ts="${esc(val("au-ts"))}" txn="${esc(val("au-txn"))}" pinhash="${esc(val("au-pinhash"))}">`;

    if ($("#toggleSecondFactor").checked) {
        const inner = buildSecondFactorXml({
            ver: val("au-ver"), signerid: val("au-signerid"),
            ts: val("au-ts"), txn: val("au-txn"),
            type: val("sf-type"), suffix: ""
        });
        showRequestPreview("sfInnerPreview", inner);
        xml += `\n<SecondFactor>${b64(inner)}</SecondFactor>`;
    }
    xml += `\n<Signature></Signature>\n</eKycReq>`;

    showRequestPreview("auPreviewBlock", xml);
    const result = await sendXml("/ekyc/auth", xml);
    renderXmlResult("auResult", result);

    // Convenience: carry txn/signer over to the standalone second-factor form
    setVal("sf-txn", val("au-txn"));
});

/* ---------- Second factor standalone ---------- */

function toggleSfFields(selectEl, containerSel) {
    const t = selectEl.value;
    $all(containerSel + " .field[data-for]").forEach(f => {
        f.style.display = f.dataset.for === t ? "flex" : "none";
    });
}

$("#sf2-type").addEventListener("change", (e) => toggleSfFields(e.target, "#sfFields"));
toggleSfFields($("#sf2-type"), "#sfFields");

$("#sendOtpDevBtn").addEventListener("click", async () => {
    const u = val("sf-signerid"), txn = val("sf-txn");
    if (!u || !txn) { alert("Signer ID and Txn are required to send an OTP"); return; }
    const result = await getJson(`/esign/dev/send-otp?username=${encodeURIComponent(u)}&txn=${encodeURIComponent(txn)}`);
    renderTextResult("sendOtpResult", result, true);
    if (result.json && result.json.otp) {
        setVal("sf-smsotp2", result.json.otp);   // standalone form
        setVal("sf-smsotp", result.json.otp);    // composite form too, if used
    }
});

$("#sendSecondFactor").addEventListener("click", async () => {
    setVal("sf-ts", istTimestamp());
    const xml = buildSecondFactorXml({
        ver: val("sf-ver"), signerid: val("sf-signerid"),
        ts: val("sf-ts"), txn: val("sf-txn"),
        type: val("sf2-type"), suffix: "2"
    });
    showRequestPreview("sfPreviewBlock", xml);
    const result = await sendXml("/ekyc/auth/second-factor", xml);
    renderXmlResult("sfResult", result);
});

/* ---------- Bank KYC ---------- */

$("#sendBankKyc").addEventListener("click", async () => {
    setVal("bk-ts", istTimestamp());
    setVal("bk-txn", randTxn("BNK"));
    const photo = $("#bk-photo").value.trim() ||
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    const fmt = val("bk-photoformat") || "PNG";

    let xml = `<BankKYC ver="${esc(val("bk-ver"))}" ts="${esc(val("bk-ts"))}" txn="${esc(val("bk-txn"))}"`;
    if (val("bk-ifsc")) xml += ` bankIfscCode="${esc(val("bk-ifsc"))}"`;
    xml += ` bankName="${esc(val("bk-bankname"))}" accountNumber="${esc(val("bk-account"))}">\n`;
    xml += `<KYCInfo name="${esc(val("bk-name"))}" mobile="${esc(val("bk-mobile"))}"`;
    if (val("bk-email")) xml += ` email="${esc(val("bk-email"))}"`;
    xml += ` address="${esc(val("bk-address"))}" stateProvince="${esc(val("bk-state"))}" country="${esc(val("bk-country"))}" postalCode="${esc(val("bk-postal"))}" dateOfBirth="${esc($("#bk-dob").value)}" gender="${esc(val("bk-gender"))}"`;
    if (val("bk-pan")) xml += ` pan="${esc(val("bk-pan"))}"`;
    if (val("bk-aadhaar")) xml += ` aadhaar="${esc(val("bk-aadhaar"))}"`;
    xml += ` />\n<Photo format="${esc(fmt)}">${esc(photo)}</Photo>\n<Signature></Signature>\n</BankKYC>`;

    showRequestPreview("bkPreviewBlock", xml);
    const result = await sendXml("/ekyc/bank-kyc", xml);
    renderXmlResult("bkResult", result);
});

/* ---------- Public key registration ---------- */

$("#sendPubKey").addEventListener("click", async () => {
    const key = $("#pk-key").value.trim() || "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA-demo-public-key";
    const xml = `<PublicKeyRegistration>\n<PublicKeyData SignerId="${esc(val("pk-signerid"))}" TimeStamp="${esc(istTimestamp())}" Algorithm="${esc(val("pk-algo"))}" Consent="${esc(val("pk-consent"))}">${esc(key)}</PublicKeyData>\n<Signature></Signature>\n</PublicKeyRegistration>`;
    showRequestPreview("pkPreviewBlock", xml);
    const result = await sendXml("/ekyc/public-key/register", xml);
    renderTextResult("pkResult", result, false);
});

initDefaults();