/* eSign user authentication page — /auth.html?txn=TXN-ID */

(function () {
    'use strict';

    const $ = (sel) => document.querySelector(sel);
    const params = new URLSearchParams(location.search);
    const txnId = params.get('txn');
    const redirectUrl = params.get('redirectUrl');
    let txnData = null;

    /* ─── boot ─────────────────────────────────────────────────────── */

    if (!txnId) {
        showError('No transaction ID provided. Add ?txn=TXN-ID to the URL.');
    } else {
        loadTransaction(txnId);
    }

    $('#sendOtpBtn').addEventListener('click', requestOtp);
    $('#signBtn').addEventListener('click', signDocument);

    /* ─── load transaction ─────────────────────────────────────────── */

    async function loadTransaction(id) {
        const res = await getJson('/esign/dev/transactions/' + encodeURIComponent(id));
        if (res.httpStatus !== 200 || !res.json || res.json.error) {
            showError(res.json ? res.json.error : 'HTTP ' + res.httpStatus);
            return;
        }
        txnData = res.json;

        if (txnData.status === 'COMPLETED') {
            showAlreadySigned(txnData);
            return;
        }
        if (txnData.status !== 'PENDING' && txnData.status !== 'IN_PROGRESS') {
            showError('Transaction is ' + txnData.status + ' — cannot sign.');
            return;
        }

        $('#txnId').value = txnData.transactionId;
        $('#aspId').value = txnData.aspId;
        $('#signingAlgo').value = txnData.signingAlgorithm;

        if (txnData.signerId) {
            $('#username').value = txnData.signerId;
        }

        renderDocs(txnData.documents || []);

        $('#loadingCard').style.display = 'none';
        $('#authCard').style.display = '';
    }

    function renderDocs(docs) {
        const container = $('#docList');
        if (!docs.length) {
            container.innerHTML = '<p class="hint">No documents attached.</p>';
            return;
        }
        container.innerHTML = docs.map(d => {
            const hashTruncated = (d.documentHash || '').substring(0, 40);
            const hashLen = (d.documentHash || '').length;
            return `<div style="background:var(--panel-2);border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin-bottom:8px">
                <div class="chips" style="margin-bottom:6px">
                    ${chip('Doc #' + d.documentId)}
                    ${chip(d.hashAlgorithm)}
                    ${chip(d.responseSigType, 'dim')}
                </div>
                <div style="font-size:13px;margin-bottom:4px"><strong>Info:</strong> ${esc(d.docInfo || '—')}</div>
                <div style="font-size:12px;font-family:var(--mono);word-break:break-all;color:var(--muted)">
                    <strong>Hash:</strong> ${esc(hashTruncated)}${hashLen > 40 ? '… (' + hashLen + ' chars)' : ''}
                </div>
            </div>`;
        }).join('');
    }

    /* ─── request OTP ──────────────────────────────────────────────── */

    async function requestOtp() {
        const username = $('#username').value.trim();
        if (!username) { alert('Enter a username'); return; }

        const btn = $('#sendOtpBtn');
        btn.disabled = true;
        btn.textContent = 'Sending…';

        try {
            const txn = txnId;
            const res = await getJson('/esign/dev/send-otp?username=' + encodeURIComponent(username)
                + '&txn=' + encodeURIComponent(txn));
            if (res.httpStatus === 200 && res.json && res.json.otp) {
                $('#otpHint').style.display = '';
                $('#otpValue').textContent = res.json.otp;
                $('#otp').focus();
            } else {
                alert('Failed to send OTP: ' + (res.json ? res.json.error : 'HTTP ' + res.httpStatus));
            }
        } catch (e) {
            alert('Error: ' + e.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Request OTP';
        }
    }

    /* ─── sign document ────────────────────────────────────────────── */

    async function signDocument() {
        const username = $('#username').value.trim();
        const pin = $('#pin').value.trim();
        const otp = $('#otp').value.trim();

        if (!username) { alert('Enter username'); return; }
        if (!pin) { alert('Enter PIN'); return; }
        if (!otp || otp.length < 4) { alert('Enter valid OTP'); return; }

        const btn = $('#signBtn');
        btn.disabled = true;
        log('Authenticating and signing…');

        try {
            const res = await postJson('/esign/dev/auth-and-sign', {
                transactionId: txnId,
                username: username,
                pin: pin,
                otp: otp,
                signingTime: new Date().toISOString()
            });

            if (res.httpStatus !== 200 || !res.json || res.json.error) {
                throw new Error(res.json ? res.json.error : 'HTTP ' + res.httpStatus);
            }

            log('Signing complete — ' + res.json.documentsSigned + ' document(s) signed');
            showSuccess(res.json);

        } catch (err) {
            log('ERROR: ' + err.message, true);
            alert('Signing failed: ' + err.message);
        } finally {
            btn.disabled = false;
        }
    }

    /* ─── success ──────────────────────────────────────────────────── */

    function showSuccess(data) {
        $('#authCard').style.display = 'none';
        $('#successCard').style.display = '';

        let html = `<div class="chips" style="margin-bottom:12px">
            ${chip('COMPLETED', 'ok')}
            ${chip(data.documentsSigned + ' doc(s) signed')}
            ${chip('signer: ' + esc(data.signerId))}
        </div>`;

        if (data.certificate) {
            html += `<div class="section-label">Certificate</div>
                <pre class="xml" style="font-size:11px;max-height:180px;overflow:auto">${esc(data.certificate)}</pre>`;
        }

        if (data.esignResponse) {
            html += `<div class="section-label">eSign Response XML</div>
                <pre class="xml" style="font-size:11px;max-height:200px;overflow:auto">${esc(JSON.stringify(data.esignResponse, null, 2))}</pre>`;
        }

        if (data.redirectUrl) {
            html += `<div style="margin-top:14px">
                <a href="${esc(data.redirectUrl)}" style="color:var(--accent-2)">Return to ASP →</a>
            </div>`;
        }

        $('#successDetails').innerHTML = html;

        /* Wire download buttons */
        if (data.certificate) {
            $('#downloadCertBtn').addEventListener('click', () => {
                downloadText(data.certificate, 'certificate.pem');
            });
        }
        if (data.esignResponse) {
            $('#downloadSignedBtn').addEventListener('click', () => {
                downloadText(JSON.stringify(data.esignResponse, null, 2), 'esign-response.json');
            });
        }
    }

    function showAlreadySigned(txnData) {
        $('#loadingCard').style.display = 'none';
        $('#authCard').style.display = 'none';
        $('#successCard').style.display = '';
        $('#successDetails').innerHTML = `
            <div class="chips" style="margin-bottom:12px">${chip('ALREADY SIGNED', 'ok')}</div>
            <p>Transaction <code>${esc(txnData.transactionId)}</code> was already completed.</p>`;
    }

    /* ─── helpers ──────────────────────────────────────────────────── */

    function showError(msg) {
        $('#loadingCard').style.display = 'none';
        $('#errorCard').style.display = '';
        $('#errorMsg').textContent = msg;
    }

    function log(msg, isErr) {
        const line = document.createElement('div');
        line.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
        if (isErr) line.style.color = 'var(--red)';
        $('#progress').appendChild(line);
    }

    function downloadText(text, filename) {
        const blob = new Blob([text], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
        URL.revokeObjectURL(a.href);
    }
})();
