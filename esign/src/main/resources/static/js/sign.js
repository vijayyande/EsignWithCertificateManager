/**
 * CCA eSign flow demo — hash-only PDF signing.
 *
 * Two entry points:
 *  1. NEW SIGNING — upload PDF, compute hash, submit, redirect to auth, poll, embed
 *  2. LOOKUP EXISTING — enter txnId, check status, re-select PDF, embed signature
 */
(function () {
    'use strict';

    const $ = (sel) => document.querySelector(sel);
    const LS_KEY_PREFIX = 'esign_pdf_';
    const LS_KEY_NAME   = 'esign_pdf_name';

    /* Reserved size (bytes) for the embedded CMS. Covers an RSA-2048 signature,
       cert chain and RFC 3161 timestamp with room to spare; CMS is right-padded
       with zero bytes to exactly this length so the PDF byte offsets stay stable. */
    const CMS_RESERVED_BYTES = 8192;

    /* ─── shared state ──────────────────────────────────────────────── */

    let originalPdfBytes = null;
    let fileName         = 'signed.pdf';
    let pendingTxnId     = null;
    /* Prepared placeholder PDF: same layout as the final signed file, but with a
       zero-filled Contents of reserved length and a real ByteRange. The hash that
       is submitted to eSign is taken over these reserved bytes, so after the CMS
       is swapped in, the digest still matches and Adobe validates the signature. */
    let preparedPdf      = null;

    /* ─── lookup section ────────────────────────────────────────────── */

    const lookupBtn    = $('#lookupBtn');
    const lookupInput  = $('#lookupTxn');
    const lookupDiv    = $('#lookupResult');
    const embedSection = $('#embedSection');
    const embedFileInput = $('#embedFileInput');
    const embedBtn     = $('#embedBtn');
    const embedProgress = $('#embedProgress');

    const urlParams = new URLSearchParams(location.search);
    const urlLookup = urlParams.get('lookup');
    if (urlLookup) lookupInput.value = urlLookup;

    lookupBtn.addEventListener('click', lookupTransaction);
    lookupInput.addEventListener('keydown', e => { if (e.key === 'Enter') lookupTransaction(); });

    embedFileInput.addEventListener('change', () => {
        embedBtn.disabled = !embedFileInput.files[0];
    });
    embedBtn.addEventListener('click', embedFromLookup);

    /* ─── lookup transaction ────────────────────────────────────────── */

    async function lookupTransaction() {
        const txnId = lookupInput.value.trim();
        if (!txnId) { alert('Enter a transaction ID'); return; }

        lookupBtn.disabled = true;
        lookupBtn.textContent = 'Looking up…';
        lookupDiv.style.display = 'none';
        embedSection.style.display = 'none';

        try {
            const res = await fetchJson('/esign/dev/transactions/' + encodeURIComponent(txnId));
            if (res.httpStatus !== 200 || !res.json || res.json.error) {
                const msg = res.json ? res.json.error : 'HTTP ' + res.httpStatus;
                lookupDiv.innerHTML = `<div class="chips">${chip('NOT FOUND', 'bad')}</div><p style="margin-top:8px;color:var(--red)">${esc(msg)}</p>`;
                lookupDiv.style.display = '';
                return;
            }

            const tx = res.json;
            const isComplete = tx.status === 'COMPLETED';
            const isPending = tx.status === 'PENDING' || tx.status === 'IN_PROGRESS';
            const statusCls = isComplete ? 'ok' : isPending ? 'warn' : 'bad';

            let html = `<div class="chips" style="margin-bottom:10px">
                ${chip(tx.status, statusCls)}
                ${chip('txn=' + esc(tx.transactionId))}
                ${chip('asp=' + esc(tx.aspId))}
                ${chip('algo=' + esc(tx.signingAlgorithm))}
            </div>`;

            if (tx.documents && tx.documents.length) {
                html += `<div class="section-label">Documents (${tx.documents.length})</div>`;
                for (const d of tx.documents) {
                    const hasSig = d.signatureValue && d.signatureValue.length > 0;
                    html += `<div style="background:var(--panel-2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:6px">
                        <div class="chips" style="margin-bottom:4px">
                            ${chip('Doc #' + d.documentId)}
                            ${chip(d.hashAlgorithm)}
                            ${hasSig ? chip('SIGNED', 'ok') : chip('unsigned', 'dim')}
                        </div>
                        <div style="font-size:12px;color:var(--muted)">Info: ${esc(d.docInfo || '—')}</div>
                        ${hasSig ? `<div style="font-size:11px;font-family:var(--mono);word-break:break-all;margin-top:4px;color:var(--green)">
                            Sig (${d.signatureValue.length} chars): ${esc(d.signatureValue.substring(0, 60))}…
                        </div>` : ''}
                    </div>`;
                }
            }

            if (tx.userCertificate) {
                html += `<div class="section-label">Certificate</div>
                    <pre class="xml" style="font-size:10px;max-height:120px;overflow:auto">${esc(tx.userCertificate)}</pre>`;
            }

            lookupDiv.innerHTML = html;
            lookupDiv.style.display = '';

            if (isComplete) {
                const hasSig = tx.documents && tx.documents.some(d => d.signatureValue);
                if (hasSig) {
                    /* Try to auto-embed from localStorage first */
                    const storedPdf = loadPdfFromStorage(txnId);
                    if (storedPdf) {
                        embedLog('Found original PDF in memory — embedding signature…');
                        embedSection.style.display = 'none';
                        await autoEmbed(txnId, storedPdf.bytes, storedPdf.name);
                    } else {
                        embedSection.style.display = '';
                        embedBtn.dataset.txnId = txnId;
                        embedLog('Select the original PDF to embed the signature.');
                    }
                }
            } else if (isPending) {
                embedSection.style.display = 'none';
                lookupDiv.innerHTML += `<p style="margin-top:10px;font-size:.9rem;color:var(--muted)">
                    Transaction is still pending. Complete authentication at
                    <a href="/auth.html?txn=${encodeURIComponent(txnId)}" style="color:var(--accent-2)">/auth.html?txn=${esc(txnId)}</a>
                    then check status again.</p>`;
            }

        } catch (err) {
            lookupDiv.innerHTML = `<p style="color:var(--red)">Error: ${esc(err.message)}</p>`;
            lookupDiv.style.display = '';
        } finally {
            lookupBtn.disabled = false;
            lookupBtn.textContent = 'Check Status';
        }
    }

    /* ─── embed from manual file pick ───────────────────────────────── */

    async function embedFromLookup() {
        const file = embedFileInput.files[0];
        const txnId = embedBtn.dataset.txnId;
        if (!file || !txnId) return;

        embedBtn.disabled = true;
        embedLog('Reading PDF…');

        try {
            const pdfBytes = await file.arrayBuffer();
            const res = await fetchJson('/esign/dev/transactions/' + encodeURIComponent(txnId));
            if (res.httpStatus !== 200 || !res.json) throw new Error('Failed to fetch transaction');

            const docs = res.json.documents || [];
            const signedDoc = docs.find(d => d.signatureValue);
            if (!signedDoc) throw new Error('No signature found in transaction');

            const cmsB64 = signedDoc.signatureValue;
            embedLog('Embedding CMS signature (' + cmsB64.length + ' chars)…');

            const signedBytes = await embedCmsIntoPdf(pdfBytes, cmsB64, signedDoc.signedAt);
            const outName = file.name.replace(/\.pdf$/i, '') + '_signed.pdf';
            download(new Blob([signedBytes], { type: 'application/pdf' }), outName);
            embedLog('Downloaded: ' + outName + ' (' + signedBytes.length + ' bytes)');

        } catch (err) {
            embedLog('ERROR: ' + err.message, true);
        } finally {
            embedBtn.disabled = false;
        }
    }

    /* ─── auto-embed from stored PDF ────────────────────────────────── */

    async function autoEmbed(txnId, pdfBytes, originalName) {
        try {
            const res = await fetchJson('/esign/dev/transactions/' + encodeURIComponent(txnId));
            if (res.httpStatus !== 200 || !res.json) throw new Error('Failed to fetch transaction');

            const docs = res.json.documents || [];
            const signedDoc = docs.find(d => d.signatureValue);
            if (!signedDoc) throw new Error('No signature found in transaction');

            const cmsB64 = signedDoc.signatureValue;
            if (!cmsB64 || typeof cmsB64 !== 'string' || cmsB64.length < 10) {
                throw new Error('Signature value invalid (len=' + (cmsB64 ? cmsB64.length : 0) + ')');
            }
            log('Embedding CMS signature (' + cmsB64.length + ' chars)…');

            const signedBytes = embedCmsIntoPrepared(pdfBytes, cmsB64);
            const outName = originalName.replace(/\.pdf$/i, '') + '_signed.pdf';

            showCompletionStep3(txnId, docs, signedBytes, outName);
            clearPdfStorage(txnId);

        } catch (err) {
            log('ERROR embedding: ' + err.message, true);
            /* Fall back to manual pick */
            embedSection.style.display = '';
            embedBtn.dataset.txnId = txnId;
            embedLog('Auto-embed failed. Select the original PDF manually.');
        }
    }

    /* ─── localStorage helpers for PDF bytes ─────────────────────────── */

    function savePdfToStorage(txnId, arrayBuffer, name) {
        try {
            /* Convert to base64 in chunks to avoid call-stack overflow */
            const bytes = new Uint8Array(arrayBuffer);
            let binary = '';
            const chunk = 32768;
            for (let i = 0; i < bytes.length; i += chunk) {
                binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
            }
            localStorage.setItem(LS_KEY_PREFIX + txnId, btoa(binary));
            localStorage.setItem(LS_KEY_NAME + txnId, name);
        } catch (e) {
            /* localStorage full or unavailable — degrade silently */
            console.warn('Could not store PDF in localStorage:', e.message);
        }
    }

    function loadPdfFromStorage(txnId) {
        try {
            const b64 = localStorage.getItem(LS_KEY_PREFIX + txnId);
            if (!b64) return null;
            const name = localStorage.getItem(LS_KEY_NAME + txnId) || 'document.pdf';
            const binary = atob(b64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            return { bytes: bytes.buffer, name };
        } catch (e) {
            return null;
        }
    }

    function clearPdfStorage(txnId) {
        try {
            localStorage.removeItem(LS_KEY_PREFIX + txnId);
            localStorage.removeItem(LS_KEY_NAME + txnId);
        } catch (e) { /* ignore */ }
    }

    function embedLog(msg, isErr) {
        const line = document.createElement('div');
        line.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
        if (isErr) line.style.color = 'var(--red)';
        embedProgress.appendChild(line);
    }

    /* ─── new signing flow ──────────────────────────────────────────── */

    const fileInput  = $('#fileInput');
    const submitBtn  = $('#submitBtn');
    const progressDiv = $('#progress');

    fileInput.addEventListener('change', async () => {
        const file = fileInput.files[0];
        if (!file) return;
        fileName = file.name.replace(/\.pdf$/i, '') + '_signed.pdf';
        originalPdfBytes = await file.arrayBuffer();
        submitBtn.disabled = false;
        log('Loaded: ' + file.name + ' (' + file.size + ' bytes)');
    });

    submitBtn.addEventListener('click', runNewSigning);

    async function runNewSigning() {
        submitBtn.disabled = true;
        try {
            /* Pass 1: reserve signature space in the PDF and compute the hash over the
               bytes that will actually be covered by the ByteRange. eSign signs THIS
               hash, so Adobe's re-digest matches after the CMS is embedded. */
            log('Preparing PDF signature placeholder…');
            preparedPdf = await preparePdfForSigning(originalPdfBytes, null);
            log('Reserved ' + CMS_RESERVED_BYTES + ' bytes for CMS; ByteRange computed');

            log('Computing SHA-256 over the signed byte-range…');
            const hashB64 = await sha256Base64(preparedPdf.coverBytes);
            $('#hashValue').textContent = hashB64;

            const txn = 'TXN-' + Date.now().toString(36).toUpperCase();
            pendingTxnId = txn;
            const xml = buildEsignXml(hashB64, txn);
            $('#reqXml').textContent = formatXml(xml);

            /* Store protected (placeholder) bytes in localStorage so we can embed after
               redirect — the digest matches THIS content, not the raw upload. */
            savePdfToStorage(txn, preparedPdf.bytes, fileName);

            log('Sending eSign request…');
            const esignResp = await postText('/esign/request', xml, 'text/plain');
            $('#respXml').textContent = formatXml(esignResp);
            const status = extractAttr(esignResp, 'status');
            log('eSign response — status=' + status + ' txn=' + txn);

            if (status !== '2') {
                throw new Error('Expected PENDING (status=2), got status=' + status
                    + ' error=' + extractAttr(esignResp, 'error'));
            }

            $('#step2Card').style.display = '';
            const authUrl = '/auth.html?txn=' + encodeURIComponent(txn);
            $('#authRedirect').innerHTML =
                `<div class="chips" style="margin-bottom:8px">${chip('PENDING', 'warn')} ${chip('txn=' + txn)}</div>
                 <p style="font-size:.92rem">Redirect the eSign user to authenticate:</p>
                 <a href="${esc(authUrl)}" style="color:var(--accent-2);font-size:1.05rem;font-weight:600">${esc(authUrl)}</a>
                 <p class="hint" style="margin-top:8px">After authentication you will be redirected back —
                 the signed PDF will be downloaded automatically.</p>`;

            log('Waiting for signing completion…');
            await pollForCompletion(txn);

        } catch (err) {
            log('ERROR: ' + err.message, true);
        } finally {
            submitBtn.disabled = false;
        }
    }

    async function pollForCompletion(txnId) {
        const maxAttempts = 120;
        for (let i = 0; i < maxAttempts; i++) {
            await sleep(1000);
            try {
                const statusXml = buildStatusXml(txnId);
                const resp = await postText('/esign/status', statusXml, 'text/plain');
                const status = extractAttr(resp, 'status');

                if (status === '1') {
                    log('Transaction completed!');
                    $('#respXml').textContent = formatXml(resp);
                    await handleCompletion(txnId);
                    return;
                } else if (status === '0') {
                    throw new Error('Transaction failed: error=' + extractAttr(resp, 'error'));
                }
                if (i % 10 === 9) log('Still waiting… (' + (i + 1) + 's)');
            } catch (e) {
                if (e.message && e.message.startsWith('Transaction failed')) throw e;
            }
        }
        throw new Error('Timed out waiting for signing (2 min)');
    }

    async function handleCompletion(txnId) {
        const detail = await fetchJson('/esign/dev/transactions/' + txnId);
        if (!detail.json || detail.httpStatus !== 200) {
            log('Could not fetch transaction details');
            return;
        }

        const docs = detail.json.documents || [];
        const completedDoc = docs.find(d => d.signatureValue);
        if (!completedDoc) {
            log('No signature found in transaction');
            return;
        }

        const cmsB64 = completedDoc.signatureValue;
        $('#sigValue').textContent = cmsB64.substring(0, 120) + '… (' + cmsB64.length + ' chars)';
        log('CMS signature extracted (' + cmsB64.length + ' chars)');

        if (preparedPdf && preparedPdf.bytes) {
            log('Embedding CMS signature into prepared PDF…');
            const signedBytes = embedCmsIntoPrepared(preparedPdf.bytes, cmsB64);
            showCompletionStep3(txnId, docs, signedBytes, fileName);
        } else {
            /* Prepared bytes lost — try localStorage (stores the prepared buffer) */
            const stored = loadPdfFromStorage(txnId);
            if (stored) {
                log('Retrieved prepared PDF from memory — embedding…');
                const signedBytes = embedCmsIntoPrepared(stored.bytes, cmsB64);
                showCompletionStep3(txnId, docs, signedBytes, stored.name);
                clearPdfStorage(txnId);
            } else if (originalPdfBytes) {
                /* Legacy fallback: re-prepare deterministically from the original upload */
                log('Re-preparing placeholder from original PDF — embedding…');
                const signedBytes = await embedCmsIntoPdf(originalPdfBytes, cmsB64, completedDoc.signedAt);
                showCompletionStep3(txnId, docs, signedBytes, fileName);
            } else {
                log('PDF not in memory — redirecting to lookup…');
                lookupInput.value = txnId;
                lookupTransaction();
            }
        }
    }

    function showCompletionStep3(txnId, docs, signedBytes, outName) {
        $('#step3Card').style.display = '';
        $('#completedDetails').innerHTML =
            `<div class="chips" style="margin-bottom:8px">${chip('COMPLETED', 'ok')} ${chip(docs.length + ' doc(s) signed')}</div>
             <p style="font-size:.92rem">The CMS signature has been embedded. Click to download.</p>`;

        const downloadBtn = $('#downloadPdfBtn');
        /* Clone to remove old listeners */
        const newBtn = downloadBtn.cloneNode(true);
        downloadBtn.parentNode.replaceChild(newBtn, downloadBtn);
        newBtn.addEventListener('click', () => {
            download(new Blob([signedBytes], { type: 'application/pdf' }), outName);
        });
        log('Download ready: ' + outName);
    }

    /* ─── crypto ─────────────────────────────────────────────────────── */

    async function sha256Base64(arrayBuffer) {
        const hashBuf = await crypto.subtle.digest('SHA-256', arrayBuffer);
        return arrayBufferToBase64(new Uint8Array(hashBuf));
    }

    function arrayBufferToBase64(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    }

    function base64ToUint8Array(b64) {
        if (!b64 || typeof b64 !== 'string') throw new Error('Invalid base64 input (not a string)');
        /* Normalise URL-safe base64 to standard base64 */
        let std = b64.replace(/-/g, '+').replace(/_/g, '/');
        while (std.length % 4) std += '=';
        const binary = atob(std);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }

    /* ─── XML building ───────────────────────────────────────────────── */

    function buildEsignXml(hashB64, txn) {
        const ts       = istTimestamp();
        const aspId    = $('#aspId').value.trim() || 'ASP001';
        const signerId = $('#signerId').value.trim() || 'demosigner';
        const algo     = $('#signingAlgorithm').value;
        const docInfo  = $('#docInfo').value.trim() || 'SignedByDemo.pdf';

        return '<Esign ver="3.3" signerid="' + escA(signerId)
            + '" ts="' + ts
            + '" txn="' + txn
            + '" maxWaitPeriod="300000" aspId="' + escA(aspId)
            + '" responseUrl="http://localhost:8080/esign/dev/callback'
            + '" redirectUrl="http://localhost:8080/sign.html?lookup=' + txn
            + '" signingAlgorithm="' + algo + '">'
            + '<Docs><InputHash id="1" hashAlgorithm="SHA256" docInfo="' + escA(docInfo)
            + '" docUrl="local://browser" responseSigType="pkcs7">' + hashB64
            + '</InputHash></Docs>'
            + '<Signature>DEV_MODE</Signature></Esign>';
    }

    function buildStatusXml(txnId) {
        return '<EsignStatus ver="3.3" ts="' + istTimestamp()
            + '" txn="' + txnId
            + '" aspId="' + ($('#aspId').value.trim() || 'ASP001')
            + '"></EsignStatus>';
    }

    function escA(s) {
        return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                .replace(/"/g,'&quot;').replace(/'/g,'&apos;');
    }

    function extractAttr(xml, name) {
        const m = xml.match(new RegExp(name + '="([^"]*)"'));
        return m ? m[1] : '';
    }

    /* ─── PDF signing ────────────────────────────────────────────────── */

    const HEX_PLACEHOLDER = '0'.repeat(CMS_RESERVED_BYTES * 2);

    function bytesToLatin1(bytes) {
        const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        let s = '';
        for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
        return s;
    }

    /* Build the placeholder signature and ByteRange. pdf-lib re-serializes the entire
       document for the ByteRange so xref/trailer offsets always match the final file
       layout (no post-hoc byte shifting that would corrupt the object table). */
    async function preparePdfForSigning(pdfBytes, signingTime) {
        const { PDFDocument, PDFName, PDFString, PDFNumber, PDFHexString } = PDFLib;

        async function buildPdf(br) {
            const pdfDoc = await PDFDocument.load(pdfBytes, { ignoreEncryption: true });
            const pages  = pdfDoc.getPages();
            const page   = pages[pages.length - 1];

            const sigDict = pdfDoc.context.obj({});
            sigDict.set(PDFName.of('Type'),      PDFName.of('Sig'));
            sigDict.set(PDFName.of('Filter'),    PDFName.of('Adobe.PPKLite'));
            sigDict.set(PDFName.of('SubFilter'), PDFName.of('adbe.pkcs7.detached'));
            sigDict.set(PDFName.of('M'),         PDFString.of(signingTime || new Date().toISOString()));
            sigDict.set(PDFName.of('ByteRange'), pdfDoc.context.obj(
                br ? br.map(n => PDFNumber.of(n))
                   : [PDFNumber.of(0), PDFNumber.of(0), PDFNumber.of(0), PDFNumber.of(0)]
            ));
            sigDict.set(PDFName.of('Contents'),  PDFHexString.of(HEX_PLACEHOLDER));

            const sigRef = pdfDoc.context.register(sigDict);

            const sigFieldDict = pdfDoc.context.obj({});
            sigFieldDict.set(PDFName.of('Type'),    PDFName.of('Annot'));
            sigFieldDict.set(PDFName.of('Subtype'), PDFName.of('Widget'));
            sigFieldDict.set(PDFName.of('FT'),      PDFName.of('Sig'));
            sigFieldDict.set(PDFName.of('V'),       sigRef);
            sigFieldDict.set(PDFName.of('T'),       PDFString.of('Signature1'));
            sigFieldDict.set(PDFName.of('F'),       PDFNumber.of(132));
            sigFieldDict.set(PDFName.of('Rect'),    pdfDoc.context.obj([
                PDFNumber.of(0), PDFNumber.of(0), PDFNumber.of(0), PDFNumber.of(0)
            ]));

            const sigAnnotRef = pdfDoc.context.register(sigFieldDict);

            const acroForm = pdfDoc.catalog.get(PDFName.of('AcroForm'));
            if (acroForm) {
                const fields = acroForm.get(PDFName.of('Fields'));
                if (fields) fields.push(sigAnnotRef);
                else acroForm.set(PDFName.of('Fields'), pdfDoc.context.obj([sigAnnotRef]));
                acroForm.set(PDFName.of('SigFlags'), PDFNumber.of(3));
            } else {
                const newAcroForm = pdfDoc.context.obj({});
                newAcroForm.set(PDFName.of('Fields'), pdfDoc.context.obj([sigAnnotRef]));
                newAcroForm.set(PDFName.of('SigFlags'), PDFNumber.of(3));
                pdfDoc.catalog.set(PDFName.of('AcroForm'), newAcroForm);
            }

            const pageAnnots = page.node.get(PDFName.of('Annots'));
            if (pageAnnots) pageAnnots.push(sigAnnotRef);
            else page.node.set(PDFName.of('Annots'), pdfDoc.context.obj([sigAnnotRef]));

            return await pdfDoc.save({ useObjectStreams: false });
        }

        const H = HEX_PLACEHOLDER.length;

        /* Pass 1 — save with the zero ByteRange placeholder to learn where the
           reserved Contents hex lands. */
        const bytes1 = await buildPdf(null);
        const s1 = bytesToLatin1(bytes1);
        const hexIdx = s1.indexOf(HEX_PLACEHOLDER);
        if (hexIdx < 0) {
            throw new Error('PDF signature placeholder not found in pass-1 output');
        }

        /* Solve dd: real ByteRange numbers are longer than the four 1-digit zeros.
           pdf-lib formats arrays as '[ 0 N1 N2 N3 ]', so the delta over the
           placeholder text is (1 + len(N1) + len(N2) + len(N3)) - 4. */
        let dd = 0;
        for (let i = 0; i < 10; i++) {
            const N1 = hexIdx + dd;
            const N2 = N1 + H;
            const N3 = bytes1.length + dd - N1 - H;
            const digitLen = [N1, N2, N3].map(n => String(n).length);
            const candidate = 1 + digitLen[0] + digitLen[1] + digitLen[2] - 4;
            if (candidate === dd) break;
            dd = candidate;
        }

        const N1 = hexIdx + dd;
        const N2 = N1 + H;
        const N3 = bytes1.length + dd - N1 - H;

        /* Pass 2 — let pdf-lib write the final ByteRange, keeping the whole file
           (xref, trailer, startxref) internally consistent. */
        const bytes2 = await buildPdf([0, N1, N2, N3]);
        const s2 = bytesToLatin1(bytes2);
        const hexIdx2 = s2.indexOf(HEX_PLACEHOLDER);
        if (hexIdx2 !== N1) {
            throw new Error('ByteRange misprediction: contents at ' + hexIdx2 + ', expected ' + N1);
        }
        if (bytes2.length !== bytes1.length + dd) {
            throw new Error('ByteRange length mismatch: ' + bytes2.length
                + ' != ' + (bytes1.length + dd));
        }

        /* Contents are excluded from the signed range; the caller hashes everything else. */
        const cover = new Uint8Array(bytes2.length - H);
        cover.set(bytes2.subarray(0, N1), 0);
        cover.set(bytes2.subarray(N2), N1);

        return { bytes: bytes2, coverBytes: cover, byteRange: [0, N1, N2, bytes2.length] };
    }

    /* Pass 2 — swap the reserved zero-filled Contents hex for the real padded CMS.
       Length is unchanged, so all ByteRange offsets from pass 1 stay valid. */
    function embedCmsIntoPrepared(preparedBytes, cmsB64) {
        const cmsBytes = base64ToUint8Array(cmsB64);
        if (cmsBytes.length > HEX_PLACEHOLDER.length / 2) {
            throw new Error('CMS too large for reserved signature space ('
                + cmsBytes.length + ' > ' + (HEX_PLACEHOLDER.length / 2) + ')');
        }
        const cmsHex = Array.from(cmsBytes)
            .map(b => b.toString(16).padStart(2, '0')).join('');
        const padded = cmsHex.padEnd(HEX_PLACEHOLDER.length, '0');

        const s = bytesToLatin1(preparedBytes);
        const idx = s.indexOf(HEX_PLACEHOLDER);
        if (idx < 0) throw new Error('Signature placeholder not found in prepared PDF');

        const out = new Uint8Array(s.length);
        const sFinal = s.slice(0, idx) + padded + s.slice(idx + HEX_PLACEHOLDER.length);
        for (let i = 0; i < sFinal.length; i++) out[i] = sFinal.charCodeAt(i);
        return out;
    }

    /* Deterministic convenience used by lookup / manual re-embed paths: recomputes the
       exact same placeholder layout (same input bytes → same serialization) then swaps
       in the CMS. Also yields a structurally valid (correct ByteRange) PDF for legacy
       transactions whose hash was computed over the un-signed original bytes. */
    async function embedCmsIntoPdf(pdfBytes, cmsB64, signingTime) {
        const prepared = await preparePdfForSigning(pdfBytes, signingTime);
        return embedCmsIntoPrepared(prepared.bytes, cmsB64);
    }

    /* ─── HTTP helpers ────────────────────────────────────────────────── */

    async function postText(url, body, contentType) {
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': contentType },
            body: body
        });
        return resp.text();
    }

    async function fetchJson(url) {
        const resp = await fetch(url);
        const text = await resp.text();
        let json = null;
        try { json = JSON.parse(text); } catch (e) { /* */ }
        return { httpStatus: resp.status, json, text };
    }

    function download(blob, name) {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = name;
        a.click();
        URL.revokeObjectURL(a.href);
    }

    function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

    /* ─── UI helpers ──────────────────────────────────────────────────── */

    function log(msg, isErr) {
        const line = document.createElement('div');
        line.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
        if (isErr) line.style.color = 'var(--red)';
        progressDiv.appendChild(line);
        progressDiv.scrollTop = progressDiv.scrollHeight;
    }

    function formatXml(xml) {
        try {
            const doc = new DOMParser().parseFromString(xml, 'application/xml');
            if (doc.querySelector('parsererror')) return xml;
            return new XMLSerializer().serializeToString(doc)
                .replace(/(>)(<)(?!\/)/g, '$1\n$2');
        } catch { return xml; }
    }

    /* ─── boot: handle URL params from auth redirect ─────────────────── */

    const pollTxn      = urlParams.get('poll');
    const completedTxn = urlParams.get('completed');
    const lookupTxn    = urlParams.get('lookup');

    if (completedTxn) {
        log('Returned from auth — embedding signature…');
        setTimeout(async () => {
            try {
                const detail = await fetchJson('/esign/dev/transactions/' + completedTxn);
                if (detail.json && detail.json.status === 'COMPLETED') {
                    const docs = detail.json.documents || [];
                    const signedDoc = docs.find(d => d.signatureValue);
                    if (!signedDoc) { log('No signature found'); return; }

                    /* Try the in-memory prepared PDF first */
                    if (preparedPdf && preparedPdf.bytes) {
                        const signedBytes = embedCmsIntoPrepared(preparedPdf.bytes, signedDoc.signatureValue);
                        showCompletionStep3(completedTxn, docs, signedBytes, fileName);
                        return;
                    }

                    /* Try localStorage (stores the prepared buffer) */
                    const stored = loadPdfFromStorage(completedTxn);
                    if (stored) {
                        const signedBytes = embedCmsIntoPrepared(stored.bytes, signedDoc.signatureValue);
                        showCompletionStep3(completedTxn, docs, signedBytes, stored.name);
                        clearPdfStorage(completedTxn);
                        return;
                    }

                    /* Legacy fallback: re-prepare deterministically from the original upload */
                    if (originalPdfBytes) {
                        const signedBytes = await embedCmsIntoPdf(originalPdfBytes, signedDoc.signatureValue, signedDoc.signedAt);
                        showCompletionStep3(completedTxn, docs, signedBytes, fileName);
                        return;
                    }

                    /* Fallback: show lookup */
                    log('PDF not found — select it below');
                    lookupInput.value = completedTxn;
                    lookupTransaction();
                } else {
                    log('Still pending — polling…');
                    await pollForCompletion(completedTxn);
                }
            } catch (e) {
                log('Error: ' + e.message, true);
            }
        }, 500);
    } else if (pollTxn) {
        log('Polling transaction ' + pollTxn + '…');
        setTimeout(() => pollForCompletion(pollTxn), 500);
    } else if (lookupTxn) {
        lookupInput.value = lookupTxn;
        lookupTransaction();
    }
})();
