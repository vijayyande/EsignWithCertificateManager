package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.domain.Asp;
import in.gov.cca.esign.domain.DocumentSignature;
import in.gov.cca.esign.domain.EsignTransaction;
import in.gov.cca.esign.model.enums.EsignErrorCode;
import in.gov.cca.esign.model.enums.EsignStatus;
import in.gov.cca.esign.model.enums.ResponseSignatureType;
import in.gov.cca.esign.model.enums.SigningAlgorithm;
import in.gov.cca.esign.model.xml.esign.EsignRequest;
import in.gov.cca.esign.model.xml.esign.EsignResponse;
import in.gov.cca.esign.model.xml.esign.EsignStatusRequest;
import in.gov.cca.esign.repository.AspRepository;
import in.gov.cca.esign.repository.EsignTransactionRepository;
import in.gov.cca.esign.service.EKycService;
import in.gov.cca.esign.service.EsignService;
import in.gov.cca.esign.service.EsignSigningService;
import in.gov.cca.esign.service.HsmService;
import in.gov.cca.esign.service.XmlSignatureService;
import in.gov.cca.esign.util.XmlUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EsignServiceImpl implements EsignService {

    private static final DateTimeFormatter IST_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
    private static final ZoneId IST = ZoneId.of("Asia/Kolkata");

    private final EsignTransactionRepository transactionRepository;
    private final AspRepository aspRepository;
    private final XmlSignatureService xmlSignatureService;
    private final HsmService hsmService;
    private final EKycService ekycService;
    private final XmlUtils xmlUtils;
    private final RestTemplate restTemplate;
    private final EsignSigningService esignSigningService;

    @Value("${esign.version:3.3}")
    private String esignVersion;

    @Value("${esign.esp-id:ESP001}")
    private String espId;

    @Value("${esign.max-documents:5}")
    private int maxDocuments;

    @Value("${esign.timestamp-tolerance-minutes:30}")
    private int timestampToleranceMinutes;

    @Value("${esign.signature-verification.enabled:true}")
    private boolean signatureVerificationEnabled;

    @Value("${esign.callback.retry-attempts:3}")
    private int callbackRetryAttempts;

    @Value("${esign.callback.retry-delay:5000}")
    private int callbackRetryDelay;

    @Value("${esign.asp-registry.validation-enabled:false}")
    private boolean aspRegistryValidationEnabled;

    @Override
    @Transactional
    public EsignResponse processEsignRequest(EsignRequest request, String requestXml, String aspSignature) {
        log.info("Processing eSign request txn: {} asp: {}", request.getTransactionId(), request.getAspId());

        EsignErrorCode validationError = validateEsignRequest(request);
        if (validationError != null) {
            return buildErrorResponse(request.getTransactionId(), validationError);
        }

        if (signatureVerificationEnabled && !xmlSignatureService.verifySignature(requestXml, aspSignature)) {
            log.warn("ASP signature verification failed txn: {}", request.getTransactionId());
            return buildErrorResponse(request.getTransactionId(), EsignErrorCode.INVALID_DIGITAL_SIGNATURE);
        }

        if (transactionRepository.findByTransactionId(request.getTransactionId()).isPresent()) {
            log.warn("Duplicate transaction ID: {}", request.getTransactionId());
            return buildErrorResponse(request.getTransactionId(), EsignErrorCode.DUPLICATE_TRANSACTION_ID);
        }

        if (!isValidTimestamp(request.getTimestamp())) {
            return buildErrorResponse(request.getTransactionId(), EsignErrorCode.INVALID_TIMESTAMP);
        }

        String responseCode = generateResponseCode();
        EsignTransaction transaction = createTransactionRecord(request, requestXml, responseCode);

        try {
            initiateAuthentication(transaction);
        } catch (Exception e) {
            log.error("Failed to initiate authentication txn: {}", request.getTransactionId(), e);
            transaction.setStatus(EsignTransaction.TransactionStatus.FAILED);
            transaction.setErrorCode(EsignErrorCode.UNKNOWN_ERROR.getCode());
            transaction.setErrorMessage(e.getMessage());
            transactionRepository.save(transaction);
            return buildErrorResponse(request.getTransactionId(), EsignErrorCode.UNKNOWN_ERROR, responseCode);
        }

        transactionRepository.save(transaction);
        return buildPendingResponse(request.getTransactionId(), responseCode);
    }

    @Override
    @Transactional
    public EsignResponse checkSigningStatus(EsignStatusRequest request, String requestXml, String aspSignature) {
        log.info("Checking signing status txn: {}", request.getTransactionId());

        if (signatureVerificationEnabled && !xmlSignatureService.verifySignature(requestXml, aspSignature)) {
            return buildErrorResponse(request.getTransactionId(), EsignErrorCode.STATUS_INVALID_REQUEST_FORMAT);
        }

        if (!esignVersion.equals(request.getVersion())) {
            return buildErrorResponse(request.getTransactionId(), EsignErrorCode.STATUS_INVALID_VERSION);
        }

        if (aspRegistryValidationEnabled && !isAspAllowed(request.getAspId())) {
            return buildErrorResponse(request.getTransactionId(), EsignErrorCode.STATUS_UNKNOWN_ERROR,
                    "ASP not registered or not active: " + request.getAspId());
        }

        EsignTransaction transaction = transactionRepository
                .findByTransactionId(request.getTransactionId())
                .orElse(null);

        if (transaction == null) {
            return buildErrorResponse(request.getTransactionId(),
                    EsignErrorCode.STATUS_TRANSACTION_NOT_FOUND);
        }

        return buildTransactionResponse(transaction);
    }

    @Override
    @Transactional(readOnly = true)
    public EsignResponse getTransactionResponse(String transactionId) {
        EsignTransaction transaction = transactionRepository.findByTransactionId(transactionId)
                .orElseThrow(() -> new IllegalArgumentException("Transaction not found: " + transactionId));
        return buildTransactionResponse(transaction);
    }

    @Override
    @Transactional(readOnly = true)
    public List<EsignTransaction> getTransactionsByAsp(String aspId) {
        return transactionRepository.findByAspIdAndStatus(aspId,
                EsignTransaction.TransactionStatus.COMPLETED);
    }

    @Override
    @Async
    public void callbackResponse(String responseUrl, EsignResponse response) {
        log.info("Sending callback to: {}", responseUrl);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_XML);
        HttpEntity<String> entity = new HttpEntity<>(xmlUtils.marshal(response), headers);

        for (int attempt = 1; attempt <= callbackRetryAttempts; attempt++) {
            try {
                ResponseEntity<String> unused = restTemplate.exchange(
                        responseUrl, HttpMethod.POST, entity, String.class);
                log.info("Callback delivered resCode: {}", response.getResponseCode());
                return;
            } catch (Exception e) {
                log.warn("Callback attempt {}/{} failed: {}",
                        attempt, callbackRetryAttempts, e.getMessage());
            }
            if (attempt < callbackRetryAttempts) {
                try {
                    Thread.sleep(callbackRetryDelay);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        log.error("All callback attempts failed resCode: {}", response.getResponseCode());
    }

    @Override
    @Transactional(readOnly = true)
    public EsignTransaction getTransaction(String transactionId) {
        return transactionRepository.findByTransactionId(transactionId)
                .orElseThrow(() -> new IllegalArgumentException("Transaction not found: " + transactionId));
    }

    @Override
    @Transactional
    public EsignResponse completeSigning(String transactionId, String signerId, Date signingTime) {
        EsignSigningService.SignResult result = esignSigningService.signTransaction(
                transactionId, signerId, signingTime);

        EsignTransaction txn = result.transaction();
        EsignResponse esignResponse = result.esignResponse();

        if (txn.getResponseUrl() != null && !txn.getResponseUrl().isBlank()) {
            callbackResponse(txn.getResponseUrl(), esignResponse);
        }

        return esignResponse;
    }

    private EsignErrorCode validateEsignRequest(EsignRequest request) {
        if (!esignVersion.equals(request.getVersion())) {
            return EsignErrorCode.INVALID_VERSION;
        }
        if (request.getAspId() == null || request.getAspId().isBlank()) {
            return EsignErrorCode.INVALID_ASP_ID;
        }
        if (!isAspAllowed(request.getAspId())) {
            return EsignErrorCode.INVALID_ASP_ID;
        }
        if (request.getResponseUrl() == null || request.getResponseUrl().isBlank()) {
            return EsignErrorCode.INVALID_REQUEST_FORMAT;
        }
        if (request.getMaxWaitPeriod() == null || request.getMaxWaitPeriod() <= 0) {
            return EsignErrorCode.INVALID_MAX_WAIT_PERIOD;
        }
        try {
            SigningAlgorithm.fromValue(request.getSigningAlgorithm());
        } catch (IllegalArgumentException e) {
            return EsignErrorCode.INVALID_REQUEST_FORMAT;
        }

        List<EsignRequest.InputHash> docs =
                request.getDocs() == null ? null : request.getDocs().getInputHash();
        if (docs == null || docs.isEmpty()) {
            return EsignErrorCode.MINIMUM_ONE_DOCUMENT_REQUIRED;
        }
        if (docs.size() > maxDocuments) {
            return EsignErrorCode.REQUEST_EXCEEDS_MAX_DOCUMENTS;
        }

        for (int i = 0; i < docs.size(); i++) {
            EsignRequest.InputHash doc = docs.get(i);
            if (doc.getId() == null || doc.getId() != i + 1) {
                return EsignErrorCode.INVALID_DOCUMENT_HASH;
            }
            if (!"SHA256".equalsIgnoreCase(doc.getHashAlgorithm())) {
                return EsignErrorCode.INVALID_HASH_ALGORITHM;
            }
            if (doc.getDocInfo() == null || doc.getDocInfo().isBlank()
                    || doc.getDocInfo().length() > 50) {
                return EsignErrorCode.INVALID_DOCUMENT_INFO;
            }
            if (doc.getDocUrl() == null || doc.getDocUrl().isBlank()) {
                return EsignErrorCode.INVALID_DOCUMENT_URL;
            }
            try {
                ResponseSignatureType.fromValue(doc.getResponseSigType());
            } catch (IllegalArgumentException e) {
                return EsignErrorCode.INVALID_RESPONSE_SIGNATURE_TYPE;
            }
            if (doc.getHashValue() == null || doc.getHashValue().isBlank()) {
                return EsignErrorCode.INVALID_DOCUMENT_HASH;
            }
        }
        return null;
    }

    /**
     * When the ASP registry check is enabled, only registered ASPs in ACTIVE
     * status may submit requests or query statuses.
     */
    private boolean isAspAllowed(String aspId) {
        if (!aspRegistryValidationEnabled) {
            return true;
        }
        return aspRepository.findByAspId(aspId)
                .map(asp -> asp.getStatus() == Asp.AspStatus.ACTIVE)
                .orElse(false);
    }

    private boolean isValidTimestamp(String timestamp) {        try {
            ZonedDateTime requestTime = ZonedDateTime.parse(timestamp);
            ZonedDateTime now = ZonedDateTime.now(IST);
            long diffMinutes = java.time.Duration.between(requestTime, now).toMinutes();
            return Math.abs(diffMinutes) <= timestampToleranceMinutes;
        } catch (Exception e) {
            return false;
        }
    }

    private void initiateAuthentication(EsignTransaction transaction) {
        transaction.setStatus(EsignTransaction.TransactionStatus.IN_PROGRESS);
    }

    private EsignTransaction createTransactionRecord(EsignRequest request,
                                                     String requestXml,
                                                     String responseCode) {
        LocalDateTime ts;
        try {
            ts = ZonedDateTime.parse(request.getTimestamp()).toLocalDateTime();
        } catch (Exception e) {
            ts = LocalDateTime.now();
        }

        EsignTransaction transaction = EsignTransaction.builder()
                .transactionId(request.getTransactionId())
                .aspId(request.getAspId())
                .signerId(request.getSignerId())
                .version(request.getVersion())
                .timestamp(ts)
                .maxWaitPeriod(request.getMaxWaitPeriod())
                .responseUrl(request.getResponseUrl())
                .redirectUrl(request.getRedirectUrl())
                .signingAlgorithm(request.getSigningAlgorithm())
                .status(EsignTransaction.TransactionStatus.PENDING)
                .responseCode(responseCode)
                .requestXml(requestXml)
                .build();

        transaction.setDocumentSignatures(new java.util.ArrayList<>());
        for (EsignRequest.InputHash doc : request.getDocs().getInputHash()) {
            transaction.getDocumentSignatures().add(DocumentSignature.builder()
                    .transaction(transaction)
                    .documentId(doc.getId())
                    .hashAlgorithm(doc.getHashAlgorithm())
                    .docInfo(doc.getDocInfo())
                    .docUrl(doc.getDocUrl())
                    .responseSigType(doc.getResponseSigType())
                    .documentHash(doc.getHashValue())
                    .build());
        }
        return transaction;
    }

    private String generateResponseCode() {
        return "RESP_" + UUID.randomUUID().toString().replace("-", "")
                .substring(0, 24).toUpperCase();
    }

    private EsignResponse buildPendingResponse(String transactionId, String responseCode) {
        return EsignResponse.builder()
                .version(esignVersion)
                .status(EsignStatus.PENDING.getCode())
                .timestamp(now())
                .transactionId(transactionId)
                .responseCode(responseCode)
                .build();
    }

    private EsignResponse buildErrorResponse(String transactionId, EsignErrorCode errorCode) {
        return buildErrorResponse(transactionId, errorCode, generateResponseCode());
    }

    private EsignResponse buildErrorResponse(String transactionId, EsignErrorCode errorCode,
                                             String responseCode) {
        return EsignResponse.builder()
                .version(esignVersion)
                .status(EsignStatus.FAILURE.getCode())
                .timestamp(now())
                .transactionId(transactionId)
                .responseCode(responseCode)
                .error(errorCode.getCode())
                .build();
    }

    private EsignResponse buildTransactionResponse(EsignTransaction transaction) {
        EsignResponse.EsignResponseBuilder builder = EsignResponse.builder()
                .version(esignVersion)
                .timestamp(now())
                .transactionId(transaction.getTransactionId())
                .responseCode(transaction.getResponseCode());

        switch (transaction.getStatus()) {
            case COMPLETED -> builder
                    .status(EsignStatus.SUCCESS.getCode())
                    .userX509Certificate(transaction.getUserCertificate())
                    .signatures(buildSignatures(transaction))
                    .signature(transaction.getEspSignature());
            case FAILED, EXPIRED, CANCELLED -> builder
                    .status(EsignStatus.FAILURE.getCode())
                    .error(transaction.getErrorCode());
            default -> builder.status(EsignStatus.PENDING.getCode());
        }
        return builder.build();
    }

    private EsignResponse.Signatures buildSignatures(EsignTransaction transaction) {
        if (transaction.getDocumentSignatures() == null
                || transaction.getDocumentSignatures().isEmpty()) {
            return null;
        }
        List<EsignResponse.DocSignature> docSignatures =
                transaction.getDocumentSignatures().stream()
                        .map(doc -> EsignResponse.DocSignature.builder()
                                .id(doc.getDocumentId())
                                .sigHashAlgorithm(doc.getHashAlgorithm())
                                .signatureValue(doc.getSignatureValue())
                                .error(doc.getErrorCode())
                                .build())
                        .toList();
        return EsignResponse.Signatures.builder().docSignatures(docSignatures).build();
    }

    private String now() {
        return ZonedDateTime.now(IST).format(IST_FORMATTER);
    }
}