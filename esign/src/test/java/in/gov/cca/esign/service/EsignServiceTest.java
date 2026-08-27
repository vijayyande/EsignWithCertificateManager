package in.gov.cca.esign.service;

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
import in.gov.cca.esign.service.impl.EsignServiceImpl;
import in.gov.cca.esign.util.XmlUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EsignServiceTest {

    @Mock
    private EsignTransactionRepository transactionRepository;

    @Mock
    private XmlSignatureService xmlSignatureService;

    @Mock
    private HsmService hsmService;

    @Mock
    private EKycService ekycService;

    @Mock
    private XmlUtils xmlUtils;

    @Mock
    private AspRepository aspRepository;

    @Mock
    private EsignSigningService esignSigningService;

    private EsignServiceImpl esignService;

    @BeforeEach
    void setUp() {
        esignService = new EsignServiceImpl(
                transactionRepository,
                aspRepository,
                xmlSignatureService,
                hsmService,
                ekycService,
                xmlUtils,
                null, // restTemplate
                esignSigningService
        );

        ReflectionTestUtils.setField(esignService, "esignVersion", "3.3");
        ReflectionTestUtils.setField(esignService, "espId", "ESP001");
        ReflectionTestUtils.setField(esignService, "maxDocuments", 5);
        ReflectionTestUtils.setField(esignService, "timestampToleranceMinutes", 30);
        ReflectionTestUtils.setField(esignService, "signatureVerificationEnabled", true);
        ReflectionTestUtils.setField(esignService, "aspRegistryValidationEnabled", false);
        ReflectionTestUtils.setField(esignService, "callbackRetryAttempts", 3);
        ReflectionTestUtils.setField(esignService, "callbackRetryDelay", 5000);
    }

    @Test
    void processEsignRequest_ValidRequest_ReturnsPendingResponse() {
        // Given
        EsignRequest request = createValidEsignRequest();
        String requestXml = "<Esign>...</Esign>";
        String aspSignature = "valid-signature";

        when(xmlSignatureService.verifySignature(anyString(), anyString())).thenReturn(true);
        when(transactionRepository.findByTransactionId(request.getTransactionId())).thenReturn(Optional.empty());
        when(transactionRepository.save(any(EsignTransaction.class))).thenAnswer(inv -> inv.getArgument(0));

        // When
        EsignResponse response = esignService.processEsignRequest(request, requestXml, aspSignature);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(EsignStatus.PENDING.getCode());
        assertThat(response.getVersion()).isEqualTo("3.3");
        assertThat(response.getTransactionId()).isEqualTo(request.getTransactionId());
        assertThat(response.getResponseCode()).isNotNull();
        assertThat(response.getError()).isNull();

        verify(transactionRepository).save(any(EsignTransaction.class));
    }

    @Test
    void processEsignRequest_InvalidVersion_ReturnsError() {
        // Given
        EsignRequest request = createValidEsignRequest();
        request.setVersion("3.2");
        String requestXml = "<Esign>...</Esign>";
        String aspSignature = "valid-signature";

        // When
        EsignResponse response = esignService.processEsignRequest(request, requestXml, aspSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo(EsignStatus.FAILURE.getCode());
        assertThat(response.getError()).isEqualTo(EsignErrorCode.INVALID_VERSION.getCode());
    }

    @Test
    void processEsignRequest_InvalidSignature_ReturnsError() {
        // Given
        EsignRequest request = createValidEsignRequest();
        String requestXml = "<Esign>...</Esign>";
        String aspSignature = "invalid-signature";

        when(xmlSignatureService.verifySignature(anyString(), anyString())).thenReturn(false);

        // When
        EsignResponse response = esignService.processEsignRequest(request, requestXml, aspSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo(EsignStatus.FAILURE.getCode());
        assertThat(response.getError()).isEqualTo(EsignErrorCode.INVALID_DIGITAL_SIGNATURE.getCode());
    }

    @Test
    void processEsignRequest_DuplicateTransactionId_ReturnsError() {
        // Given
        EsignRequest request = createValidEsignRequest();
        String requestXml = "<Esign>...</Esign>";
        String aspSignature = "valid-signature";

        when(xmlSignatureService.verifySignature(anyString(), anyString())).thenReturn(true);
        when(transactionRepository.findByTransactionId(request.getTransactionId()))
                .thenReturn(Optional.of(new EsignTransaction()));

        // When
        EsignResponse response = esignService.processEsignRequest(request, requestXml, aspSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo(EsignStatus.FAILURE.getCode());
        assertThat(response.getError()).isEqualTo(EsignErrorCode.DUPLICATE_TRANSACTION_ID.getCode());
    }

    @Test
    void processEsignRequest_NoDocuments_ReturnsError() {
        // Given
        EsignRequest request = createValidEsignRequest();
        request.setDocs(new EsignRequest.Docs()); // Empty docs
        String requestXml = "<Esign>...</Esign>";
        String aspSignature = "valid-signature";

        // When - validation fails before signature verification is attempted
        EsignResponse response = esignService.processEsignRequest(request, requestXml, aspSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo(EsignStatus.FAILURE.getCode());
        assertThat(response.getError()).isEqualTo(EsignErrorCode.MINIMUM_ONE_DOCUMENT_REQUIRED.getCode());
    }

    @Test
    void processEsignRequest_TooManyDocuments_ReturnsError() {
        // Given
        EsignRequest request = createValidEsignRequest();
        // Add 6 documents (max is 5)
        List<EsignRequest.InputHash> docs = new java.util.ArrayList<>();
        for (int i = 0; i < 6; i++) {
            docs.add(createInputHash(i + 1));
        }
        request.getDocs().setInputHash(docs);
        String requestXml = "<Esign>...</Esign>";
        String aspSignature = "valid-signature";

        // When - validation fails before signature verification is attempted
        EsignResponse response = esignService.processEsignRequest(request, requestXml, aspSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo(EsignStatus.FAILURE.getCode());
        assertThat(response.getError()).isEqualTo(EsignErrorCode.REQUEST_EXCEEDS_MAX_DOCUMENTS.getCode());
    }

    @Test
    void checkSigningStatus_ValidRequest_ReturnsStatus() {
        // Given
        EsignStatusRequest request = createValidStatusRequest();
        String requestXml = "<EsignStatus>...</EsignStatus>";
        String aspSignature = "valid-signature";

        EsignTransaction transaction = createTransaction(EsignTransaction.TransactionStatus.COMPLETED);
        transaction.setResponseCode("RESP_123");
        transaction.setUserCertificate("cert-data");

        when(xmlSignatureService.verifySignature(anyString(), anyString())).thenReturn(true);
        when(transactionRepository.findByTransactionId(request.getTransactionId()))
                .thenReturn(Optional.of(transaction));

        // When
        EsignResponse response = esignService.checkSigningStatus(request, requestXml, aspSignature);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(EsignStatus.SUCCESS.getCode());
        assertThat(response.getTransactionId()).isEqualTo(request.getTransactionId());
        assertThat(response.getUserX509Certificate()).isEqualTo("cert-data");
    }

    @Test
    void checkSigningStatus_TransactionNotFound_ReturnsError() {
        // Given
        EsignStatusRequest request = createValidStatusRequest();
        String requestXml = "<EsignStatus>...</EsignStatus>";
        String aspSignature = "valid-signature";

        when(xmlSignatureService.verifySignature(anyString(), anyString())).thenReturn(true);
        when(transactionRepository.findByTransactionId(request.getTransactionId()))
                .thenReturn(Optional.empty());

        // When
        EsignResponse response = esignService.checkSigningStatus(request, requestXml, aspSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo(EsignStatus.FAILURE.getCode());
        assertThat(response.getError()).isEqualTo(EsignErrorCode.STATUS_TRANSACTION_NOT_FOUND.getCode());
    }

    @Test
    void checkSigningStatus_InvalidVersion_ReturnsError() {
        // Given
        EsignStatusRequest request = createValidStatusRequest();
        request.setVersion("3.2");
        String requestXml = "<EsignStatus>...</EsignStatus>";
        String aspSignature = "valid-signature";

        when(xmlSignatureService.verifySignature(anyString(), anyString())).thenReturn(true);

        // When
        EsignResponse response = esignService.checkSigningStatus(request, requestXml, aspSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo(EsignStatus.FAILURE.getCode());
        assertThat(response.getError()).isEqualTo(EsignErrorCode.STATUS_INVALID_VERSION.getCode());
    }

    // Helper methods

    private EsignRequest createValidEsignRequest() {
        EsignRequest request = new EsignRequest();
        request.setVersion("3.3");
        request.setSignerId("user123@username.ESP001");
        request.setTimestamp(getCurrentIstTimestamp());
        request.setTransactionId("TXN_123456");
        request.setMaxWaitPeriod(60);
        request.setAspId("ASP001");
        request.setResponseUrl("https://asp.example.com/callback");
        request.setRedirectUrl("https://asp.example.com/redirect");
        request.setSigningAlgorithm(SigningAlgorithm.RSA.getValue());

        EsignRequest.Docs docs = new EsignRequest.Docs();
        docs.setInputHash(List.of(createInputHash(1)));
        request.setDocs(docs);

        return request;
    }

    private EsignRequest.InputHash createInputHash(int id) {
        EsignRequest.InputHash inputHash = new EsignRequest.InputHash();
        inputHash.setId(id);
        inputHash.setHashAlgorithm("SHA256");
        inputHash.setDocInfo("Test Document " + id);
        inputHash.setDocUrl("https://example.com/doc" + id + ".pdf");
        inputHash.setResponseSigType(ResponseSignatureType.PKCS7.getValue());
        inputHash.setHashValue("a1b2c3d4e5f6" + id);
        return inputHash;
    }

    private EsignStatusRequest createValidStatusRequest() {
        EsignStatusRequest request = new EsignStatusRequest();
        request.setVersion("3.3");
        request.setTimestamp(getCurrentIstTimestamp());
        request.setTransactionId("TXN_123456");
        request.setAspId("ASP001");
        return request;
    }

    private EsignTransaction createTransaction(EsignTransaction.TransactionStatus status) {
        EsignTransaction transaction = new EsignTransaction();
        transaction.setId(java.util.UUID.randomUUID());
        transaction.setTransactionId("TXN_123456");
        transaction.setAspId("ASP001");
        transaction.setSignerId("user123@username.ESP001");
        transaction.setVersion("3.3");
        transaction.setTimestamp(LocalDateTime.now());
        transaction.setMaxWaitPeriod(60);
        transaction.setResponseUrl("https://asp.example.com/callback");
        transaction.setSigningAlgorithm("RSA");
        transaction.setStatus(status);
        transaction.setResponseCode("RESP_123");
        return transaction;
    }

    private String getCurrentIstTimestamp() {
        return ZonedDateTime.now(ZoneId.of("Asia/Kolkata"))
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX"));
    }
}