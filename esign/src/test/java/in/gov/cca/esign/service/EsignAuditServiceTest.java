package in.gov.cca.esign.service;

import in.gov.cca.esign.domain.EsignAuditLog;
import in.gov.cca.esign.repository.EsignAuditLogRepository;
import in.gov.cca.esign.service.impl.EsignAuditServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EsignAuditServiceTest {

    private static final String REQUEST_XML = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <EsignRequest ver="3.3" txn="TXN-1" aspId="ASP001" signerid="demosigner" ts="2026-08-24T10:00:00+05:30" \
            maxWaitPeriod="120000"><Docs hashAlgorithm="SHA256">\
            <InputHash id="1" hashAlgorithm="SHA256" docInfo="A.pdf" docUrl="https://a" responseSigType="raw">abc\
            </InputHash><InputHash id="2" hashAlgorithm="SHA256" docInfo="B.pdf" docUrl="https://b" \
            responseSigType="raw">def</InputHash></Docs></EsignRequest>
            """;

    @Mock
    private EsignAuditLogRepository auditLogRepository;

    private EsignAuditServiceImpl auditService;

    @BeforeEach
    void setUp() {
        auditService = new EsignAuditServiceImpl(auditLogRepository);
    }

    @Test
    void pendingSignRequestIsCapturedWithAttributes() {
        String responseXml = "<EsignResp ver=\"3.3\" status=\"2\" txn=\"TXN-1\" resCode=\"RESP_1\"/>";

        auditService.record(EsignAuditLog.RequestType.SIGN, REQUEST_XML, responseXml, 202, "10.0.0.9");

        ArgumentCaptor<EsignAuditLog> captor = ArgumentCaptor.forClass(EsignAuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        EsignAuditLog saved = captor.getValue();

        assertThat(saved.getEndpoint()).isEqualTo(EsignAuditLog.RequestType.SIGN);
        assertThat(saved.getTransactionId()).isEqualTo("TXN-1");
        assertThat(saved.getAspId()).isEqualTo("ASP001");
        assertThat(saved.getSignerId()).isEqualTo("demosigner");
        assertThat(saved.getRemoteIp()).isEqualTo("10.0.0.9");
        assertThat(saved.getOutcome()).isEqualTo(EsignAuditLog.Outcome.PENDING);
        assertThat(saved.getHttpStatus()).isEqualTo(202);
        assertThat(saved.getDocumentCount()).isEqualTo(2);
        assertThat(saved.getRequestBytes()).isPositive();
        assertThat(saved.getRequestXml()).contains("TXN-1");
        assertThat(saved.getResponseSnippet()).contains("RESP_1");
        assertThat(saved.getErrorCode()).isNull();
    }

    @Test
    void rejectedResponseMapsToRejectedOutcomeWithErrorCode() {
        String responseXml = "<EsignResp ver=\"3.3\" status=\"0\" txn=\"TXN-2\" resCode=\"R\" error=\"112\"/>";

        auditService.record(EsignAuditLog.RequestType.SIGN, "<EsignRequest txn=\"TXN-2\"/>",
                responseXml, 200, "127.0.0.1");

        ArgumentCaptor<EsignAuditLog> captor = ArgumentCaptor.forClass(EsignAuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        assertThat(captor.getValue().getOutcome()).isEqualTo(EsignAuditLog.Outcome.REJECTED);
        assertThat(captor.getValue().getErrorCode()).isEqualTo("112");
    }

    @Test
    void malformedPayloadStillLoggedWithErrorOutcome() {
        String garbage = "this is not xml at all";

        auditService.record(EsignAuditLog.RequestType.STATUS, garbage, "", 400, "127.0.0.1");

        ArgumentCaptor<EsignAuditLog> captor = ArgumentCaptor.forClass(EsignAuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        EsignAuditLog saved = captor.getValue();
        assertThat(saved.getTransactionId()).isEmpty();
        assertThat(saved.getOutcome()).isEqualTo(EsignAuditLog.Outcome.ERROR);
        assertThat(saved.getRequestBytes()).isEqualTo(garbage.length());
    }

    @Test
    void successResponseWithoutStatusAttrDefaultsToSuccess() {
        auditService.record(EsignAuditLog.RequestType.AUTH_CALLBACK,
                "txnref=QUJD", "Authentication completed", 200, "192.168.1.5");

        ArgumentCaptor<EsignAuditLog> captor = ArgumentCaptor.forClass(EsignAuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        assertThat(captor.getValue().getOutcome()).isEqualTo(EsignAuditLog.Outcome.SUCCESS);
        assertThat(captor.getValue().getEndpoint()).isEqualTo(EsignAuditLog.RequestType.AUTH_CALLBACK);
    }

    @Test
    void repositoryFailureNeverPropagates() {
        when(auditLogRepository.save(any())).thenThrow(new RuntimeException("db down"));

        auditService.record(EsignAuditLog.RequestType.SIGN, REQUEST_XML,
                "<EsignResp status=\"1\"/>", 200, "127.0.0.1");

        // no exception thrown — audit must not break the eSign flow
    }
}
