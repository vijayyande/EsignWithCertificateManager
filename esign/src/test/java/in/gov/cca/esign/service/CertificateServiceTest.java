package in.gov.cca.esign.service;

import in.gov.cca.esign.model.CertificateEnrollmentRequest;
import in.gov.cca.esign.service.impl.CertificateServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateServiceTest {

    @Mock
    private RestTemplate caRestTemplate;

    @org.mockito.Captor
    private org.mockito.ArgumentCaptor<HttpEntity<CertificateEnrollmentRequest>> httpEntityCaptor;

    private CertificateServiceImpl certificateService;

    @BeforeEach
    void setUp() {
        certificateService = new CertificateServiceImpl(caRestTemplate);
        ReflectionTestUtils.setField(certificateService, "enabled", true);
        ReflectionTestUtils.setField(certificateService, "baseUrl", "http://localhost:8443/");
        ReflectionTestUtils.setField(certificateService, "enrollPath", "api/certificates/request");
        ReflectionTestUtils.setField(certificateService, "authType", "api-key");
        ReflectionTestUtils.setField(certificateService, "username", "");
        ReflectionTestUtils.setField(certificateService, "password", "");
        ReflectionTestUtils.setField(certificateService, "apiKeyHeader", "X-API-Key");
        ReflectionTestUtils.setField(certificateService, "apiKey", "secret-key");
    }

    private CertificateEnrollmentRequest sampleRequest() {
        return new CertificateEnrollmentRequest(
                "ESP Signer", "CCA Demo", "eSign", "IN", "Karnataka", "Bengaluru",
                "esp@example.gov.in", "RSA", 2048, 365, null,
                List.of("esign.example.gov.in"), List.of("10.0.0.1"),
                1L, "esp-admin", 5L,
                List.of(new CertificateEnrollmentRequest.AdditionalExtension("2.5.29.17", "SAN", "dns:extra.example")),
                "SIGNER-001", "ASP-001", "TXN-123", "abc123hash",
                "AadhaarSigning.pdf", "RSA");
    }

    @Test
    void disabledCaReturns503WithoutCallingEndpoint() {
        ReflectionTestUtils.setField(certificateService, "enabled", false);

        ResponseEntity<Map<String, Object>> out = certificateService.requestCertificate(sampleRequest());

        assertThat(out.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(out.getBody()).containsEntry("error", "CA integration is disabled — set ca.enabled=true (env CA_ENABLED) to enable");
        verify(caRestTemplate, never()).postForEntity(anyString(), any(HttpEntity.class), eq(Map.class));
    }

    @Test
    void blankCommonNameReturns400() {
        CertificateEnrollmentRequest bad = new CertificateEnrollmentRequest(null, null, null, null,
                null, null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null);

        ResponseEntity<Map<String, Object>> out = certificateService.requestCertificate(bad);

        assertThat(out.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(out.getBody()).containsEntry("error", "commonName is required");
    }

    @Test
    void forwardsToConfiguredEndpointWithApiKeyAndPassesThroughBody() {
        Map<String, Object> caBody = Map.of("certificateId", 42, "certificatePEM", "-----BEGIN CERTIFICATE-----");
        when(caRestTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(new ResponseEntity<>(caBody, HttpStatus.CREATED));

        ResponseEntity<Map<String, Object>> out = certificateService.requestCertificate(sampleRequest());

        assertThat(out.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(out.getBody()).containsEntry("certificateId", 42);

        verify(caRestTemplate).postForEntity(
                eq("http://localhost:8443/api/certificates/request"),
                httpEntityCaptor.capture(),
                eq(Map.class));
        HttpEntity<CertificateEnrollmentRequest> sent = httpEntityCaptor.getValue();
        assertThat(sent.getHeaders().getFirst("X-API-Key")).isEqualTo("secret-key");
        assertThat(sent.getHeaders().getContentType()).isEqualTo(org.springframework.http.MediaType.APPLICATION_JSON);
        assertThat(sent.getBody().commonName()).isEqualTo("ESP Signer");
        assertThat(sent.getBody().issuerCaId()).isEqualTo(1L);
    }

    @Test
    void basicAuthTypeSendsAuthorizationHeader() {
        ReflectionTestUtils.setField(certificateService, "authType", "basic");
        ReflectionTestUtils.setField(certificateService, "username", "ca-admin");
        ReflectionTestUtils.setField(certificateService, "password", "s3cret");
        when(caRestTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(new ResponseEntity<>(Map.of("id", 1), HttpStatus.OK));

        certificateService.requestCertificate(sampleRequest());

        verify(caRestTemplate).postForEntity(
                eq("http://localhost:8443/api/certificates/request"),
                httpEntityCaptor.capture(),
                eq(Map.class));
        String auth = httpEntityCaptor.getValue().getHeaders().getFirst("Authorization");
        assertThat(auth).startsWith("Basic ");
        String decoded = new String(java.util.Base64.getDecoder().decode(auth.substring(6)));
        assertThat(decoded).isEqualTo("ca-admin:s3cret");
    }

    @Test
    void noneAuthTypeSendsNoCredentials() {
        ReflectionTestUtils.setField(certificateService, "authType", "none");
        when(caRestTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(new ResponseEntity<>(Map.of(), HttpStatus.OK));

        certificateService.requestCertificate(sampleRequest());

        verify(caRestTemplate).postForEntity(anyString(), httpEntityCaptor.capture(), eq(Map.class));
        HttpEntity<CertificateEnrollmentRequest> sent = httpEntityCaptor.getValue();
        assertThat(sent.getHeaders().getFirst("Authorization")).isNull();
        assertThat(sent.getHeaders().get("X-API-Key")).isNull();
    }

    @Test
    void caClientErrorIsPassedThroughWithParsedBody() {
        String body = "{\"errorMessage\":\"Profile not found\"}";
        when(caRestTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(Map.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.BAD_REQUEST, "Bad Request",
                        org.springframework.http.HttpHeaders.EMPTY, body.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8));

        ResponseEntity<Map<String, Object>> out = certificateService.requestCertificate(sampleRequest());

        assertThat(out.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(out.getBody()).containsEntry("errorMessage", "Profile not found");
        assertThat(out.getBody()).containsEntry("httpStatus", 400);
    }

    @Test
    void unreachableCaReturns502() {
        when(caRestTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(Map.class)))
                .thenThrow(new ResourceAccessException("connect timed out"));

        ResponseEntity<Map<String, Object>> out = certificateService.requestCertificate(sampleRequest());

        assertThat(out.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(String.valueOf(out.getBody().get("error"))).contains("unreachable");
    }

    @Test
    void settingsSummaryMasksSecretsButShowsEndpoint() {
        Map<String, Object> summary = certificateService.settingsSummary();

        assertThat(summary).containsEntry("enabled", true);
        assertThat(summary).containsEntry("endpoint", "http://localhost:8443/api/certificates/request");
        assertThat(summary).containsEntry("authType", "api-key");
        assertThat(summary).containsEntry("apiKeyHeader", "X-API-Key");
        assertThat(summary).containsEntry("apiKeyConfigured", true);
        assertThat(summary.toString()).doesNotContain("secret-key");

        ReflectionTestUtils.setField(certificateService, "authType", "basic");
        ReflectionTestUtils.setField(certificateService, "username", "ca-admin");
        ReflectionTestUtils.setField(certificateService, "password", "s3cret");
        Map<String, Object> basicSummary = certificateService.settingsSummary();
        assertThat(basicSummary).containsEntry("username", "ca-admin");
        assertThat(basicSummary).containsEntry("passwordConfigured", true);
        assertThat(basicSummary.toString()).doesNotContain("s3cret");
    }
}
