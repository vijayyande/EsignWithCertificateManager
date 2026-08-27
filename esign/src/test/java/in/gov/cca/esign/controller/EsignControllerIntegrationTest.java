package in.gov.cca.esign.controller;

import in.gov.cca.esign.EsignApplication;
import in.gov.cca.esign.model.xml.esign.EsignRequest;
import in.gov.cca.esign.model.xml.esign.EsignResponse;
import in.gov.cca.esign.model.xml.esign.EsignStatusRequest;
import in.gov.cca.esign.repository.EsignTransactionRepository;
import in.gov.cca.esign.util.XmlUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = EsignApplication.class)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class EsignControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private EsignTransactionRepository transactionRepository;

    @Autowired
    private XmlUtils xmlUtils;

    private static final DateTimeFormatter IST_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");

    @Test
    void esignRequest_ValidRequest_ReturnsPendingResponse() throws Exception {
        // Given
        EsignRequest request = createValidEsignRequest();
        String requestXml = xmlUtils.marshal(request);

        // When
        MvcResult result = mockMvc.perform(post("/esign/request")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isAccepted())
                .andExpect(content().contentType(MediaType.APPLICATION_XML))
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EsignResponse response = xmlUtils.unmarshal(responseXml, EsignResponse.class);

        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo("2"); // Pending
        assertThat(response.getVersion()).isEqualTo("3.3");
        assertThat(response.getTransactionId()).isEqualTo(request.getTransactionId());
        assertThat(response.getResponseCode()).isNotNull();
        assertThat(response.getError()).isNull();

        // Verify transaction persisted
        assertThat(transactionRepository.findByTransactionId(request.getTransactionId())).isPresent();
    }

    @Test
    void esignRequest_InvalidVersion_ReturnsError() throws Exception {
        // Given
        EsignRequest request = createValidEsignRequest();
        request.setVersion("3.2");
        String requestXml = xmlUtils.marshal(request);

        // When - business failures are returned as HTTP 200 with error status in the body
        MvcResult result = mockMvc.perform(post("/esign/request")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isOk())
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EsignResponse response = xmlUtils.unmarshal(responseXml, EsignResponse.class);

        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).isEqualTo("103"); // INVALID_VERSION
    }

    @Test
    void esignRequest_NoDocuments_ReturnsError() throws Exception {
        // Given
        EsignRequest request = createValidEsignRequest();
        request.setDocs(new EsignRequest.Docs()); // Empty
        String requestXml = xmlUtils.marshal(request);

        // When - business failures are returned as HTTP 200 with error status in the body
        MvcResult result = mockMvc.perform(post("/esign/request")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isOk())
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EsignResponse response = xmlUtils.unmarshal(responseXml, EsignResponse.class);

        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).isEqualTo("108"); // MINIMUM_ONE_DOCUMENT_REQUIRED
    }

    @Test
    void esignRequest_TooManyDocuments_ReturnsError() throws Exception {
        // Given
        EsignRequest request = createValidEsignRequest();
        // Add 6 documents (max 5)
        List<EsignRequest.InputHash> docs = new java.util.ArrayList<>();
        for (int i = 0; i < 6; i++) {
            docs.add(createInputHash(i + 1));
        }
        request.getDocs().setInputHash(docs);
        String requestXml = xmlUtils.marshal(request);

        // When - business failures are returned as HTTP 200 with error status in the body
        MvcResult result = mockMvc.perform(post("/esign/request")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isOk())
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EsignResponse response = xmlUtils.unmarshal(responseXml, EsignResponse.class);

        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).isEqualTo("109"); // REQUEST_EXCEEDS_MAX_DOCUMENTS
    }

    @Test
    void checkStatus_ValidRequest_ReturnsStatus() throws Exception {
        // Given - create a transaction first
        EsignRequest request = createValidEsignRequest();
        String requestXml = xmlUtils.marshal(request);

        mockMvc.perform(post("/esign/request")
                .contentType(MediaType.APPLICATION_XML)
                .content(requestXml))
                .andExpect(status().isAccepted());

        // When - check status
        EsignStatusRequest statusRequest = createValidStatusRequest(request.getTransactionId());
        String statusXml = xmlUtils.marshal(statusRequest);

        MvcResult result = mockMvc.perform(post("/esign/status")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(statusXml))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_XML))
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EsignResponse response = xmlUtils.unmarshal(responseXml, EsignResponse.class);

        assertThat(response).isNotNull();
        assertThat(response.getTransactionId()).isEqualTo(request.getTransactionId());
        assertThat(response.getStatus()).isEqualTo("2"); // Still pending
    }

    @Test
    void checkStatus_TransactionNotFound_ReturnsError() throws Exception {
        // Given
        EsignStatusRequest statusRequest = createValidStatusRequest("NONEXISTENT_TXN");
        String statusXml = xmlUtils.marshal(statusRequest);

        // When - business failures are returned as HTTP 200 with error status in the body
        MvcResult result = mockMvc.perform(post("/esign/status")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(statusXml))
                .andExpect(status().isOk())
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EsignResponse response = xmlUtils.unmarshal(responseXml, EsignResponse.class);

        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).isEqualTo("302"); // STATUS_TRANSACTION_NOT_FOUND
    }

    @Test
    void esignRequest_InvalidTimestamp_ReturnsError() throws Exception {
        // Given
        EsignRequest request = createValidEsignRequest();
        // Set timestamp to 1 hour ago (outside 30 min tolerance)
        request.setTimestamp(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")).minusHours(1).format(IST_FORMATTER));
        String requestXml = xmlUtils.marshal(request);

        // When - business failures are returned as HTTP 200 with error status in the body
        MvcResult result = mockMvc.perform(post("/esign/request")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isOk())
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EsignResponse response = xmlUtils.unmarshal(responseXml, EsignResponse.class);

        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).isEqualTo("110"); // INVALID_TIMESTAMP
    }

    // Helper methods

    private EsignRequest createValidEsignRequest() {
        EsignRequest request = new EsignRequest();
        request.setVersion("3.3");
        request.setSignerId("user123@username.ESP001");
        request.setTimestamp(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")).format(IST_FORMATTER));
        request.setTransactionId("TXN_" + System.currentTimeMillis());
        request.setMaxWaitPeriod(60);
        request.setAspId("ASP001");
        request.setResponseUrl("https://asp.example.com/callback");
        request.setRedirectUrl("https://asp.example.com/redirect");
        request.setSigningAlgorithm("RSA");

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
        inputHash.setResponseSigType("PKCS7");
        inputHash.setHashValue("a1b2c3d4e5f6" + id);
        return inputHash;
    }

    private EsignStatusRequest createValidStatusRequest(String transactionId) {
        EsignStatusRequest request = new EsignStatusRequest();
        request.setVersion("3.3");
        request.setTimestamp(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")).format(IST_FORMATTER));
        request.setTransactionId(transactionId);
        request.setAspId("ASP001");
        return request;
    }
}