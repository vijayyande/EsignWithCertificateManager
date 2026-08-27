package in.gov.cca.esign.controller;

import in.gov.cca.esign.EsignApplication;
import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.model.xml.ekyc.EKycRequest;
import in.gov.cca.esign.model.xml.ekyc.EKycResponse;
import in.gov.cca.esign.model.xml.ekyc.SecondFactorRequest;
import in.gov.cca.esign.repository.EKycUserRepository;
import in.gov.cca.esign.util.CryptoUtils;
import in.gov.cca.esign.util.TokenStore;
import in.gov.cca.esign.util.XmlUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = EsignApplication.class)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class EKycControllerIntegrationTest {

    private static final String TXN = "TXN_KYC_123";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private EKycUserRepository userRepository;

    @Autowired
    private XmlUtils xmlUtils;

    @Autowired
    private TokenStore tokenStore;

    private EKycUser testUser;
    private String pinHash;

    @BeforeEach
    void setUp() {
        // Create test user
        testUser = new EKycUser();
        testUser.setUsername("testuser@username.ESP001");
        testUser.setName("Test User");
        testUser.setMobile("9876543210");
        testUser.setEmail("test@example.com");
        testUser.setAddress("123 Test Street");
        testUser.setStateProvince("Maharashtra");
        testUser.setCountry("IN");
        testUser.setPostalCode("400001");
        testUser.setPan("ABCDE1234F");
        testUser.setAadhaarLast4("1234");
        testUser.setDob(java.time.LocalDate.of(1995, 5, 10));
        testUser.setGender("M");
        testUser.setPhotograph("base64-photo");
        testUser.setEkycType(in.gov.cca.esign.model.enums.EKycType.OFFLINE_AADHAAR);
        testUser.setStatus(EKycUser.UserStatus.ACTIVE);
        testUser.setPinSalt(CryptoUtils.generateSalt());
        testUser.setPinHash(CryptoUtils.hashPin("123456", testUser.getPinSalt(), "PBKDF2WithHmacSHA256", 100000));
        testUser.setFailedAttempts(0);

        pinHash = CryptoUtils.hash(TXN + testUser.getPinHash());
        testUser = userRepository.save(testUser);
    }

    @Test
    void authenticate_ValidCredentialsCompositeMode_ReturnsSuccess() throws Exception {
        // Given
        seedSmsOtp("123456");

        EKycRequest request = createValidEkycRequest();
        request.setPinHash(pinHash);

        // Add second factor in composite mode
        SecondFactorRequest secondFactor = new SecondFactorRequest();
        secondFactor.setVersion("1.0");
        secondFactor.setSignerId(request.getSignerId());
        secondFactor.setTimestamp(java.time.ZonedDateTime.now().toString());
        secondFactor.setTransactionId(request.getTransactionId());
        secondFactor.setAuthenticationType("SMSOTP");
        secondFactor.setConsent("I hereby authorize this KYC Information authentication.");
        secondFactor.setSmsOtp("123456");

        String secondFactorXml = xmlUtils.marshal(secondFactor);
        request.setSecondFactor(Base64.getEncoder().encodeToString(secondFactorXml.getBytes()));

        String requestXml = xmlUtils.marshal(request);

        // When
        MvcResult result = mockMvc.perform(post("/ekyc/auth")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_XML))
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EKycResponse response = xmlUtils.unmarshal(responseXml, EKycResponse.class);

        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo("1"); // Success
        assertThat(response.getSignerId()).isEqualTo(request.getSignerId());
        assertThat(response.getKycData()).isNotNull();
        assertThat(response.getKycData().getName()).isEqualTo(testUser.getName());
    }

    @Test
    void authenticate_UserNotFound_ReturnsError() throws Exception {
        // Given
        EKycRequest request = createValidEkycRequest();
        request.setSignerId("nonexistent@username.ESP001");
        request.setPinHash("invalid");
        String requestXml = xmlUtils.marshal(request);

        // When - business failures are returned as HTTP 200 with error status in the body
        MvcResult result = mockMvc.perform(post("/ekyc/auth")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isOk())
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EKycResponse response = xmlUtils.unmarshal(responseXml, EKycResponse.class);

        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).contains("User not found");
    }

    @Test
    void authenticate_InvalidPin_ReturnsError() throws Exception {
        // Given
        EKycRequest request = createValidEkycRequest();
        request.setPinHash("wrong-pin-hash");
        String requestXml = xmlUtils.marshal(request);

        // When - business failures are returned as HTTP 200 with error status in the body
        MvcResult result = mockMvc.perform(post("/ekyc/auth")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isOk())
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EKycResponse response = xmlUtils.unmarshal(responseXml, EKycResponse.class);

        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).contains("Invalid PIN");
    }

    @Test
    void authenticate_IndependentMode_ReturnsPending() throws Exception {
        // Given
        EKycRequest request = createValidEkycRequest();
        request.setPinHash(pinHash);
        request.setSecondFactor(null); // Independent mode
        String requestXml = xmlUtils.marshal(request);

        // When
        MvcResult result = mockMvc.perform(post("/ekyc/auth")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isOk())
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EKycResponse response = xmlUtils.unmarshal(responseXml, EKycResponse.class);

        assertThat(response.getStatus()).isEqualTo("2"); // Pending for second factor
        assertThat(response.getResponseCode()).isNotNull();
    }

    @Test
    void authenticateSecondFactor_ValidSmsOtp_ReturnsSuccess() throws Exception {
        // Given
        seedSmsOtp("123456");

        SecondFactorRequest request = createSecondFactorRequest();
        request.setSmsOtp("123456");

        String requestXml = xmlUtils.marshal(request);

        // When
        MvcResult result = mockMvc.perform(post("/ekyc/auth/second-factor")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isOk())
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EKycResponse response = xmlUtils.unmarshal(responseXml, EKycResponse.class);

        assertThat(response.getStatus()).isEqualTo("1");
        assertThat(response.getKycData()).isNotNull();
    }

    @Test
    void authenticateSecondFactor_InvalidSmsOtp_ReturnsError() throws Exception {
        // Given
        seedSmsOtp("123456");

        SecondFactorRequest request = createSecondFactorRequest();
        request.setSmsOtp("wrong-otp");

        String requestXml = xmlUtils.marshal(request);

        // When - business failures are returned as HTTP 200 with error status in the body
        MvcResult result = mockMvc.perform(post("/ekyc/auth/second-factor")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(requestXml))
                .andExpect(status().isOk())
                .andReturn();

        // Then
        String responseXml = result.getResponse().getContentAsString();
        EKycResponse response = xmlUtils.unmarshal(responseXml, EKycResponse.class);

        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).contains("Invalid SMS OTP");
    }

    // Helper methods

    private void seedSmsOtp(String otp) {
        tokenStore.put("sms_otp:" + testUser.getUsername() + ":" + TXN, otp,
                5, TimeUnit.MINUTES);
    }

    private SecondFactorRequest createSecondFactorRequest() {
        SecondFactorRequest request = new SecondFactorRequest();
        request.setVersion("1.0");
        request.setSignerId(testUser.getUsername());
        request.setTimestamp(java.time.ZonedDateTime.now().toString());
        request.setTransactionId(TXN);
        request.setAuthenticationType("SMSOTP");
        request.setConsent("I hereby authorize this KYC Information authentication.");
        return request;
    }

    private EKycRequest createValidEkycRequest() {
        EKycRequest request = new EKycRequest();
        request.setVersion("3.3");
        request.setSignerId(testUser.getUsername());
        request.setTimestamp(java.time.ZonedDateTime.now().toString());
        request.setTransactionId(TXN);
        return request;
    }
}