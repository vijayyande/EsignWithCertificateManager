package in.gov.cca.esign.controller;

import in.gov.cca.esign.EsignApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = EsignApplication.class)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class DevTestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void transactionDetails_TransactionNotFound_Returns404() throws Exception {
        mockMvc.perform(get("/esign/dev/transactions/NONEXISTENT"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void authAndSign_MissingFields_ReturnsBadRequest() throws Exception {
        String body = """
                {"transactionId":"TXN-1","username":"user"}
                """;
        mockMvc.perform(post("/esign/dev/auth-and-sign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void authAndSign_TransactionNotFound_ReturnsNotFound() throws Exception {
        String body = """
                {"transactionId":"NONEXISTENT","username":"demosigner","pin":"123456","otp":"123456"}
                """;
        mockMvc.perform(post("/esign/dev/auth-and-sign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("Transaction not found: NONEXISTENT"));
    }

    @Test
    void completeSigning_TransactionNotFound_ReturnsNotFound() throws Exception {
        mockMvc.perform(post("/esign/dev/complete-signing")
                        .param("transactionId", "NONEXISTENT")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void pinHash_UserNotFound_ReturnsNotFound() throws Exception {
        mockMvc.perform(get("/esign/dev/pin-hash")
                        .param("username", "ghost")
                        .param("pin", "123456")
                        .param("txn", "TXN-1"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void sendOtp_UserNotFound_ReturnsBadRequest() throws Exception {
        mockMvc.perform(get("/esign/dev/send-otp")
                        .param("username", "ghost")
                        .param("txn", "TXN-1"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }
}
