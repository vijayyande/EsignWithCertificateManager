package in.gov.cca.esign.service;

import java.util.List;
import java.util.Map;

public interface Fido2Service {

    Map<String, Object> startRegistration(String username);

    Map<String, Object> finishRegistration(String username, Map<String, Object> attestationResponse);

    Map<String, Object> startAuthentication(String username);

    boolean verifyAssertion(String username, String assertion, String transactionId);

    void revokeCredential(String username, String credentialId);

    List<Map<String, Object>> getUserCredentials(String username);
}