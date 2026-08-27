package in.gov.cca.esign.service;

public interface PublicKeyAuthService {

    String startRegistration(String username, String algorithm);

    boolean finishRegistration(String username, String publicKeyData, String signature);

    String startAuthentication(String username);

    boolean verifySignature(String username, String signature, String challenge);

    void revokeKey(String username);

    String getRegisteredAlgorithm(String username);
}