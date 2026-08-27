package in.gov.cca.esign.service;

public interface XmlSignatureService {

    boolean verifySignature(String xmlContent, String signature);

    String signXml(String xmlContent, String privateKeyAlias);

    boolean validateSignature(String xmlContent, String signature, String certificate);
}