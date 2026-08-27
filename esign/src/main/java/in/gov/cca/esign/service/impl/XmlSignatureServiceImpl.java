package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.service.XmlSignatureService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

@Slf4j
@Service
@RequiredArgsConstructor
public class XmlSignatureServiceImpl implements XmlSignatureService {

    static {
        Init.init();
    }

    private final KeyStore espKeyStore;

    @Value("${esign.keystore.password:changeit}")
    private String keystorePassword;

    @Value("${esign.keystore.alias:esign-esp}")
    private String keystoreAlias;

    @Override
    public boolean verifySignature(String xmlContent, String signature) {
        if (xmlContent == null || xmlContent.isBlank()) {
            return false;
        }
        try {
            Document doc = parseSecurely(xmlContent);

            NodeList signatureNodes =
                    doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
            if (signatureNodes.getLength() == 0) {
                log.warn("No XML-DSig Signature element found");
                return false;
            }

            Element sigElement = (Element) signatureNodes.item(0);
            XMLSignature xmlSignature = new XMLSignature(sigElement, "");

            PublicKey publicKey = extractPublicKey(xmlSignature);
            if (publicKey == null) {
                log.warn("No public key resolvable from signature KeyInfo");
                return false;
            }
            return xmlSignature.checkSignatureValue(publicKey);
        } catch (Exception e) {
            log.error("Error verifying XML signature", e);
            return false;
        }
    }

    @Override
    public String signXml(String xmlContent, String privateKeyAlias) {
        try {
            String alias = privateKeyAlias != null ? privateKeyAlias : keystoreAlias;
            PrivateKey privateKey = (PrivateKey) espKeyStore.getKey(
                    alias, keystorePassword.toCharArray());
            X509Certificate cert = (X509Certificate) espKeyStore.getCertificate(alias);

            if (privateKey == null || cert == null) {
                throw new IllegalStateException(
                        "No signing credential configured for alias: " + alias);
            }

            Document doc = parseSecurely(xmlContent);

            XMLSignature sig = new XMLSignature(doc,
                    "",
                    XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
                    MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

            sig.addDocument("", null, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
            sig.addKeyInfo(cert);
            sig.addKeyInfo(cert.getPublicKey());
            sig.sign(privateKey);

            doc.getDocumentElement().appendChild(sig.getElement());

            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            return writer.toString();
        } catch (Exception e) {
            log.error("Error signing XML", e);
            throw new RuntimeException("Failed to sign XML", e);
        }
    }

    @Override
    public boolean validateSignature(String xmlContent, String signature, String certificate) {
        try {
            byte[] certBytes = java.util.Base64.getDecoder().decode(certificate);
            java.security.cert.CertificateFactory cf =
                    java.security.cert.CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(certBytes));

            Document doc = parseSecurely(xmlContent);
            NodeList signatureNodes =
                    doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
            if (signatureNodes.getLength() == 0) {
                return false;
            }

            XMLSignature xmlSignature =
                    new XMLSignature((Element) signatureNodes.item(0), "");
            return xmlSignature.checkSignatureValue(cert);
        } catch (Exception e) {
            log.error("Error validating signature with certificate", e);
            return false;
        }
    }

    private Document parseSecurely(String xmlContent) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setExpandEntityReferences(false);
        dbf.setXIncludeAware(false);
        try {
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        } catch (javax.xml.parsers.ParserConfigurationException ignored) {
            log.debug("Parser features not supported by this implementation");
        }
        return dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8)));
    }

    private PublicKey extractPublicKey(XMLSignature xmlSignature) {
        try {
            org.apache.xml.security.keys.KeyInfo keyInfo = xmlSignature.getKeyInfo();
            if (keyInfo == null) {
                return null;
            }
            X509Certificate cert = keyInfo.getX509Certificate();
            if (cert != null) {
                return cert.getPublicKey();
            }
            return keyInfo.getPublicKey();
        } catch (Exception e) {
            log.debug("Could not extract public key from KeyInfo: {}", e.getMessage());
            return null;
        }
    }
}