package in.gov.cca.esign.model.xml.ekyc;

import jakarta.xml.bind.annotation.*;
import lombok.*;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"publicKeyData", "signature"})
@XmlRootElement(name = "PublicKeyRegistration")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PublicKeyRegistration {

    @XmlElement(name = "PublicKeyData", required = true)
    private PublicKeyData publicKeyData;

    @XmlElement(name = "Signature", required = true)
    private String signature;

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "")
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class PublicKeyData {
        @XmlValue
        private String base64PublicKey;

        @XmlAttribute(name = "SignerId", required = true)
        private String signerId;

        @XmlAttribute(name = "TimeStamp", required = true)
        private String timestamp;

        @XmlAttribute(name = "Algorithm", required = true)
        private String algorithm;

        @XmlAttribute(name = "Consent", required = true)
        private String consent;
    }
}