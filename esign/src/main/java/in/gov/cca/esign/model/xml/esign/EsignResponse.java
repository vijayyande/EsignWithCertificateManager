package in.gov.cca.esign.model.xml.esign;

import jakarta.xml.bind.annotation.*;
import lombok.*;

import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"userX509Certificate", "signatures", "signature"})
@XmlRootElement(name = "EsignResp")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EsignResponse {

    @XmlAttribute(name = "ver", required = true)
    private String version;

    @XmlAttribute(name = "status", required = true)
    private String status;

    @XmlAttribute(name = "ts", required = true)
    private String timestamp;

    @XmlAttribute(name = "txn", required = true)
    private String transactionId;

    @XmlAttribute(name = "resCode", required = true)
    private String responseCode;

    @XmlAttribute(name = "error")
    private String error;

    @XmlElement(name = "UserX509Certificate")
    private String userX509Certificate;

    @XmlElement(name = "Signatures")
    private Signatures signatures;

    @XmlElement(name = "Signature")
    private String signature;

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {"docSignatures"})
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class Signatures {
        @XmlElement(name = "DocSignature", required = true)
        private List<DocSignature> docSignatures;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "")
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class DocSignature {
        @XmlValue
        private String signatureValue;

        @XmlAttribute(name = "id", required = true)
        private Integer id;

        @XmlAttribute(name = "sigHashAlgorithm", required = true)
        private String sigHashAlgorithm;

        @XmlAttribute(name = "error")
        private String error;
    }
}