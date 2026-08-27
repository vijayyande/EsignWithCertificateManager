package in.gov.cca.esign.model.xml.esign;

import jakarta.xml.bind.annotation.*;
import lombok.*;

import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"docs", "signature"})
@XmlRootElement(name = "Esign")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EsignRequest {

    @XmlAttribute(name = "ver", required = true)
    private String version;

    @XmlAttribute(name = "signerid")
    private String signerId;

    @XmlAttribute(name = "ts", required = true)
    private String timestamp;

    @XmlAttribute(name = "txn", required = true)
    private String transactionId;

    @XmlAttribute(name = "maxWaitPeriod", required = true)
    private Integer maxWaitPeriod;

    @XmlAttribute(name = "aspId", required = true)
    private String aspId;

    @XmlAttribute(name = "responseUrl", required = true)
    private String responseUrl;

    @XmlAttribute(name = "redirectUrl")
    private String redirectUrl;

    @XmlAttribute(name = "signingAlgorithm", required = true)
    private String signingAlgorithm;

    @XmlElement(name = "Docs", required = true)
    private Docs docs;

    @XmlElement(name = "Signature", required = true)
    private String signature;

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {"inputHash"})
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class Docs {
        @XmlElement(name = "InputHash", required = true)
        private List<InputHash> inputHash;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "")
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class InputHash {
        @XmlValue
        private String hashValue;

        @XmlAttribute(name = "id", required = true)
        private Integer id;

        @XmlAttribute(name = "hashAlgorithm", required = true)
        private String hashAlgorithm;

        @XmlAttribute(name = "docInfo", required = true)
        private String docInfo;

        @XmlAttribute(name = "docUrl", required = true)
        private String docUrl;

        @XmlAttribute(name = "responseSigType", required = true)
        private String responseSigType;
    }
}