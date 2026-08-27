package in.gov.cca.esign.model.xml.ekyc;

import jakarta.xml.bind.annotation.*;
import lombok.*;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"secondFactor", "signature"})
@XmlRootElement(name = "eKycReq")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EKycRequest {

    @XmlAttribute(name = "ver", required = true)
    private String version;

    @XmlAttribute(name = "signerid", required = true)
    private String signerId;

    @XmlAttribute(name = "ts", required = true)
    private String timestamp;

    @XmlAttribute(name = "txn", required = true)
    private String transactionId;

    @XmlAttribute(name = "pinhash", required = true)
    private String pinHash;

    @XmlElement(name = "SecondFactor")
    private String secondFactor;

    @XmlElement(name = "Signature", required = true)
    private String signature;
}