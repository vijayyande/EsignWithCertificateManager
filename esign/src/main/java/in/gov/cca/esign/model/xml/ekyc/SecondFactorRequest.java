package in.gov.cca.esign.model.xml.ekyc;

import jakarta.xml.bind.annotation.*;
import lombok.*;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"smsOtp", "totp", "mat", "fido", "pubSign", "signature"})
@XmlRootElement(name = "SecondFactorRequest")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecondFactorRequest {

    @XmlAttribute(name = "ver", required = true)
    private String version;

    @XmlAttribute(name = "signerid", required = true)
    private String signerId;

    @XmlAttribute(name = "ts", required = true)
    private String timestamp;

    @XmlAttribute(name = "txn", required = true)
    private String transactionId;

    @XmlAttribute(name = "authenticationType", required = true)
    private String authenticationType;

    @XmlAttribute(name = "consent", required = true)
    private String consent;

    @XmlElement(name = "SMSOTP")
    private String smsOtp;

    @XmlElement(name = "TOTP")
    private String totp;

    @XmlElement(name = "MAT")
    private String mat;

    @XmlElement(name = "FIDO")
    private String fido;

    @XmlElement(name = "PUBSIGN")
    private String pubSign;

    @XmlElement(name = "Signature")
    private String signature;
}