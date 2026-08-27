package in.gov.cca.esign.model.xml.ekyc.bank;

import jakarta.xml.bind.annotation.*;
import lombok.*;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "BankKYCResp")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BankKycResponse {

    @XmlAttribute(name = "ver", required = true)
    private String version;

    @XmlAttribute(name = "ts", required = true)
    private String timestamp;

    @XmlAttribute(name = "txn", required = true)
    private String transactionId;

    @XmlAttribute(name = "status", required = true)
    private String status;

    @XmlAttribute(name = "resCode", required = true)
    private String responseCode;

    @XmlAttribute(name = "errorCode")
    private String errorCode;

    @XmlAttribute(name = "errorMessage")
    private String errorMessage;
}