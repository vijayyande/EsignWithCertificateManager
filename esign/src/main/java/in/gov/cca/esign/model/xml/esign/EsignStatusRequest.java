package in.gov.cca.esign.model.xml.esign;

import jakarta.xml.bind.annotation.*;
import lombok.*;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"signature"})
@XmlRootElement(name = "EsignStatus")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EsignStatusRequest {

    @XmlAttribute(name = "ver", required = true)
    private String version;

    @XmlAttribute(name = "ts", required = true)
    private String timestamp;

    @XmlAttribute(name = "txn", required = true)
    private String transactionId;

    @XmlAttribute(name = "aspId", required = true)
    private String aspId;

    @XmlElement(name = "Signature", required = true)
    private String signature;
}