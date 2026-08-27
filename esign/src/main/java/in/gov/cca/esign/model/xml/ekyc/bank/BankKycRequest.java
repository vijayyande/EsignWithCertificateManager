package in.gov.cca.esign.model.xml.ekyc.bank;

import jakarta.xml.bind.annotation.*;
import lombok.*;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"kycInfo", "photo", "signature"})
@XmlRootElement(name = "BankKYC")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BankKycRequest {

    @XmlAttribute(name = "ver", required = true)
    private String version;

    @XmlAttribute(name = "ts", required = true)
    private String timestamp;

    @XmlAttribute(name = "txn", required = true)
    private String transactionId;

    @XmlAttribute(name = "bankIfscCode")
    private String bankIfscCode;

    @XmlAttribute(name = "bankName", required = true)
    private String bankName;

    @XmlAttribute(name = "accountNumber", required = true)
    private String accountNumber;

    @XmlElement(name = "KYCInfo", required = true)
    private KycInfo kycInfo;

    @XmlElement(name = "Photo", required = true)
    private Photo photo;

    @XmlElement(name = "Signature", required = true)
    private String signature;

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "")
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class KycInfo {
        @XmlAttribute(name = "name", required = true)
        private String name;

        @XmlAttribute(name = "mobile", required = true)
        private String mobile;

        @XmlAttribute(name = "email")
        private String email;

        @XmlAttribute(name = "address", required = true)
        private String address;

        @XmlAttribute(name = "stateProvince", required = true)
        private String stateProvince;

        @XmlAttribute(name = "country", required = true)
        private String country;

        @XmlAttribute(name = "postalCode", required = true)
        private String postalCode;

        @XmlAttribute(name = "dateOfBirth", required = true)
        private String dateOfBirth;

        @XmlAttribute(name = "gender", required = true)
        private String gender;

        @XmlAttribute(name = "pan")
        private String pan;

        @XmlAttribute(name = "aadhaar")
        private String aadhaar;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "")
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class Photo {
        @XmlValue
        private String base64Photo;

        @XmlAttribute(name = "format", required = true)
        private String format;
    }
}