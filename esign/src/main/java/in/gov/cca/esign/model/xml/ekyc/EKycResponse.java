package in.gov.cca.esign.model.xml.ekyc;

import jakarta.xml.bind.annotation.*;
import lombok.*;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"kycData", "photo", "organisationDetails", "bankDetails", "signature"})
@XmlRootElement(name = "eKycResp")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EKycResponse {

    @XmlAttribute(name = "ver", required = true)
    private String version;

    @XmlAttribute(name = "status", required = true)
    private String status;

    @XmlAttribute(name = "signerid", required = true)
    private String signerId;

    @XmlAttribute(name = "ts", required = true)
    private String timestamp;

    @XmlAttribute(name = "txn", required = true)
    private String transactionId;

    @XmlAttribute(name = "error")
    private String error;

    @XmlAttribute(name = "respCode", required = true)
    private String responseCode;

    @XmlElement(name = "kycData")
    private KycData kycData;

    @XmlElement(name = "Photo")
    private String photo;

    @XmlElement(name = "OrganisationDetails")
    private OrganisationDetails organisationDetails;

    @XmlElement(name = "Bankdetails")
    private BankDetails bankDetails;

    @XmlElement(name = "Signature")
    private String signature;

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "")
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class KycData {
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

        @XmlAttribute(name = "PAN")
        private String pan;

        @XmlAttribute(name = "DOB")
        private String dob;

        @XmlAttribute(name = "Gender")
        private String gender;

        @XmlAttribute(name = "Aadhaar")
        private String aadhaar;

        @XmlAttribute(name = "eKYCtype", required = true)
        private String ekycType;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "")
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class OrganisationDetails {
        @XmlAttribute(name = "txn", required = true)
        private String transactionId;

        @XmlAttribute(name = "OrgName", required = true)
        private String orgName;

        @XmlAttribute(name = "Orgunit", required = true)
        private String orgUnit;

        @XmlAttribute(name = "KycOrgId", required = true)
        private String kycOrgId;

        @XmlAttribute(name = "orgSigName", required = true)
        private String orgSigName;

        @XmlAttribute(name = "orgSigCertId", required = true)
        private String orgSigCertId;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "")
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class BankDetails {
        @XmlAttribute(name = "txn", required = true)
        private String transactionId;

        @XmlAttribute(name = "bankIfscCode")
        private String bankIfscCode;

        @XmlAttribute(name = "bankName", required = true)
        private String bankName;

        @XmlAttribute(name = "accountNumber", required = true)
        private String accountNumber;
    }
}