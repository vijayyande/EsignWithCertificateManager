package in.gov.cca.esign.model.enums;

public enum EKycType {
    OFFLINE_AADHAAR("Offline Aadhaar"),
    BANK("BANK"),
    ORGANISATIONAL("Organisational KYC"),
    PAN("PAN KYC"),
    FOREIGN_NATIONAL("Foreign National KYC");

    private final String description;

    EKycType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}