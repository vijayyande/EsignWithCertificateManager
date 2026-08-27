package in.gov.cca.esign.model.enums;

public enum ResponseSignatureType {
    RAW("raw"),
    PKCS7("PKCS7"),
    PKCS7_PDF("PKCS7pdf"),
    PKCS7_COMPLETE("PKCS7complete");

    private final String value;

    ResponseSignatureType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static ResponseSignatureType fromValue(String value) {
        for (ResponseSignatureType type : values()) {
            if (type.value.equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown response signature type: " + value);
    }
}