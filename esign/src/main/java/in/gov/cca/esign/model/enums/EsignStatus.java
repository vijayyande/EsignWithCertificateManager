package in.gov.cca.esign.model.enums;

public enum EsignStatus {
    SUCCESS("1"),
    FAILURE("0"),
    PENDING("2");

    private final String code;

    EsignStatus(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public static EsignStatus fromCode(String code) {
        for (EsignStatus status : values()) {
            if (status.code.equals(code)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown eSign status code: " + code);
    }
}