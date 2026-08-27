package in.gov.cca.esign.model.enums;

public enum AuthenticationType {
    SMSOTP("SMSOTP"),
    TOTP("TOTP"),
    MAT("MAT"),
    FIDO("FIDO"),
    PUBSIGN("PUBSIGN");

    private final String value;

    AuthenticationType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static AuthenticationType fromValue(String value) {
        for (AuthenticationType type : values()) {
            if (type.value.equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown authentication type: " + value);
    }
}