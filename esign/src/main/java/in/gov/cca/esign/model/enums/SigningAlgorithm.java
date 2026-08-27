package in.gov.cca.esign.model.enums;

public enum SigningAlgorithm {
    ECDSA("ECDSA"),
    RSA("RSA");

    private final String value;

    SigningAlgorithm(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static SigningAlgorithm fromValue(String value) {
        for (SigningAlgorithm algo : values()) {
            if (algo.value.equalsIgnoreCase(value)) {
                return algo;
            }
        }
        throw new IllegalArgumentException("Unknown signing algorithm: " + value);
    }
}