package in.gov.cca.esign.model.enums;

public enum EsignErrorCode {
    // eSign Response Error Codes (1xx)
    INVALID_REQUEST_FORMAT("101", "Invalid Request Format"),
    INVALID_SIGNER_ID("102", "Invalid Signer ID"),
    INVALID_VERSION("103", "Invalid Version"),
    XML_SIGNATURE_VALIDATION_FAILED("104", "XML Signature validation failed"),
    INVALID_TRANSACTION_ID("105", "Invalid transaction ID"),
    INVALID_ASP_ID("106", "Invalid ASP ID"),
    INVALID_DIGITAL_SIGNATURE("107", "Invalid Digital Signature"),
    MINIMUM_ONE_DOCUMENT_REQUIRED("108", "Minimum one document is required"),
    REQUEST_EXCEEDS_MAX_DOCUMENTS("109", "Request exceeds Maximum number of documents allowed"),
    INVALID_TIMESTAMP("110", "Invalid Timestamp"),
    INVALID_MAX_WAIT_PERIOD("111", "Invalid Maximum Wait Period"),
    DUPLICATE_TRANSACTION_ID("112", "Duplicate Transaction ID"),
    USER_TIMEOUT("113", "User Timeout. Maximum Wait Time expired."),
    AUTHENTICATION_FAILED("114", "Authentication failed. User credentials invalid."),
    UNKNOWN_ERROR("199", "Unknown error/Custom error from ESP"),

    // Document Level Error Codes (2xx)
    INVALID_DOCUMENT_HASH("201", "Invalid Document Hash"),
    INVALID_RESPONSE_SIGNATURE_TYPE("202", "Invalid response signature type"),
    INVALID_DOCUMENT_URL("203", "Invalid document URL"),
    INVALID_DOCUMENT_INFO("204", "Invalid document information"),
    INVALID_HASH_ALGORITHM("205", "Invalid hash algorithm"),
    DOCUMENT_CANCELLED_BY_USER("206", "Document cancelled by user"),
    DOCUMENT_UNKNOWN_ERROR("299", "Unknown error/Custom error from ESP"),

    // Status Check Error Codes (3xx)
    STATUS_INVALID_REQUEST_FORMAT("301", "Invalid Request Format"),
    STATUS_TRANSACTION_NOT_FOUND("302", "Transaction number not found"),
    STATUS_INVALID_VERSION("303", "Invalid Version"),
    STATUS_UNKNOWN_ERROR("399", "Unknown error/Custom error from ESP"),

    // Bank KYC Error Codes (4xx)
    BANK_INVALID_REQUEST_XML("401", "Invalid Bank KYC Request XML"),
    BANK_INVALID_SIGNATURE("402", "Invalid Bank Digital Signature or Bank is not registered entity"),
    BANK_INVALID_VERSION("403", "Invalid Version Number"),
    BANK_INVALID_TRANSACTION_ID("404", "Invalid Transaction Id"),
    BANK_DUPLICATE_TRANSACTION_ID("405", "Duplicate Transaction Id"),
    BANK_INVALID_IFSC_CODE("406", "Invalid Bank IFSC Code"),
    BANK_INVALID_BANK_NAME("407", "Invalid Bank Name"),
    BANK_KYC_INFO_MISSING("408", "KYC Information Missing"),
    BANK_INVALID_COMMON_NAME("409", "Invalid Common Name"),
    BANK_INVALID_MOBILE("410", "Invalid Mobile Number"),
    BANK_INVALID_EMAIL("411", "Invalid Email Id"),
    BANK_INVALID_ADDRESS("412", "Invalid Address"),
    BANK_INVALID_STATE("413", "Invalid State/Province"),
    BANK_INVALID_COUNTRY("414", "Invalid Country"),
    BANK_INVALID_POSTAL_CODE("415", "Invalid Postal Code"),
    BANK_INVALID_DOB("416", "Invalid Date of Birth"),
    BANK_INVALID_PAN("417", "Invalid PAN"),
    BANK_INVALID_AADHAAR("418", "Invalid Aadhaar"),
    BANK_INVALID_PHOTO_FORMAT("419", "Invalid Photo Format"),
    BANK_INVALID_PHOTO("420", "Invalid Photo"),
    BANK_UNKNOWN_ERROR("499", "Unknown error/Custom error from eKYC Service Provider"),

    // Organization KYC Error Codes (5xx)
    ORG_INVALID_REQUEST_XML("501", "Invalid OrgKYC Request XML"),
    ORG_INVALID_SIGNATURE("502", "Invalid Organizational Digital Signature"),
    ORG_INVALID_VERSION("503", "Invalid Version Number"),
    ORG_INVALID_TRANSACTION_ID("504", "Invalid Transaction Id"),
    ORG_DUPLICATE_TRANSACTION_ID("505", "Duplicate Transaction Id"),
    ORG_INVALID_KYC_ORG_ID("506", "Invalid KYC OrgId"),
    ORG_INVALID_ORG_NAME("507", "Invalid Organization Name"),
    ORG_INVALID_SIGNATORY_NAME("508", "Invalid Organization Signatory Name"),
    ORG_INVALID_SIGNATORY_CERT("509", "Invalid Organizational Signatory Certificate Identifier"),
    ORG_KYC_INFO_MISSING("510", "KYC Information is Missing"),
    ORG_INVALID_EMPLOYEE_ID("511", "Invalid Employee Id"),
    ORG_INVALID_NAME("512", "Invalid Name"),
    ORG_INVALID_MOBILE("513", "Invalid Mobile Number"),
    ORG_INVALID_EMAIL("514", "Invalid Email Id"),
    ORG_INVALID_DOB("515", "Invalid Date of Birth"),
    ORG_INVALID_GENDER("516", "Invalid Gender"),
    ORG_INVALID_PAN("517", "Invalid PAN"),
    ORG_INVALID_AADHAAR("518", "Invalid Aadhaar"),
    ORG_INVALID_PHOTO_FORMAT("519", "Invalid Photo Format"),
    ORG_INVALID_PHOTO("520", "Invalid Photo"),
    ORG_INVALID_PHYSICAL_VERIFICATION("521", "Invalid Physical Verification Tag"),
    ORG_UNKNOWN_ERROR("599", "Unknown error/Custom error from eKYC Service Provider");

    private final String code;
    private final String message;

    EsignErrorCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public static EsignErrorCode fromCode(String code) {
        for (EsignErrorCode error : values()) {
            if (error.code.equals(code)) {
                return error;
            }
        }
        return UNKNOWN_ERROR;
    }
}