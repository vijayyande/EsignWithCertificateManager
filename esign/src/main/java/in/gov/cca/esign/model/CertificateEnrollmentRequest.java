package in.gov.cca.esign.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Payload accepted by our {@code POST /api/certificates/request} endpoint.
 * <p>
 * CA-bound fields are forwarded verbatim to the CA service configured under
 * {@code ca.*}. The eSign-metadata fields (annotated {@code WRITE_ONLY}) are
 * captured locally for audit tracking and never sent to the CA.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CertificateEnrollmentRequest(
        // ── CA-bound fields ─────────────────────────────────────────────
        String commonName,
        String organization,
        String organizationalUnit,
        String country,
        String state,
        String locality,
        String emailAddress,
        String keyAlgorithm,
        Integer keySize,
        Integer validityDays,
        Integer validityMinutes,
        List<String> dnsNames,
        List<String> ipAddresses,
        Long issuerCaId,
        String requestedBy,
        Long profileId,
        List<AdditionalExtension> additionalExtensions,

        // ── eSign metadata (captured locally, never forwarded to CA) ────
        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String signerId,
        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String aspId,
        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String transactionId,
        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String docHash,
        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String docInfo,
        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String signingAlgorithm) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AdditionalExtension(
            String oid,
            String type,
            String value) {
    }
}
