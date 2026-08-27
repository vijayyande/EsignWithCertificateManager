package in.gov.cca.esign.controller;

import in.gov.cca.esign.domain.DocumentSignature;
import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.domain.EsignTransaction;
import in.gov.cca.esign.domain.UserAuthenticationFactor;
import in.gov.cca.esign.model.enums.EKycType;
import in.gov.cca.esign.repository.EKycUserRepository;
import in.gov.cca.esign.repository.EsignTransactionRepository;
import in.gov.cca.esign.repository.UserAuthenticationFactorRepository;
import in.gov.cca.esign.service.EKycService;
import in.gov.cca.esign.service.EsignSigningService;
import in.gov.cca.esign.service.OtpService;
import in.gov.cca.esign.util.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DEV / TEST HARNESS ONLY - never expose these endpoints in production.
 * Backs the bundled web test console (src/main/resources/static).
 */
@Slf4j
@RestController
@RequestMapping("/esign/dev")
@RequiredArgsConstructor
public class DevTestController {

    private static final DateTimeFormatter IST_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
    private static final ZoneId IST = ZoneId.of("Asia/Kolkata");

    private final EKycService ekycService;
    private final EKycUserRepository userRepository;
    private final UserAuthenticationFactorRepository factorRepository;
    private final OtpService otpService;
    private final EsignTransactionRepository transactionRepository;
    private final EsignSigningService esignSigningService;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public record DevUserRequest(
            String username,
            String pin,
            String name,
            String mobile,
            String email,
            String address,
            String stateProvince,
            String country,
            String postalCode,
            String dob,
            String gender,
            String pan,
            String aadhaarLast4,
            String photograph,
            String ekycType) {
    }

    @PostMapping(value = "/users", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Transactional
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody DevUserRequest req) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            if (req.username() == null || req.username().isBlank()
                    || req.pin() == null || req.pin().isBlank()) {
                out.put("error", "username and pin are required");
                return ResponseEntity.badRequest().body(out);
            }

            // Idempotent seeding: replace any existing user with the same username
            userRepository.findByUsername(req.username())
                    .ifPresent(existing -> userRepository.delete(existing));

            EKycUser user = EKycUser.builder()
                    .username(req.username())
                    .name(req.name() != null ? req.name() : req.username())
                    .mobile(req.mobile())
                    .email(req.email())
                    .address(req.address())
                    .stateProvince(req.stateProvince())
                    .country(req.country() != null ? req.country() : "IN")
                    .postalCode(req.postalCode())
                    .dob(req.dob() != null && !req.dob().isBlank() ? LocalDate.parse(req.dob()) : null)
                    .gender(req.gender())
                    .pan(req.pan())
                    .aadhaarLast4(req.aadhaarLast4())
                    .photograph(req.photograph())
                    .ekycType(resolveEkycType(req.ekycType()))
                    .build();

            EKycUser saved = ekycService.createUser(user, req.pin());

            // createUser registers a default SMSOTP factor; add TOTP for that flow too
            registerFactor(saved, UserAuthenticationFactor.AuthenticationFactorType.TOTP,
                    null, randomBase32(32));

            out.put("status", "created");
            out.put("username", saved.getUsername());
            out.put("ekycType", saved.getEkycType().name());
            out.put("factorsRegistered", "SMSOTP, TOTP");
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            log.warn("Dev user creation failed: {}", e.getMessage());
            out.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(out);
        }
    }

    @GetMapping(value = "/users/{username}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getUser(@PathVariable String username) {
        Map<String, Object> out = new LinkedHashMap<>();
        return userRepository.findByUsername(username)
                .<ResponseEntity<Map<String, Object>>>map(user -> {
                    out.put("username", user.getUsername());
                    out.put("name", user.getName());
                    out.put("mobile", user.getMobile());
                    out.put("email", user.getEmail());
                    out.put("status", user.getStatus().name());
                    out.put("ekycType", user.getEkycType().name());
                    out.put("failedAttempts", user.getFailedAttempts());
                    out.put("lockedUntil", user.getLockedUntil());
                    return ResponseEntity.ok(out);
                })
                .orElseGet(() -> {
                    out.put("error", "User not found: " + username);
                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(out);
                });
    }

    /**
     * Computes the pinhash value an eKYC client must supply:
     * pinhash = SHA256( txn + SHA256_PBKDF2(pin, salt) )
     */
    @GetMapping(value = "/pin-hash", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> pinHash(@RequestParam String username,
                                                       @RequestParam String pin,
                                                       @RequestParam String txn) {
        Map<String, Object> out = new LinkedHashMap<>();
        EKycUser user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            out.put("error", "User not found: " + username);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(out);
        }
        boolean pinValid = CryptoUtils.constantTimeEquals(
                CryptoUtils.hashPin(pin, user.getPinSalt(),
                        "PBKDF2WithHmacSHA256",
                        100000),
                user.getPinHash());

        out.put("username", username);
        out.put("txn", txn);
        out.put("pinValid", pinValid);
        out.put("pinHash", CryptoUtils.hash(txn + user.getPinHash()));
        return ResponseEntity.ok(out);
    }

    /**
     * Sends an SMS OTP through the real pipeline and RETURNS THE CODE so the
     * browser console can complete second-factor flows without an SMS gateway.
     */
    @GetMapping(value = "/send-otp", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> sendOtp(@RequestParam String username,
                                                       @RequestParam String txn) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            String otp = otpService.sendSmsOtp(username, txn);
            log.warn("[DEV] OTP exposed over unsecured dev endpoint for user {}", username);
            out.put("username", username);
            out.put("txn", txn);
            out.put("otp", otp);
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            out.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(out);
        }
    }

    /**
     * DEV ONLY — instantly completes a pending eSign transaction by signing each
     * document hash with the HSM key-pair and returning the full signed response
     * (including CMS signatures). The browser console uses this to simulate the
     * user-auth → signing flow without requiring a real eKYC session.
     */
    @PostMapping(value = "/complete-signing", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Transactional
    public ResponseEntity<Map<String, Object>> completeSigning(
            @RequestParam String transactionId,
            @RequestBody(required = false) Map<String, String> body) {
        Map<String, Object> out = new LinkedHashMap<>();

        EsignTransaction txn = transactionRepository.findByTransactionId(transactionId).orElse(null);
        if (txn == null) {
            out.put("error", "Transaction not found: " + transactionId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(out);
        }

        try {
            Date browserSigningTime = null;
            if (body != null && body.containsKey("signingTime") && body.get("signingTime") != null) {
                browserSigningTime = Date.from(java.time.Instant.parse(body.get("signingTime")));
            }
            Date signTime = browserSigningTime != null ? browserSigningTime : new Date();

            String signerId = body != null ? body.getOrDefault("signerId", txn.getSignerId()) : txn.getSignerId();

            EsignSigningService.SignResult result = esignSigningService.signTransaction(
                    transactionId, signerId, signTime);

            out.put("status", "COMPLETED");
            out.put("transactionId", transactionId);
            out.put("signerId", signerId);
            out.put("documentsSigned", result.transaction().getDocumentSignatures().size());
            out.put("esignResponse", result.esignResponse());
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            log.error("Dev signing failed for txn {}", transactionId, e);
            out.put("error", "Signing failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(out);
        }
    }

    /**
     * Returns full transaction details (including document hashes) so the auth
     * page can display what the user is being asked to sign.
     */
    @GetMapping(value = "/transactions/{transactionId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> transactionDetails(@PathVariable String transactionId) {
        Map<String, Object> out = new LinkedHashMap<>();
        EsignTransaction txn = transactionRepository.findByTransactionId(transactionId).orElse(null);
        if (txn == null) {
            out.put("error", "Transaction not found: " + transactionId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(out);
        }
        out.put("transactionId", txn.getTransactionId());
        out.put("aspId", txn.getAspId());
        out.put("signerId", txn.getSignerId());
        out.put("signingAlgorithm", txn.getSigningAlgorithm());
        out.put("maxWaitPeriod", txn.getMaxWaitPeriod());
        out.put("responseUrl", txn.getResponseUrl());
        out.put("redirectUrl", txn.getRedirectUrl());
        out.put("status", txn.getStatus().name());
        out.put("createdAt", txn.getCreatedAt() != null ? txn.getCreatedAt().toString() : null);

        List<Map<String, Object>> docs = new java.util.ArrayList<>();
        if (txn.getDocumentSignatures() != null) {
            for (DocumentSignature d : txn.getDocumentSignatures()) {
                Map<String, Object> dm = new LinkedHashMap<>();
                dm.put("documentId", d.getDocumentId());
                dm.put("hashAlgorithm", d.getHashAlgorithm());
                dm.put("docInfo", d.getDocInfo());
                dm.put("docUrl", d.getDocUrl());
                dm.put("responseSigType", d.getResponseSigType());
                dm.put("documentHash", d.getDocumentHash());
                dm.put("signatureValue", d.getSignatureValue());
                dm.put("signedAt", d.getSignedAt() != null ? d.getSignedAt().toString() : null);
                docs.add(dm);
            }
        }
        out.put("documents", docs);
        return ResponseEntity.ok(out);
    }

    /**
     * Authenticates user (PIN + OTP) and completes signing in one step.
     * Used by the /esign/auth page.  Validates PIN hash, verifies OTP, then
     * generates a key pair, optionally calls the CA for a certificate, signs
     * every document hash, and returns the full signed response.
     */
    @PostMapping(value = "/auth-and-sign", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Transactional
    public ResponseEntity<Map<String, Object>> authAndSign(@RequestBody Map<String, String> body) {
        Map<String, Object> out = new LinkedHashMap<>();

        String transactionId = body.get("transactionId");
        String username = body.get("username");
        String pin = body.get("pin");
        String otp = body.get("otp");

        if (transactionId == null || username == null || pin == null || otp == null) {
            out.put("error", "transactionId, username, pin, and otp are required");
            return ResponseEntity.badRequest().body(out);
        }

        EsignTransaction txn = transactionRepository.findByTransactionId(transactionId).orElse(null);
        if (txn == null) {
            out.put("error", "Transaction not found: " + transactionId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(out);
        }
        if (txn.getStatus() != EsignTransaction.TransactionStatus.PENDING
                && txn.getStatus() != EsignTransaction.TransactionStatus.IN_PROGRESS) {
            out.put("error", "Transaction " + transactionId + " is " + txn.getStatus()
                    + " — cannot sign");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(out);
        }

        EKycUser user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            out.put("error", "User not found: " + username);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(out);
        }

        boolean pinValid = CryptoUtils.constantTimeEquals(
                CryptoUtils.hashPin(pin, user.getPinSalt(), "PBKDF2WithHmacSHA256", 100000),
                user.getPinHash());
        if (!pinValid) {
            out.put("error", "Invalid PIN");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(out);
        }

        boolean otpValid = otpService.verifySmsOtp(username, otp, transactionId);
        if (!otpValid) {
            out.put("error", "Invalid or expired OTP");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(out);
        }

        try {
            Date browserSigningTime = null;
            String signingTimeStr = body.get("signingTime");
            if (signingTimeStr != null && !signingTimeStr.isBlank()) {
                browserSigningTime = Date.from(java.time.Instant.parse(signingTimeStr));
            }
            Date signTime = browserSigningTime != null ? browserSigningTime : new Date();

            EsignSigningService.SignResult result = esignSigningService.signTransaction(
                    transactionId, username, signTime);

            out.put("status", "COMPLETED");
            out.put("transactionId", transactionId);
            out.put("signerId", username);
            out.put("documentsSigned", result.transaction().getDocumentSignatures().size());
            out.put("certificate", result.certificatePem());
            out.put("redirectUrl", txn.getRedirectUrl());
            out.put("esignResponse", result.esignResponse());
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            log.error("Auth-and-sign failed for txn {}", transactionId, e);
            out.put("error", "Signing failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(out);
        }
    }

    private EKycType resolveEkycType(String value) {
        if (value == null || value.isBlank()) {
            return EKycType.OFFLINE_AADHAAR;
        }
        for (EKycType type : EKycType.values()) {
            if (type.name().equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown eKYC type: " + value);
    }

    private void registerFactor(EKycUser user, UserAuthenticationFactor.AuthenticationFactorType type,
                                String factorData, String secretKey) {
        factorRepository.save(UserAuthenticationFactor.builder()
                .user(user)
                .factorType(type)
                .factorData(factorData)
                .secretKey(secretKey)
                .status(UserAuthenticationFactor.FactorStatus.ACTIVE)
                .registeredAt(LocalDateTime.now())
                .build());
    }

    private String randomBase32(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(BASE32_ALPHABET.charAt(RANDOM.nextInt(BASE32_ALPHABET.length())));
        }
        return sb.toString();
    }
}