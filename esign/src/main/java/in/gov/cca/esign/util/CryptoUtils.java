package in.gov.cca.esign.util;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

@Slf4j
public final class CryptoUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    private CryptoUtils() {
    }

    public static String generateSalt() {
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);
        return Hex.toHexString(salt);
    }

    public static String hashPin(String pin, String salt, String algorithm, int iterations) {
        try {
            if ("PBKDF2WithHmacSHA256".equals(algorithm)) {
                return hashPinPbkdf2(pin, salt, iterations);
            } else {
                // Fallback to standard Java PBKDF2
                return hashPinStandard(pin, salt, iterations);
            }
        } catch (Exception e) {
            log.error("Error hashing PIN", e);
            throw new RuntimeException("Failed to hash PIN", e);
        }
    }

    private static String hashPinPbkdf2(String pin, String salt, int iterations) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(
                new org.bouncycastle.crypto.digests.SHA256Digest());
        byte[] passwordBytes = new String(pin.toCharArray()).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        generator.init(
                passwordBytes,
                Hex.decode(salt),
                iterations
        );
        byte[] key = ((KeyParameter) generator.generateDerivedParameters(256)).getKey();
        return Hex.toHexString(key);
    }

    private static String hashPinStandard(String pin, String salt, int iterations) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(
                pin.toCharArray(),
                Hex.decode(salt),
                iterations,
                256
        );
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return Hex.toHexString(hash);
    }

    public static String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Hex.toHexString(hash);
        } catch (Exception e) {
            log.error("Error computing hash", e);
            throw new RuntimeException("Failed to compute hash", e);
        }
    }

    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    public static String bytesToHex(byte[] bytes) {
        return Hex.toHexString(bytes);
    }

    public static byte[] hexToBytes(String hex) {
        return Hex.decode(hex);
    }
}