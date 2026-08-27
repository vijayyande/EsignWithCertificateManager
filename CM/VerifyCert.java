import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;

public class VerifyCert {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate leaf = (X509Certificate) cf.generateCertificate(
            new FileInputStream(args[0]));
        X509Certificate issuer = (X509Certificate) cf.generateCertificate(
            new FileInputStream(args[1]));

        System.out.println("=== LEAF CERTIFICATE ===");
        System.out.println("Subject:  " + leaf.getSubjectDN());
        System.out.println("Issuer:   " + leaf.getIssuerDN());
        System.out.println("SigAlg:   " + leaf.getSigAlgName());
        System.out.println("Serial:   " + leaf.getSerialNumber());
        System.out.println("Version:  v" + leaf.getVersion());
        System.out.println("NotBefore:" + leaf.getNotBefore());
        System.out.println("NotAfter: " + leaf.getNotAfter());
        System.out.println("PublicKey:" + leaf.getPublicKey().getAlgorithm()
            + " " + leaf.getPublicKey().getFormat());
        System.out.println("SigBytes: " + leaf.getSignature().length + " bytes");

        System.out.println("\n=== ISSUER CERTIFICATE ===");
        System.out.println("Subject:  " + issuer.getSubjectDN());
        System.out.println("Issuer:   " + issuer.getIssuerDN());
        System.out.println("SelfSigned:" + issuer.getSubjectDN().equals(issuer.getIssuerDN()));

        // DER round-trip: encode -> decode -> re-encode -> compare
        System.out.println("\n=== DER ROUND-TRIP TEST ===");
        byte[] originalDer = leaf.getEncoded();
        X509Certificate reEncoded = (X509Certificate) cf.generateCertificate(
            new ByteArrayInputStream(originalDer));
        byte[] reEncodedDer = reEncoded.getEncoded();
        boolean derMatch = java.util.Arrays.equals(originalDer, reEncodedDer);
        System.out.println("DER round-trip: " + (derMatch ? "PASS" : "FAIL"));
        System.out.println("Original DER length:  " + originalDer.length);
        System.out.println("Re-encoded DER length:" + reEncodedDer.length);

        // Signature verification
        System.out.println("\n=== SIGNATURE VERIFICATION ===");
        try {
            leaf.verify(issuer.getPublicKey());
            System.out.println("Signature verify: PASS");
        } catch (Exception e) {
            System.out.println("Signature verify: FAIL - " + e.getMessage());
        }

        // Try to create PKCS#12 (simulates Windows cert store import)
        System.out.println("\n=== PKCS#12 KEYSTORE TEST ===");
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            // Use a dummy private key entry for testing
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            java.security.KeyPair kp = kpg.generateKeyPair();
            ks.setKeyEntry("test", kp.getPrivate(), "changeit".toCharArray(),
                new Certificate[]{leaf, issuer});
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ks.store(bos, "changeit".toCharArray());
            System.out.println("PKCS#12 export: PASS (" + bos.size() + " bytes)");
            
            // Re-import and verify
            KeyStore ks2 = KeyStore.getInstance("PKCS12");
            ks2.load(new ByteArrayInputStream(bos.toByteArray()), "changeit".toCharArray());
            X509Certificate imported = (X509Certificate) ks2.getCertificateChain("test")[0];
            System.out.println("PKCS#12 re-import: subject=" + imported.getSubjectDN());
            imported.verify(issuer.getPublicKey());
            System.out.println("PKCS#12 chain verify: PASS");
        } catch (Exception e) {
            System.out.println("PKCS#12 test: FAIL - " + e.getMessage());
            e.printStackTrace();
        }

        // Check BasicConstraints critical flag
        System.out.println("\n=== CRITICAL EXTENSIONS ===");
        try {
            byte[] bcBytes = leaf.getExtensionValue("2.5.29.19");
            System.out.println("BasicConstraints present: " + (bcBytes != null));
        } catch (Exception e) {
            System.out.println("BasicConstraints check error: " + e.getMessage());
        }
        try {
            byte[] kuBytes = leaf.getExtensionValue("2.5.29.15");
            System.out.println("KeyUsage present: " + (kuBytes != null));
        } catch (Exception e) {
            System.out.println("KeyUsage check error: " + e.getMessage());
        }

        System.out.println("\n=== CERTPRINT (hex dump of TBS + SigAlg + Sig) ===");
        byte[] enc = leaf.getEncoded();
        System.out.println("Total encoded length: " + enc.length + " bytes");
        // First 8 bytes (ASN.1 header)
        System.out.printf("ASN.1 tag=0x%02X, length bytes=%d%n", enc[0] & 0xFF, enc[1] & 0xFF);
    }
}
