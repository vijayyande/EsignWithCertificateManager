package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.service.TimestampService;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.cms.*;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
public class TimestampServiceImpl implements TimestampService {

    private static final ASN1ObjectIdentifier ID_AA_SIGNATURE_TIMESTAMP_TOKEN =
            new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14");

    @Value("${esign.tsa.enabled:false}")
    private boolean tsaEnabled;

    @Value("${esign.tsa.url:http://timestamp.digicert.com,http://timestamp.sectigo.com,http://timestamp.entrust.net/TSS/RFC3161sha2TS}")
    private String tsaUrls;

    @Value("${esign.tsa.connect-timeout-ms:5000}")
    private int connectTimeoutMs;

    @Value("${esign.tsa.read-timeout-ms:10000}")
    private int readTimeoutMs;

    @Override
    public boolean isEnabled() {
        return tsaEnabled;
    }

    @Override
    public Optional<byte[]> embedTimestamp(byte[] cmsSignatureBytes) {
        if (!tsaEnabled) return Optional.empty();

        try {
            CMSSignedData signedData = new CMSSignedData(cmsSignatureBytes);
            SignerInformationStore signerInfoStore = signedData.getSignerInfos();

            SignerInformation signerInfo = signerInfoStore.getSigners().iterator().next();

            byte[] signedAttrsEncoded = signerInfo.toASN1Structure().getAuthenticatedAttributes().getEncoded();

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] attrHash = md.digest(signedAttrsEncoded);

            TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
            reqGen.setCertReq(false);
            TimeStampRequest tsReq = reqGen.generate(
                    org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256, attrHash);

            byte[] tsReqBytes = tsReq.getEncoded();

            List<String> urls = parseTsaUrls();
            for (String tsaUrl : urls) {
                Optional<TimeStampToken> token = requestTimestamp(tsaUrl.trim(), tsReq, tsReqBytes);
                if (token.isPresent()) {
                    byte[] tsTokenEncoded = token.get().getEncoded();

                    ASN1EncodableVector unsignedAttrs = new ASN1EncodableVector();
                    ASN1EncodableVector attrValues = new ASN1EncodableVector();
                    attrValues.add(new DEROctetString(tsTokenEncoded));
                    unsignedAttrs.add(new Attribute(
                            ID_AA_SIGNATURE_TIMESTAMP_TOKEN,
                            new DERSet(attrValues)));

                    SignerInformation updatedSignerInfo = SignerInformation.replaceUnsignedAttributes(
                            signerInfo, new AttributeTable(unsignedAttrs));

                    SignerInformationStore updatedStore = new SignerInformationStore(updatedSignerInfo);
                    CMSSignedData timestampedData = CMSSignedData.replaceSigners(signedData, updatedStore);

                    log.info("TSA timestamp embedded from {}", tsaUrl.trim());
                    return Optional.of(timestampedData.getEncoded());
                }
            }

            log.warn("All TSA servers failed, using unsigned signature");
            return Optional.empty();

        } catch (Exception e) {
            log.warn("TSA timestamp failed, using unsigned signature: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private List<String> parseTsaUrls() {
        List<String> urls = new ArrayList<>();
        if (tsaUrls != null) {
            for (String u : tsaUrls.split(",")) {
                if (!u.trim().isEmpty()) urls.add(u.trim());
            }
        }
        return urls;
    }

    private Optional<TimeStampToken> requestTimestamp(String tsaUrl, TimeStampRequest tsReq, byte[] tsReqBytes) {
        try {
            URL url = new URL(tsaUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/timestamp-query");
            conn.setRequestProperty("Content-Length", String.valueOf(tsReqBytes.length));
            conn.setConnectTimeout(connectTimeoutMs);
            conn.setReadTimeout(readTimeoutMs);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(tsReqBytes);
            }

            int httpCode = conn.getResponseCode();
            if (httpCode != 200) {
                log.warn("TSA {} returned HTTP {}", tsaUrl, httpCode);
                return Optional.empty();
            }

            byte[] tsRespBytes = conn.getInputStream().readAllBytes();
            TimeStampResponse tsResp = new TimeStampResponse(tsRespBytes);
            tsResp.validate(tsReq);

            TimeStampToken tsToken = tsResp.getTimeStampToken();
            if (tsToken == null) {
                log.warn("TSA {} response contained no token (status={})", tsaUrl, tsResp.getStatus());
                return Optional.empty();
            }

            return Optional.of(tsToken);
        } catch (Exception e) {
            log.warn("TSA {} failed: {}", tsaUrl, e.getMessage());
            return Optional.empty();
        }
    }
}
