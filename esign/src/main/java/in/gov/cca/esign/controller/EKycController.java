package in.gov.cca.esign.controller;

import in.gov.cca.esign.model.xml.ekyc.EKycRequest;
import in.gov.cca.esign.model.xml.ekyc.EKycResponse;
import in.gov.cca.esign.model.xml.ekyc.SecondFactorRequest;
import in.gov.cca.esign.service.EKycService;
import in.gov.cca.esign.util.XmlUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/ekyc")
@RequiredArgsConstructor
public class EKycController {

    private final EKycService ekycService;
    private final XmlUtils xmlUtils;

    @PostMapping(value = "/auth", consumes = {MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_PLAIN_VALUE}, produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> authenticate(@RequestBody String requestXml, HttpServletRequest request) {
        log.info("Received eKYC auth request from IP: {}", getClientIp(request));

        try {
            EKycRequest ekycRequest = xmlUtils.unmarshal(requestXml, EKycRequest.class);
            String espSignature = extractEspSignature(requestXml);

            EKycResponse response = ekycService.authenticateUser(ekycRequest, requestXml, espSignature);
            String responseXml = xmlUtils.marshal(response);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_XML)
                    .body(responseXml);

        } catch (Exception e) {
            log.error("Error processing eKYC auth request", e);
            EKycResponse errorResponse = buildErrorResponse(e.getMessage());
            return ResponseEntity.status(400)
                    .contentType(MediaType.APPLICATION_XML)
                    .body(xmlUtils.marshal(errorResponse));
        }
    }

    @PostMapping(value = "/auth/second-factor", consumes = {MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_PLAIN_VALUE}, produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> authenticateSecondFactor(@RequestBody String requestXml, HttpServletRequest request) {
        log.info("Received eKYC second factor auth request");

        try {
            SecondFactorRequest secondFactorRequest = xmlUtils.unmarshal(requestXml, SecondFactorRequest.class);

            EKycResponse response = ekycService.authenticateSecondFactor(secondFactorRequest,
                    secondFactorRequest.getTransactionId());
            String responseXml = xmlUtils.marshal(response);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_XML)
                    .body(responseXml);

        } catch (Exception e) {
            log.error("Error processing second factor auth", e);
            EKycResponse errorResponse = buildErrorResponse(e.getMessage());
            return ResponseEntity.status(400)
                    .contentType(MediaType.APPLICATION_XML)
                    .body(xmlUtils.marshal(errorResponse));
        }
    }

    @PostMapping(value = "/bank-kyc", consumes = {MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_PLAIN_VALUE}, produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> bankKyc(@RequestBody String requestXml, HttpServletRequest request) {
        log.info("Received Bank KYC request from IP: {}", getClientIp(request));

        // In real implementation, process Bank KYC request
        return ResponseEntity.ok("<BankKYCResp ver=\"1.0\" status=\"1\" resCode=\"BANK_KYC_001\"/>");
    }

    @PostMapping(value = "/public-key/register", consumes = {MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_PLAIN_VALUE}, produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> registerPublicKey(@RequestBody String requestXml) {
        log.info("Received Public Key registration request");
        // In real implementation, process Public Key registration
        return ResponseEntity.ok("<PublicKeyRegResp status=\"1\"/>");
    }

    private String extractEspSignature(String xml) {
        int start = xml.indexOf("<Signature>") + 11;
        int end = xml.indexOf("</Signature>");
        if (start > 11 && end > start) {
            return xml.substring(start, end).trim();
        }
        return "";
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private EKycResponse buildErrorResponse(String message) {
        return EKycResponse.builder()
                .version("3.3")
                .status("0")
                .timestamp(java.time.ZonedDateTime.now().toString())
                .error(message)
                .build();
    }
}