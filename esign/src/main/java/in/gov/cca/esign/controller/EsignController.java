package in.gov.cca.esign.controller;

import in.gov.cca.esign.domain.EsignAuditLog;
import in.gov.cca.esign.model.xml.esign.EsignRequest;
import in.gov.cca.esign.model.xml.esign.EsignResponse;
import in.gov.cca.esign.model.xml.esign.EsignStatusRequest;
import in.gov.cca.esign.service.EsignAuditService;
import in.gov.cca.esign.service.EsignService;
import in.gov.cca.esign.util.XmlUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;

@Slf4j
@RestController
@RequestMapping("/esign")
@RequiredArgsConstructor
public class EsignController {

    private final EsignService esignService;
    private final EsignAuditService auditService;
    private final XmlUtils xmlUtils;

    @PostMapping(value = "/request", consumes = {MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_PLAIN_VALUE}, produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> esignRequest(@RequestBody String requestXml, HttpServletRequest request) {
        log.info("Received eSign request from IP: {}", getClientIp(request));
        String remoteIp = getClientIp(request);

        ResponseEntity<String> out;
        try {
            EsignRequest esignRequest = xmlUtils.unmarshal(requestXml, EsignRequest.class);

            // Extract ASP signature from request (in real impl, from Signature element)
            String aspSignature = extractAspSignature(requestXml);

            EsignResponse response = esignService.processEsignRequest(esignRequest, requestXml, aspSignature);

            String responseXml = xmlUtils.marshal(response);
            HttpStatus status = "2".equals(response.getStatus()) ? HttpStatus.ACCEPTED : HttpStatus.OK;

            out = ResponseEntity.status(status)
                    .contentType(MediaType.APPLICATION_XML)
                    .body(responseXml);

        } catch (Exception e) {
            log.error("Error processing eSign request", e);
            EsignResponse errorResponse = buildErrorResponse(e.getMessage());
            out = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .contentType(MediaType.APPLICATION_XML)
                    .body(xmlUtils.marshal(errorResponse));
        }
        auditService.record(EsignAuditLog.RequestType.SIGN, requestXml, out.getBody(),
                out.getStatusCode().value(), remoteIp);
        return out;
    }

    @PostMapping(value = "/status", consumes = {MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_PLAIN_VALUE}, produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> checkStatus(@RequestBody String requestXml, HttpServletRequest request) {
        log.info("Received eSign status check from IP: {}", getClientIp(request));
        String remoteIp = getClientIp(request);

        ResponseEntity<String> out;
        try {
            EsignStatusRequest statusRequest = xmlUtils.unmarshal(requestXml, EsignStatusRequest.class);
            String aspSignature = extractAspSignature(requestXml);

            EsignResponse response = esignService.checkSigningStatus(statusRequest, requestXml, aspSignature);
            String responseXml = xmlUtils.marshal(response);

            out = ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_XML)
                    .body(responseXml);

        } catch (Exception e) {
            log.error("Error checking eSign status", e);
            EsignResponse errorResponse = buildErrorResponse(e.getMessage());
            out = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .contentType(MediaType.APPLICATION_XML)
                    .body(xmlUtils.marshal(errorResponse));
        }
        auditService.record(EsignAuditLog.RequestType.STATUS, requestXml, out.getBody(),
                out.getStatusCode().value(), remoteIp);
        return out;
    }

    @PostMapping(value = "/auth/callback", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<String> authCallback(@RequestParam("txnref") String txnRef,
                                               @RequestParam(value = "signerId", required = false) String signerId,
                                               HttpServletRequest request) {
        log.info("Received auth callback with txnref: {}", txnRef);

        ResponseEntity<String> out;
        try {
            String decoded = new String(java.util.Base64.getDecoder().decode(txnRef));
            String[] parts = decoded.split("\\|", 2);

            if (parts.length != 2) {
                out = ResponseEntity.badRequest().body("Invalid txnref format");
            } else {
                String transactionId = parts[0];
                String responseCode = parts[1];

                EsignResponse esignResponse = esignService.completeSigning(
                        transactionId,
                        signerId != null ? signerId : transactionId,
                        new java.util.Date());

                String redirectUrl = esignService.getTransaction(transactionId).getRedirectUrl();
                if (redirectUrl != null && !redirectUrl.isBlank()) {
                    out = ResponseEntity.status(HttpStatus.FOUND)
                            .header("Location", redirectUrl)
                            .build();
                } else {
                    out = ResponseEntity.ok("Signing completed for transaction: " + transactionId);
                }
            }

        } catch (Exception e) {
            log.error("Error processing auth callback", e);
            out = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Callback processing failed");
        }
        auditService.record(EsignAuditLog.RequestType.AUTH_CALLBACK,
                "txnref=" + txnRef, out.getBody(), out.getStatusCode().value(), getClientIp(request));
        return out;
    }

    @GetMapping("/transaction/{transactionId}")
    public ResponseEntity<EsignResponse> getTransaction(@PathVariable String transactionId) {
        EsignResponse response = esignService.getTransactionResponse(transactionId);
        return ResponseEntity.ok(response);
    }

    private String extractAspSignature(String xml) {
        // Extract Signature element value from XML
        // Simplified - in real implementation use proper XML parsing
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

    private EsignResponse buildErrorResponse(String message) {
        return EsignResponse.builder()
                .version("3.3")
                .status("0")
                .timestamp(java.time.ZonedDateTime.now().toString())
                .error(message)
                .build();
    }
}