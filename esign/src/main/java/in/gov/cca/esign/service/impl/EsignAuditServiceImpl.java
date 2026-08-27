package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.domain.EsignAuditLog;
import in.gov.cca.esign.repository.EsignAuditLogRepository;
import in.gov.cca.esign.service.EsignAuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class EsignAuditServiceImpl implements EsignAuditService {

    private static final int MAX_STORED_XML_CHARS = 20_000;
    private static final int RESPONSE_SNIPPET_LEN = 400;

    private static final Pattern TXN_ATTR = attrPattern("txn");
    private static final Pattern ASP_ATTR = attrPattern("aspId");
    private static final Pattern SIGNER_ATTR = attrPattern("signerid");
    private static final Pattern STATUS_ATTR = attrPattern("status");
    private static final Pattern ERROR_ATTR = attrPattern("error");

    private final EsignAuditLogRepository auditLogRepository;

    @Override
    public void record(EsignAuditLog.RequestType type, String rawRequest, String responseXml,
                       int httpStatus, String remoteIp) {
        // Deliberately NOT joining an outer transaction: repository.save() runs in
        // its own short transaction so constraint violations surface synchronously
        // inside the catch below instead of at some caller's commit time.
        try {
            String request = rawRequest == null ? "" : rawRequest;
            EsignAuditLog.EsignAuditLogBuilder builder = EsignAuditLog.builder()
                    .endpoint(type)
                    .transactionId(truncate(attr(request, TXN_ATTR), 100))
                    .aspId(truncate(attr(request, ASP_ATTR), 100))
                    .signerId(truncate(attr(request, SIGNER_ATTR), 200))
                    .remoteIp(remoteIp)
                    .httpStatus(httpStatus)
                    .documentCount(countDocuments(request))
                    .requestBytes(request.getBytes(java.nio.charset.StandardCharsets.UTF_8).length)
                    .responseSnippet(truncate(responseXml, RESPONSE_SNIPPET_LEN))
                    .requestXml(truncate(request, MAX_STORED_XML_CHARS));

            applyOutcome(builder, responseXml, httpStatus);
            auditLogRepository.save(builder.build());
        } catch (Exception ex) {
            log.error("Failed to persist eSign audit log for {}", type, ex);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Page<EsignAuditLog> search(String q, EsignAuditLog.RequestType type,
                                      EsignAuditLog.Outcome outcome,
                                      java.time.LocalDateTime from,
                                      java.time.LocalDateTime to, int page, int size) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 200));
        String query = (q == null || q.isBlank()) ? null : q.trim();
        return auditLogRepository.search(query, type, outcome,
                from, to, pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public java.util.Optional<EsignAuditLog> findById(java.util.UUID id) {
        return auditLogRepository.findById(id);
    }
    private void applyOutcome(EsignAuditLog.EsignAuditLogBuilder builder,
                              String responseXml, int httpStatus) {
        String statusAttr = attr(responseXml, STATUS_ATTR);
        String errorAttr = attr(responseXml, ERROR_ATTR);
        if (!errorAttr.isBlank()) {
            // Numeric CCA error codes are <=3 chars; anything longer is a free-text
            // message (e.g. unmarshal failures) and belongs in errorMessage instead.
            if (errorAttr.length() <= 10) {
                builder.outcome(EsignAuditLog.Outcome.REJECTED).errorCode(errorAttr);
            } else {
                builder.outcome(EsignAuditLog.Outcome.REJECTED)
                        .errorMessage(truncate(errorAttr, 500));
            }
        } else if ("1".equals(statusAttr)) {
            builder.outcome(EsignAuditLog.Outcome.SUCCESS);
        } else if ("2".equals(statusAttr)) {
            builder.outcome(EsignAuditLog.Outcome.PENDING);
        } else if (httpStatus >= 400) {
            builder.outcome(EsignAuditLog.Outcome.ERROR)
                    .errorMessage(truncate(firstLine(responseXml), 500));
        } else {
            builder.outcome(EsignAuditLog.Outcome.SUCCESS);
        }
    }

    private int countDocuments(String requestXml) {
        if (requestXml == null) {
            return 0;
        }
        int count = 0;
        int idx = 0;
        while ((idx = requestXml.indexOf("<InputHash", idx)) != -1) {
            count++;
            idx += 10;
        }
        return count;
    }

    private static Pattern attrPattern(String name) {
        return Pattern.compile(name + "=\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);
    }

    private String attr(String xml, Pattern pattern) {
        if (xml == null) {
            return "";
        }
        Matcher matcher = pattern.matcher(xml);
        return matcher.find() ? matcher.group(1) : "";
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    private String firstLine(String text) {
        if (text == null) {
            return "";
        }
        int nl = text.indexOf('\n');
        String line = nl > 0 ? text.substring(0, nl) : text;
        return line.length() > 300 ? line.substring(0, 300) : line;
    }
}
