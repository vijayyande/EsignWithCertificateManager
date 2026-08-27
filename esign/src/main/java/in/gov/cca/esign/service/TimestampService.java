package in.gov.cca.esign.service;

import java.util.Optional;

public interface TimestampService {

    boolean isEnabled();

    Optional<byte[]> embedTimestamp(byte[] cmsSignatureBytes);
}
