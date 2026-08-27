package in.gov.cca.esign.util;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

public interface TokenStore {

    void put(String key, String value, long ttl, TimeUnit unit);

    Optional<String> get(String key);

    Optional<String> getAndDelete(String key);

    void delete(String key);
}