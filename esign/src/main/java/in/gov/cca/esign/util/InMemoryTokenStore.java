package in.gov.cca.esign.util;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Component
@ConditionalOnProperty(name = "esign.token-store", havingValue = "memory", matchIfMissing = true)
public class InMemoryTokenStore implements TokenStore {

    private final Map<String, ExpiringValue> store = new ConcurrentHashMap<>();

    @Override
    public void put(String key, String value, long ttl, TimeUnit unit) {
        purge();
        store.put(key, new ExpiringValue(value, System.currentTimeMillis() + unit.toMillis(ttl)));
    }

    @Override
    public Optional<String> get(String key) {
        purge();
        ExpiringValue v = store.get(key);
        return v == null ? Optional.empty() : Optional.of(v.value());
    }

    @Override
    public synchronized Optional<String> getAndDelete(String key) {
        purge();
        ExpiringValue v = store.remove(key);
        return v == null ? Optional.empty() : Optional.of(v.value());
    }

    @Override
    public void delete(String key) {
        store.remove(key);
    }

    private void purge() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, ExpiringValue>> it = store.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().expiresAt() <= now) {
                it.remove();
            }
        }
    }

    private record ExpiringValue(String value, long expiresAt) {
        boolean expired() {
            return expiresAt <= System.currentTimeMillis();
        }
    }
}