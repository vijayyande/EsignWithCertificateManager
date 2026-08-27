package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.util.TokenStore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
@ConditionalOnProperty(name = "esign.token-store", havingValue = "redis")
public class RedisTokenStore implements TokenStore {

    private final StringRedisTemplate redisTemplate;

    public RedisTokenStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void put(String key, String value, long ttl, TimeUnit unit) {
        redisTemplate.opsForValue().set(key, value, ttl, unit);
    }

    @Override
    public Optional<String> get(String key) {
        return Optional.ofNullable(redisTemplate.opsForValue().get(key));
    }

    @Override
    public Optional<String> getAndDelete(String key) {
        String v = redisTemplate.opsForValue().getAndDelete(key);
        return Optional.ofNullable(v);
    }

    @Override
    public void delete(String key) {
        redisTemplate.delete(key);
    }
}