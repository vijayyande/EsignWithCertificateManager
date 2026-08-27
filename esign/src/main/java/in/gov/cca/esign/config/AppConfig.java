package in.gov.cca.esign.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.web.client.RestTemplate;

import java.security.KeyStore;

@Configuration
public class AppConfig {

    private final ResourceLoader resourceLoader;

    public AppConfig(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    /**
     * Dedicated client for the external CA enrollment endpoint
     * (settings under {@code ca.*} in application.yml).
     */
    @Bean
    public RestTemplate caRestTemplate(
            @Value("${ca.connect-timeout-ms:5000}") int connectTimeoutMs,
            @Value("${ca.read-timeout-ms:15000}") int readTimeoutMs) {
        org.springframework.http.client.SimpleClientHttpRequestFactory factory =
                new org.springframework.http.client.SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(connectTimeoutMs);
        factory.setReadTimeout(readTimeoutMs);
        return new RestTemplate(factory);
    }

    @Bean
    public KeyStore espKeyStore(
            @Value("${esign.keystore.path:}") String path,
            @Value("${esign.keystore.password:changeit}") String password,
            @Value("${esign.keystore.type:PKCS12}") String type) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type);
        if (path == null || path.isBlank()) {
            keyStore.load(null, null);
        } else {
            Resource resource = resourceLoader.getResource(path);
            try (java.io.InputStream in = resource.getInputStream()) {
                keyStore.load(in, password.toCharArray());
            }
        }
        return keyStore;
    }
}