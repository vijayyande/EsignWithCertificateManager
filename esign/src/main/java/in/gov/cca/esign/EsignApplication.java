package in.gov.cca.esign;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@EntityScan(basePackages = "in.gov.cca.esign.domain")
@EnableJpaRepositories(basePackages = "in.gov.cca.esign.repository")
@ComponentScan(basePackages = "in.gov.cca.esign")
@EnableAsync
@EnableTransactionManagement
public class EsignApplication {

    public static void main(String[] args) {
        SpringApplication.run(EsignApplication.class, args);
    }
}