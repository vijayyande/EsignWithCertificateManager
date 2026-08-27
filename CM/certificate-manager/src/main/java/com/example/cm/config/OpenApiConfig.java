package com.example.cm.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI cmOpenAPI() {
        String securitySchemeName = "basicAuth";
        return new OpenAPI()
                .info(new Info()
                        .title("Certificate Manager API")
                        .version("1.0.0")
                        .description("REST API for the Certificate Manager platform. "
                                + "Provides CA management, certificate issuance (CSR and manual), "
                                + "CRL and OCSP services, certificate profiles, user management, "
                                + "and a signed audit trail.\n\n"
                                + "**Authentication:** HTTP Basic with username and password. "
                                + "Admin endpoints require the ADMIN role. "
                                + "CSR and certificate request endpoints require the REQUESTER or ADMIN role.")
                        .contact(new Contact()
                                .name("Certificate Manager")
                                .url("https://github.com/example/cm")))
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(new Components()
                        .addSecuritySchemes(securitySchemeName,
                                new SecurityScheme()
                                        .name(securitySchemeName)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("basic")
                                        .description("HTTP Basic authentication. "
                                                + "Use admin/admin123 for admin access, "
                                                + "requester/requester123 for certificate requests.")));
    }
}
