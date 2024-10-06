package com.wsd.docx_conversion_wrapper_microservice.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.cglib.core.Local;

@OpenAPIDefinition(
        info = @Info(
                title = "Just One Microservice",
                version = "0.0.1-SNAPSHOT",
                description = "This is a simple microservice for converting DOCX files to ZIP File",
                contact = @Contact(
                        name = "Abdullah Al Masum",
                        email = "abdullahmasum6035@gmail.com",
                        url = "https://masum035.bio.link")
        ),
        servers = {
                @Server(
                        description = "local env",
                        url = "http://localhost:8080"
                ),
                @Server(
                        description = "staging env",
                        url = "http://staging-server.com"
                ),
                @Server(
                        description = "pre-prod env",
                        url = "http://pre-production-server.com"
                )
        }

)
@SecurityScheme(
        name = "BearerAuth",
        description = "JWT Bearer token authentication From Keycloak",
        in = SecuritySchemeIn.HEADER,
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT"
)
public class OpenApiConfig {
}
