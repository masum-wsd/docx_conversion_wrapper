package com.wsd.docx_conversion_wrapper_microservice.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;


import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${local_keycloak.clientId}")
    private String clientId;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    public static String[] PUBLIC_URLS = {
            "/v1/wsd/**",
            "/v1/spring-boot-app/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/public/**",
            "/actuator/**",
            "/websocket"
    };
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // As for OAuth2 Resource Server
                .cors(Customizer.withDefaults());
//                .headers(headers -> headers
//                        .contentSecurityPolicy(csp -> csp
//                                .policyDirectives("default-src 'self'; script-src 'self'; object-src 'none';")
//                        )
//                        .xssProtection(HeadersConfigurer.XXssConfig::disable  // XSS protection header is automatically handled by modern browsers; disable it explicitly if not needed
//                        )
//                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny // Prevents clickjacking by blocking all framing
//                        )
//                        .httpStrictTransportSecurity(hsts -> hsts
//                                .maxAgeInSeconds(31536000)  // Sets the HSTS max-age directive
//                                .includeSubDomains(true)    // Applies HSTS to all subdomains
//                        )
//                        .referrerPolicy(referrer -> referrer
//                                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE) // Sets the referrer policy
//                        )
//                        .contentTypeOptions(withDefaults())  // Prevents MIME-type sniffing
//                        .permissionsPolicy(permissions -> permissions
//                                .policy("geolocation=(self), microphone=(), camera=()") // Controls feature permissions
//                        )
//                );

        // This is the main portion for authorizing
        http
//                .authorizeHttpRequests(authorizeRequests ->
//                        authorizeRequests
//                                .requestMatchers("/api/v1/**").authenticated() // Only require authentication for this path
//                                .requestMatchers("/api/v1/secured/**").hasRole("client_admin") // Role-based authorization
//                                .anyRequest().permitAll() // All other endpoints are publicly accessible
//                )
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry.requestMatchers(PUBLIC_URLS).permitAll()
                                .anyRequest().authenticated()

                )
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer.jwt(jwtConfigurer -> jwtConfigurer
                                .jwtAuthenticationConverter(jwtAuthenticationConverter()) // Set custom role converter
                        )
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Stateless session management
                );

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter(clientId));
        return jwtAuthenticationConverter;
    }



//    @Bean
//    public RoleHierarchy roleHierarchy() {
//        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
//        hierarchy.setHierarchy("ROLE_EDGAR_ADMIN > ROLE_EDGAR_FILING_MANAGER > ROLE_EDGAR_BARCLAYS_TEAM_LEAD > ROLE_EDGAR_BARCLAYS_ASST_TEAM_LEAD > ROLE_EDGAR_FILING_MEMBER > ROLE_EDGAR_USER");
//        return hierarchy;
//    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        String hierarchy = buildRoleHierarchy();
        roleHierarchy.setHierarchy(hierarchy);
        return roleHierarchy;
    }

    private String buildRoleHierarchy() {
        StringBuilder hierarchyBuilder = new StringBuilder();

        // Super Admin has access to Admin, reason is: Admin will not have payment related permissions, its only reserve for super admin 
        hierarchyBuilder.append("ROLE_EDGAR_SUPER_ADMIN > ROLE_EDGAR_ADMIN\n");
        
        // Admin has access to Filing Manager, admin is responsible for filing + mailing + status updates  
        hierarchyBuilder.append("ROLE_EDGAR_ADMIN > ROLE_EDGAR_FILING_MANAGER\n");

        // Filing Manager has access to all Team Leads, he/she is responsible for only filing related stuffs
        hierarchyBuilder.append("ROLE_EDGAR_FILING_MANAGER > ROLE_EDGAR_BARCLAYS_TEAM_LEAD\n");
        hierarchyBuilder.append("ROLE_EDGAR_FILING_MANAGER > ROLE_EDGAR_CITI_TEAM_LEAD\n");

        // Barclays branch hierarchy
        hierarchyBuilder.append("ROLE_EDGAR_BARCLAYS_TEAM_LEAD > ROLE_EDGAR_BARCLAYS_ASSISTANT_TEAM_LEAD\n");
        hierarchyBuilder.append("ROLE_EDGAR_BARCLAYS_ASSISTANT_TEAM_LEAD > ROLE_EDGAR_BARCLAYS_FILING_MEMBER\n");

        // Citi branch hierarchy
        hierarchyBuilder.append("ROLE_EDGAR_CITI_TEAM_LEAD > ROLE_EDGAR_CITI_ASSISTANT_TEAM_LEAD\n");
        hierarchyBuilder.append("ROLE_EDGAR_CITI_ASSISTANT_TEAM_LEAD > ROLE_EDGAR_CITI_FILING_MEMBER\n");

        // Lowest access role (ROLE_USER), which is like a guest for us or like client for us
        hierarchyBuilder.append("ROLE_EDGAR_SUPER_ADMIN > ROLE_USER\n");
        hierarchyBuilder.append("ROLE_EDGAR_ADMIN > ROLE_USER\n");
        hierarchyBuilder.append("ROLE_EDGAR_FILING_MANAGER > ROLE_USER\n");
        hierarchyBuilder.append("ROLE_EDGAR_BARCLAYS_TEAM_LEAD > ROLE_USER\n");
        hierarchyBuilder.append("ROLE_EDGAR_BARCLAYS_ASSISTANT_TEAM_LEAD > ROLE_USER\n");
        hierarchyBuilder.append("ROLE_EDGAR_BARCLAYS_FILING_MEMBER > ROLE_USER\n");
        hierarchyBuilder.append("ROLE_EDGAR_CITI_TEAM_LEAD > ROLE_USER\n");
        hierarchyBuilder.append("ROLE_EDGAR_CITI_ASSISTANT_TEAM_LEAD > ROLE_USER\n");
        hierarchyBuilder.append("ROLE_EDGAR_CITI_FILING_MEMBER > ROLE_USER\n");

        return hierarchyBuilder.toString();
    }
    
    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setRoleHierarchy(roleHierarchy);
        return expressionHandler;
    }
}
