package com.wsd.docx_conversion_wrapper_microservice.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;

public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String clientId;

    public KeycloakRoleConverter(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        return extractRoles(jwt); // Call the extractRoles method here to process the JWT
    }

    private Collection<GrantedAuthority> extractRoles(Jwt jwt) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        // Extract realm-level roles
        if (jwt.getClaim("realm_access") != null) {
            var realmAccess = (Map<String, Object>) jwt.getClaim("realm_access");
            List<String> realmRoles = (List<String>) realmAccess.get("roles");
            if (realmRoles != null) {
                grantedAuthorities.addAll(realmRoles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                        .collect(Collectors.toList()));
            }
        }

        // Extract client-level roles from resource_access
        var resourceAccess = jwt.getClaimAsMap("resource_access");
        if (resourceAccess != null && resourceAccess.containsKey(clientId)) {
            var clientRoles = (Map<String, Object>) resourceAccess.get(clientId);
            var roles = (List<String>) clientRoles.get("roles");
            if (roles != null) {
                grantedAuthorities.addAll(roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                        .collect(Collectors.toList()));
            }
        }

        return grantedAuthorities;
    }
}
