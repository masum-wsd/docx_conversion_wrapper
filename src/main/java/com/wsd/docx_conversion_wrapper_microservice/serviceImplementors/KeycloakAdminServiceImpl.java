package com.wsd.docx_conversion_wrapper_microservice.serviceImplementors;

import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class KeycloakAdminServiceImpl {
    private final Keycloak keycloak;

    public KeycloakAdminServiceImpl() {
        this.keycloak = KeycloakBuilder.builder()
                .serverUrl("http://localhost:8081")
                .realm("testrealm")
                .grantType(OAuth2Constants.PASSWORD)
                .clientId("admin-cli")
                .username("keycloak_admin")
                .password("keycloak_password")
                .build();
    }

    public String createUser(String username, String password, String email, String roleName, String firstName, String lastName) {

        RealmResource realmResource = keycloak.realm("testrealm");
//        realmResource.users().list();
        
        // Create user representation
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEnabled(true);

        // Set user credentials
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);
        user.setCredentials(Collections.singletonList(credential));

        // Create user
        try (Response response = realmResource.users().create(user)) {

            if (response.getStatus() == 201) {
                String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                assignClientRolesToUser(realmResource, userId, "edgar-wrapper-api", "client_admin", "client_user");
                return userId;
            } else {
                throw new RuntimeException("Failed to create user");
            }
        }
    }

    private void assignClientRolesToUser(RealmResource realmResource, String userId, String clientId, String... roles) {
        // Find client
        ClientRepresentation clientRepresentation = realmResource.clients().findByClientId(clientId).get(0);
        ClientResource clientResource = realmResource.clients().get(clientRepresentation.getId());

        // Fetch the user
        UserResource userResource = realmResource.users().get(userId);

        for (String roleName : roles) {
            // Get role by client role name
            RoleRepresentation role = clientResource.roles().get(roleName).toRepresentation();

            // Assign the client role to the user
            userResource.roles().clientLevel(clientRepresentation.getId()).add(Collections.singletonList(role));
        }
    }
    
}
