package com.wsd.docx_conversion_wrapper_microservice.controllers;

import com.wsd.docx_conversion_wrapper_microservice.dto.requestsDTO.UserCreationDTO;
import com.wsd.docx_conversion_wrapper_microservice.dto.responsesDTO.ApiResponseDTO;
import com.wsd.docx_conversion_wrapper_microservice.serviceImplementors.KeycloakAdminServiceImpl;
import com.wsd.docx_conversion_wrapper_microservice.utils.ApiResponseUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/secured/")
@SecurityRequirement(name = "BearerAuth")
public class UserController {

    private final KeycloakAdminServiceImpl keycloakAdminService;

    public UserController(KeycloakAdminServiceImpl keycloakAdminService) {
        this.keycloakAdminService = keycloakAdminService;
    }

    @PostMapping("create-user")
    @PreAuthorize("hasRole('client_admin')")
    @Operation(
            summary = "Create a new User in Keycloak",
            description = "This endpoint allows clients to create a new User in Keycloak.",
            responses = {
                    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "201", description = "User created successfully"),
                    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Bad Request"),
                    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "500", description = "Internal Server Error")
            }
    )
    public ResponseEntity<ApiResponseDTO<?>> createUser(@RequestBody UserCreationDTO userCreationDTO, HttpServletRequest httpServletRequest) {
        ApiResponseDTO<?> responseDTO;

        String userId = keycloakAdminService.createUser(
                userCreationDTO.getUsername(),
                userCreationDTO.getPassword(),
                userCreationDTO.getEmail(),
                userCreationDTO.getRoleName(),
                userCreationDTO.getFirstName(),
                userCreationDTO.getLastName());
        if (!userId.isBlank()) {
            responseDTO = ApiResponseUtil.success(userId, "User created successfully", httpServletRequest.getRequestURI());
            return new ResponseEntity<>(responseDTO, HttpStatus.CREATED);
        } else {
            responseDTO = ApiResponseUtil.error("Cause of Error Unknown", "Could not create User", 400, httpServletRequest.getRequestURI());
            return new ResponseEntity<>(responseDTO, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
