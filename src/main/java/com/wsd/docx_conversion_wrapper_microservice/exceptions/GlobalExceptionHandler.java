package com.wsd.docx_conversion_wrapper_microservice.exceptions;

import com.wsd.docx_conversion_wrapper_microservice.utils.ApiResponseUtil;
import com.wsd.docx_conversion_wrapper_microservice.dto.responsesDTO.ApiResponseDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Arrays;
import java.util.List;

@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> handleAccessDeniedException(AccessDeniedException ex, WebRequest request) {
        ApiResponseDTO<?> apiResponseDTO = ApiResponseUtil.error(
                "Access is denied",
                ex.getMessage(),
                403,
                request.getContextPath()
        );
        return new ResponseEntity<>(apiResponseDTO, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<?> handleAuthenticationException(AuthenticationException ex, WebRequest request) {
        ApiResponseDTO<?> apiResponseDTO = ApiResponseUtil.error(
                "Authentication failed",
                ex.getMessage(),
                401,
                request.getContextPath()
        );
        return new ResponseEntity<>(apiResponseDTO, HttpStatus.UNAUTHORIZED);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGlobalException(Exception ex, WebRequest request) {
        List<String> errors = Arrays.asList(ex.getMessage());
        ApiResponseDTO<?> apiResponseDTO = ApiResponseUtil.error(
                errors,
                ex.getMessage(),
                100,
                request.getContextPath());
        return new ResponseEntity<>(apiResponseDTO, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // rest of the exceptions would be handled here

}
