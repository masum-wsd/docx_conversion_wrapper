package com.wsd.docx_conversion_wrapper_microservice.controllers;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/api/poc")
@SecurityRequirement(name = "Bearer_Authentication")
public class PocController {
    
    @GetMapping("/admin")
    @PreAuthorize("hasRole('EDGAR_ADMIN')")
    public ResponseEntity<String> admin_privilege(){
        Jwt principal = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok("Hello " + principal.getClaims().get("preferred_username"));
    }

    @GetMapping("/team_lead")
    @PreAuthorize("hasRole('EDGAR_BARCLAYS_TEAM_LEAD')")
    public ResponseEntity<String> team_lead_privilege(){
        Jwt principal = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok("Hello " + principal.getClaims().get("preferred_username"));
    }

    @GetMapping("/asst_team_lead")
    @PreAuthorize("hasRole('EDGAR_BARCLAYS_ASSISTANT_TEAM_LEAD')")
    public ResponseEntity<String> asst_team_lead_privilege(){
        Jwt principal = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok("Hello " + principal.getClaims().get("preferred_username"));
    }
    
    @GetMapping("/filing_member")
    @PreAuthorize("hasRole('EDGAR_BARCLAYS_FILING_MEMBER')")
    public ResponseEntity<String> filing_member_privilege(){
        Jwt principal = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok("Hello " + principal.getClaims().get("preferred_username"));
    }
    
}
