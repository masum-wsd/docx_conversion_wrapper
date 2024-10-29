package com.wsd.docx_conversion_wrapper_microservice;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableAsync
@EnableWebSecurity
@EnableMethodSecurity
public class DocxConversionWrapperApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(DocxConversionWrapperApplication.class, args);
    }

}
