package com.wsd.docx_conversion_wrapper_microservice.controllers;

import com.github.f4b6a3.ulid.UlidCreator;
import com.wsd.docx_conversion_wrapper_microservice.dto.requestsDTO.FileUploadRequestDTO;
import com.wsd.docx_conversion_wrapper_microservice.services.IDocxPreprocessingService;
import com.wsd.docx_conversion_wrapper_microservice.services.IFileUploadService;
import com.wsd.docx_conversion_wrapper_microservice.services.IMinioService;
import com.wsd.docx_conversion_wrapper_microservice.utils.ApiResponseUtil;
import com.wsd.docx_conversion_wrapper_microservice.dto.responsesDTO.ApiResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import reactor.core.publisher.Mono;


@RequiredArgsConstructor
@RestController
@RequestMapping("api/v1/")
public class DocxController {

    private static final Logger logger = LoggerFactory.getLogger(DocxController.class);
    private final IDocxPreprocessingService docxPreprocessingService;
    private final IMinioService minioService;
    private final IFileUploadService fileUploadService;


    @GetMapping("/health")
    public ResponseEntity<ApiResponseDTO<?>> HealthCheck(HttpServletRequest request) {
        logger.warn("Task performed successfully.");
        ApiResponseDTO<?> responseDTO = ApiResponseUtil.success(null, "Health Check is done", request.getRequestURI());
        return new ResponseEntity<>(responseDTO, HttpStatus.OK);
    }

    @PostMapping(value = "/upload2", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Mono<ResponseEntity<String>> uploadFile(@RequestParam("file") MultipartFile file) {
        return fileUploadService.uploadAndProcessFile(file)
                .then(minioService.uploadFile("original-files", file))
                .then(Mono.just(ResponseEntity.ok("File uploaded, processed, and stored in MinIO successfully.")))
                .onErrorResume(error -> {
                    return Mono.just(ResponseEntity.status(500).body("An error occurred: " + error.getMessage()));
                });
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponseDTO<?>> handleFileUpload(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
        ApiResponseDTO<?> responseDTO;
        System.out.println("ok");
        try {
            minioService.uploadFile("original-files", file);
//            System.out.println(fileUrl);
            docxPreprocessingService.downloadFileWithNoParams(file);
            responseDTO = ApiResponseUtil.success(null, "success", request.getRequestURI());
            return new ResponseEntity<>(responseDTO, HttpStatus.CREATED);
        } catch (Exception ex) {
            responseDTO = ApiResponseUtil.error(ex.getLocalizedMessage(), ex.getMessage(), 1001, request.getRequestURI());
            return new ResponseEntity<>(responseDTO, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    //    @PostMapping(value = "/convert", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    @PostMapping(value = "/convert")
    public ResponseEntity<ApiResponseDTO<?>> conversionService(
            @RequestBody FileUploadRequestDTO requestDAO,
            @RequestPart("file") MultipartFile file,
            HttpServletRequest httpServletRequest) {
        ApiResponseDTO<?> responseDTO;
        HttpHeaders httpHeaders = new HttpHeaders();
        try {
            if (requestDAO.getZipFileName().isEmpty()) {
                requestDAO.setZipFileName("EdgarDefault.zip");
            }
            requestDAO.setZipFileName(UlidCreator.getMonotonicUlid().toString() + "-" + requestDAO.getZipFileName());
            if (!requestDAO.getZipFileName().endsWith(".zip")) {
                requestDAO.setZipFileName(requestDAO.getZipFileName() + ".zip");
            }

            httpHeaders.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            httpHeaders.setContentDispositionFormData("attachment", requestDAO.getZipFileName());
            // logic goes here
            minioService.uploadFile("original-files", file);
            
            // return statement
            logger.info("converted successfully.");
            responseDTO = ApiResponseUtil.success(requestDAO, "success", httpServletRequest.getRequestURI());
            logger.info("converted successfully-2" + requestDAO.getZipFileName());
        } catch (Exception ex) {
            logger.error("conversion didn't happen");
            responseDTO = ApiResponseUtil.error(ex.getLocalizedMessage(), ex.getMessage(), 1001, httpServletRequest.getRequestURI());

        }
//        return new ResponseEntity<>(responseDTO, httpHeaders, HttpStatus.OK);
        return new ResponseEntity<>(responseDTO, HttpStatus.OK);
    }
}

