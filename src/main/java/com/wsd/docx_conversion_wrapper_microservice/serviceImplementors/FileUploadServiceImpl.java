package com.wsd.docx_conversion_wrapper_microservice.serviceImplementors;

import com.wsd.docx_conversion_wrapper_microservice.services.IFileUploadService;
import com.wsd.docx_conversion_wrapper_microservice.services.IFileValidationService;
import com.wsd.docx_conversion_wrapper_microservice.services.IMinioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import org.springframework.mock.web.MockMultipartFile;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

@Service
public class FileUploadServiceImpl implements IFileUploadService {
    private final WebClient webClient;
    private final IFileValidationService fileValidationService;
    private final IMinioService minioService;

    @Autowired
    public FileUploadServiceImpl(WebClient webClient, IFileValidationService fileValidationService, IMinioService minioService) {
        this.webClient = webClient;
        this.fileValidationService = fileValidationService;
        this.minioService = minioService;
    }

    @Override
    public Mono<Void> uploadAndProcessFile(MultipartFile file) {
//        if (!fileValidationService.isValidFile(file)) {
//            return Mono.error(new RuntimeException("Invalid file type or size."));
//        }

        return uploadFile(file)
                .flatMap(fetchedFile -> fileToMultipartFile(fetchedFile)
                        .flatMap(multipartFile -> minioService.uploadFile("pre-processed-files", multipartFile)
                                .then(Mono.just(fetchedFile)))) // Store fetched file in MinIO
                .flatMap(this::processFile) // Process the file into a zip
                .flatMap(zipFile -> fileToMultipartFile(zipFile) // Convert processed zip to MultipartFile
                        .flatMap(multipartFile -> minioService.uploadFile("zipped-files", multipartFile))) // Store resulting ZIP file in MinIO
                .onErrorContinue((throwable, f) -> System.err.println("Error processing file: " + throwable.getMessage()))
                .then();
    }

    private Mono<File> uploadFile(MultipartFile file) {
        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", new ByteArrayResource(file.getBytes()) {
                        @Override
                        public String getFilename() {
                            return file.getOriginalFilename();
                        }
                    })
                    .contentType(MediaType.parseMediaType(file.getContentType()));

            return webClient.post()
                    .uri("http://localhost:5000/api/v1/http/apply-all-conversion") // URL to your ASP.NET Core endpoint
                    .contentType(MediaType.MULTIPART_FORM_DATA) // Set content type explicitly
                    .bodyValue(bodyBuilder.build()) // Pass the built MultiValueMap as the body
                    .retrieve()
                    .bodyToMono(byte[].class) // Expecting the ASP.NET Core API to return a file as byte array
                    .flatMap(this::saveFetchedFile); // Save the fetched file locally and return a Mono<File>
        } catch (IOException e) {
            return Mono.error(new RuntimeException("Error preparing file for upload: " + e.getMessage()));
        }
    }

    private MultipartBodyBuilder buildMultipartBody(MultipartFile file) {
        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", new ByteArrayResource(file.getBytes()) {
                        @Override
                        public String getFilename() {
                            return file.getOriginalFilename();
                        }
                    })
                    .contentType(MediaType.parseMediaType(file.getContentType()));
            return bodyBuilder;
        } catch (IOException e) {
            throw new RuntimeException("Error building multipart body: " + e.getMessage());
        }
    }

    private Mono<File> saveFetchedFile(byte[] fileContent) {
        return Mono.fromCallable(() -> {
            File savedFile = new File("processed_file.docx"); // Define the path and name for the saved file
            try (FileOutputStream fos = new FileOutputStream(savedFile)) {
                fos.write(fileContent);
                System.out.println("Fetched file saved locally: " + savedFile.getAbsolutePath());
                return savedFile;
            } catch (IOException e) {
                throw new RuntimeException("Error saving fetched file: " + e.getMessage());
            }
        });
    }

    private Mono<File> processFile(File file) {
        return Mono.fromCallable(() -> {
            File zipFile = new File("processed_file.zip");
            try (FileOutputStream fos = new FileOutputStream(zipFile)) {
                fos.write("Dummy Zip Content".getBytes()); // Replace with actual content
            } catch (IOException e) {
                throw new RuntimeException("Error creating zip file: " + e.getMessage());
            }

            System.out.println("Processed ZIP file created: " + zipFile.getAbsolutePath());
            return zipFile;
        });
    }

    private Mono<MultipartFile> fileToMultipartFile(File file) {
        return Mono.fromCallable(() -> {
            try (FileInputStream fis = new FileInputStream(file)) {
                return new MockMultipartFile(file.getName(), file.getName(), MediaType.APPLICATION_OCTET_STREAM_VALUE, fis);
            } catch (IOException e) {
                throw new RuntimeException("Error converting file to MultipartFile: " + e.getMessage());
            }
        });
    }
}
