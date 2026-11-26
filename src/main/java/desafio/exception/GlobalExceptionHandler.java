package desafio.exception;

import desafio.dto.ErrorResponse;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;

import java.time.Instant;

/**
 * Serviço responsável por converter exceções de execução em objetos de resposta http
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private final Logger log;

    public GlobalExceptionHandler(Logger log) {
        this.log = log;
    }

    @ExceptionHandler({InvalidInputException.class, InvalidKeystoreException.class})
    public ResponseEntity<ErrorResponse> badRequest(RuntimeException e) {
        log.warn("Invalid request input or keystore: {}", e.getMessage());
        return build(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorResponse> tooLarge(MaxUploadSizeExceededException e) {
        log.warn("Uploaded file exceeded maximum allowed size: {}", e.getMessage());
        return build(HttpStatus.PAYLOAD_TOO_LARGE, "Request file exceeds size limit.");
    }

    @ExceptionHandler(MultipartException.class)
    public ResponseEntity<ErrorResponse> notMultipart(MultipartException e) {
        log.warn("Malformed multipart request: {}", e.getMessage());
        return build(HttpStatus.BAD_REQUEST, "The http request must contain a valid multipart/form-data.");
    }

    @ExceptionHandler(SignatureProcessingException.class)
    public ResponseEntity<ErrorResponse> processing(SignatureProcessingException e) {
        log.error("Cryptographic processing failure.", e);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Error while processing signature.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> fallback(Exception e) {
        if (e instanceof org.springframework.web.ErrorResponse springError) {
            log.warn("HTTP error ({}): {}", springError.getStatusCode(), e.getMessage());
            return build(springError.getStatusCode(), e.getMessage());
        }
        log.error("Unhandled internal server error.", e);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error.");
    }

    private static ResponseEntity<ErrorResponse> build(HttpStatusCode code, String message) {
        HttpStatus status = HttpStatus.resolve(code.value());
        String reason = status == null ? "Error" : status.getReasonPhrase();
        return ResponseEntity.status(code).body(new ErrorResponse(Instant.now(), code.value(), reason, message));
    }
}