package desafio.exception;

import desafio.dto.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;

import java.time.Instant;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler({InvalidInputException.class, InvalidKeystoreException.class})
    public ResponseEntity<ErrorResponse> badRequest(RuntimeException e) {
        return build(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorResponse> tooLarge(MaxUploadSizeExceededException e) {
        return build(HttpStatus.PAYLOAD_TOO_LARGE, "Request file exceeds size limit.");
    }

    @ExceptionHandler(MultipartException.class)
    public ResponseEntity<ErrorResponse> notMultipart(MultipartException e) {
        return build(HttpStatus.BAD_REQUEST, "The http request must contain a valid multipart/form-data.");
    }

    @ExceptionHandler(SignatureProcessingException.class)
    public ResponseEntity<ErrorResponse> processing(SignatureProcessingException e) {
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Error while processing signature.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> fallback(Exception e) {
        if (e instanceof org.springframework.web.ErrorResponse springError) {
            return build(springError.getStatusCode(), e.getMessage());
        }
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error.");
    }

    private static ResponseEntity<ErrorResponse> build(HttpStatusCode code, String message) {
        HttpStatus status = HttpStatus.resolve(code.value());
        String reason = status == null ? "Error" : status.getReasonPhrase();
        return ResponseEntity.status(code).body(new ErrorResponse(Instant.now(), code.value(), reason, message));
    }
}