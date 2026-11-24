package desafio.exception;

/** Falha interna inesperada de criptografia (provider ausente, erro ao gerar CMS...). HTTP 500. */
public class SignatureProcessingException extends RuntimeException {

    public SignatureProcessingException(String message) {
        super(message);
    }

    public SignatureProcessingException(String message, Throwable cause) {
        super(message, cause);
    }
}
