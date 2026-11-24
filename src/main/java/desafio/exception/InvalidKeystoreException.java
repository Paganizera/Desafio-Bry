package desafio.exception;

public class InvalidKeystoreException extends RuntimeException {

    public InvalidKeystoreException(String message) {
        super(message);
    }

    public InvalidKeystoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
