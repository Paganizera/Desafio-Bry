package desafio.dto;

public record VerifyResponse(String status, SignatureInfo infos) {

    public static final String VALID = "VALIDO";
    public static final String INVALID = "INVALIDO";
}