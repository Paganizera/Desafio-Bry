package desafio.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Resultado da verificação da assinatura digital CMS.")
public record VerifyResponse(
        @Schema String status,
        @Schema SignatureInfo infos) {

    public static final String VALID = "VALIDO";
    public static final String INVALID = "INVALIDO";
}