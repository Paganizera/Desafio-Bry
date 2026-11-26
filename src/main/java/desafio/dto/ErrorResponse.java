package desafio.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;


@Schema(description = "Estrutura padronizada de erro retornada pela API.")
public record ErrorResponse(
        @Schema Instant timestamp,
        @Schema int status,
        @Schema String error,
        @Schema String message) {
}