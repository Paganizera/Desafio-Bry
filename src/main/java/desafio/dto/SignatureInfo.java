package desafio.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import desafio.crypto.CertificateInfo;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;


@Schema(description = "Informações detalhadas extraídas da assinatura digital e do certificado do signatário.")
public record SignatureInfo(
        @Schema String nomeSignatario,
        @Schema Instant dataAssinatura,
        @Schema String hashDocumento,
        @Schema String algoritmoHash,
        @Schema CertificateInfo certificado,
        @Schema boolean cadeiaConfiavel,
        @Schema @JsonInclude(JsonInclude.Include.NON_NULL) String motivoCadeiaNaoConfiavel) {
}