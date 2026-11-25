package desafio.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import desafio.crypto.CertificateInfo;

import java.time.Instant;


public record SignatureInfo(String nomeSignatario,
                            Instant dataAssinatura,
                            String hashDocumento,
                            String algoritmoHash,
                            CertificateInfo certificado,
                            boolean cadeiaConfiavel,
                            @JsonInclude(JsonInclude.Include.NON_NULL) String motivoCadeiaNaoConfiavel) {
}