package desafio.crypto;

import java.time.Instant;

/**
 * @param signingTime atributo signingTime do signatári
 * @param contentHashHex  hash do conteúdo anexado, calculado com o digestAlgorithm do signatário
 * @param digestAlgorithm nome do algoritmo de assinatura utilizado
 */
public record SignatureDetails(Instant signingTime, String contentHashHex, String digestAlgorithm) {
}