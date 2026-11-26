package desafio.crypto;

import java.time.Instant;

public record SignatureDetails(Instant signingTime, String content, String digestAlgorithm) {
}