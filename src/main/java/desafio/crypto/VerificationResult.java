package desafio.crypto;


public record VerificationResult(boolean integrityValid,
                                 boolean trusted,
                                 String trustFailureReason,
                                 CertificateInfo signer) {
}