package desafio.crypto;

import desafio.exception.SignatureProcessingException;

import javax.security.auth.x500.X500Principal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HexFormat;

public record CertificateInfo(String subject,
                              String issuer,
                              String serialNumberHex,
                              Instant notBefore,
                              Instant notAfter,
                              String signatureAlgorithm,
                              String publicKeyAlgorithm,
                              String sha256Fingerprint) {

    public static CertificateInfo from(X509Certificate cert) {
        return new CertificateInfo(
                cert.getSubjectX500Principal().getName(X500Principal.RFC1779),
                cert.getIssuerX500Principal().getName(X500Principal.RFC1779),
                cert.getSerialNumber().toString(16).toUpperCase(),
                cert.getNotBefore().toInstant(),
                cert.getNotAfter().toInstant(),
                cert.getSigAlgName(),
                cert.getPublicKey().getAlgorithm(),
                sha256(cert));
    }


    private static String sha256(X509Certificate cert) {
        try {
            return HexFormat.of().withUpperCase()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new SignatureProcessingException("Não foi possível calcular a impressão digital do certificado.", e);
        }
    }
}