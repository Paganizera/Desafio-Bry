package desafio.crypto;

import desafio.exception.InvalidInputException;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class CertificateLoader {

    private CertificateLoader() {
    }

    public static X509Certificate load(byte[] encoded) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encoded));
        } catch (CertificateException e) {
            throw new InvalidInputException("Invalid x509 certificate.", e);
        }
    }
}