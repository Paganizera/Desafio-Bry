package desafio.crypto;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public record SignerCredentials(PrivateKey privateKey, X509Certificate certificate, List<X509Certificate> chain) {
}