package stage3;

import desafio.Application;
import desafio.crypto.CertificateLoader;
import desafio.crypto.PKCS12Loader;
import desafio.crypto.Verifier;
import desafio.crypto.SignerCredentials;
import desafio.crypto.Signer;
import desafio.crypto.VerificationResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static utils.TestArtifacts.OUTPUT_DIR;
import static utils.TestArtifacts.bytes;

@SpringBootTest(classes = Application.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
public class TestVerify {

    @Value("${desafio.bry.pkcs12.alias}")
    private String alias;

    @Value("${desafio.bry.pkcs12.password}")
    private String passwd;

    private static byte[] doc;
    private static byte[] pkcs12;
    private static List<X509Certificate> chain;

    private byte[] signature;

    @BeforeAll
    static void loadArtifacts() throws Exception {
        doc = bytes("artifacts/files/doc.txt");
        pkcs12 = bytes("artifacts/pkcs12/certificado_teste_hub.pfx");
        chain = List.of(
                CertificateLoader.load(bytes("artifacts/chain/ac_raiz_bry_v3.cer")),
                CertificateLoader.load(bytes("artifacts/chain/ac_bry_servidor_seguro_v3.cer")));
    }

    @BeforeEach
    void sign() throws Exception {
        signature = Signer.signAttached(doc, PKCS12Loader.load(pkcs12, passwd.toCharArray(), alias));
        Files.createDirectories(OUTPUT_DIR);
        Files.write(OUTPUT_DIR.resolve("doc.p7s"), signature);
    }

    @Test
    void validSignatureHasIntegrityAndTrustedChain() {
        VerificationResult result = Verifier.verify(signature, chain);

        assertNotNull(result.signer());
        assertTrue(result.integrityValid());
        assertTrue(result.trusted(), result.trustFailureReason());
    }

    @Test
    void tamperedContentBreaksIntegrity() {
        byte[] tampered = signature.clone();
        int at = indexOf(tampered, doc);
        assertTrue(at >= 0);
        tampered[at] ^= 0x01;

        assertFalse(Verifier.verify(tampered, chain).integrityValid());
    }

    @Test
    void signatureWithoutEmbeddedChainIsTrustedThroughProvidedArtifacts() throws Exception {
        SignerCredentials full = PKCS12Loader.load(pkcs12, passwd.toCharArray(), alias);
        SignerCredentials leafOnly = new SignerCredentials(full.privateKey(), full.certificate(),
                List.of(full.certificate()));
        byte[] sig = Signer.signAttached(doc, leafOnly);

        VerificationResult result = Verifier.verify(sig, chain);

        assertTrue(result.integrityValid());
        assertTrue(result.trusted(), result.trustFailureReason());
    }

    @Test
    void withoutChainArtifactsCertificateIsNotTrusted() {
        VerificationResult result = Verifier.verify(signature, List.of());

        assertTrue(result.integrityValid());
        assertFalse(result.trusted());
        assertNotNull(result.trustFailureReason());
    }

    private static int indexOf(byte[] data, byte[] pattern) {
        outer:
        for (int i = 0; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}