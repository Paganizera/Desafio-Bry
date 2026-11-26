package stage3;

import desafio.Application;
import desafio.crypto.*;
import desafio.util.ChallengeUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static utils.TestArtifacts.*;

@SpringBootTest(classes = Application.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
public class TestVerify {

    private static final Logger log = LoggerFactory.getLogger(TestVerify.class);

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
                ChallengeUtils.load(bytes("artifacts/chain/ac_raiz_bry_v3.cer")),
                ChallengeUtils.load(bytes("artifacts/chain/ac_bry_servidor_seguro_v3.cer")));
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

        // Print signer certificate metadata as required by Stage 3
        log.info("Signer Certificate Details -> CN='{}', Subject='{}', Issuer='{}', Serial='{}', ValidFrom={}, ValidUntil={}, SHA256='{}'",
                result.signer().commonName(),
                result.signer().subject(),
                result.signer().issuer(),
                result.signer().serialNumberHex(),
                result.signer().notBefore(),
                result.signer().notAfter(),
                result.signer().sha256Fingerprint());
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
}