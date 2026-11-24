package stage2;

import desafio.Application;
import desafio.crypto.PKCS12Loader;
import desafio.crypto.Signer;
import desafio.crypto.SignerCredentials;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = Application.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
public class TestSign {

    private static final String SHA512_OID = "2.16.840.1.101.3.4.2.3";
    private static final String RSA_OID_PREFIX = "1.2.840.113549.1.1.";

    @Value("${desafio.bry.pkcs12.alias}")
    private String alias;

    @Value("${desafio.bry.pkcs12.password}")
    private String passwd;

    private static byte[] doc;
    private static byte[] pkcs12;

    @BeforeAll
    static void loadArtifacts() throws Exception {
        doc = Files.readAllBytes(resource("artifacts/files/doc.txt"));
        pkcs12 = Files.readAllBytes(resource("artifacts/pkcs12/certificado_teste_hub.pfx"));
    }

    @Test
    void signsDocAttachedWithSha512AndRsaAndWritesP7s() throws Exception {
        SignerCredentials credentials = PKCS12Loader.load(pkcs12, passwd.toCharArray(), alias);

        byte[] signature = Signer.signAttached(doc, credentials);

        // This is the step were we write it onto disc
        Path out = Paths.get("target", "signatures", "doc.p7s");
        Files.createDirectories(out.getParent());
        Files.write(out, signature);
        assertTrue(Files.size(out) > 0);

        // Re read the disc and verify if there's content assigned to disc
        CMSSignedData parsed = new CMSSignedData(Files.readAllBytes(out));

        // We assert the content is attached
        assertNotNull(parsed.getSignedContent());
        assertArrayEquals(doc, (byte[]) parsed.getSignedContent().getContent());

        SignerInformation info = parsed.getSignerInfos().getSigners().iterator().next();
        assertEquals(SHA512_OID, info.getDigestAlgOID());
        assertTrue(info.getEncryptionAlgOID().startsWith(RSA_OID_PREFIX));

        assertTrue(info.verify(new JcaSimpleSignerInfoVerifierBuilder().build(credentials.certificate())));
    }

    private static Path resource(String name) throws Exception {
        var url = TestSign.class.getClassLoader().getResource(name);
        assertNotNull(url);
        return Paths.get(url.toURI());
    }
}