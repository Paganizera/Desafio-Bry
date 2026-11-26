package stage4;

import desafio.Application;
import desafio.util.ChallengeUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static utils.TestArtifacts.bytes;
import static utils.TestArtifacts.indexOf;

@SpringBootTest(classes = Application.class)
@AutoConfigureMockMvc
public class TestAPI {

    @Autowired
    private MockMvc mvc;

    @Value("${desafio.bry.pkcs12.password}")
    private String passwd;

    private static byte[] doc;
    private static byte[] pkcs12;

    @BeforeAll
    static void loadArtifacts() throws Exception {
        doc = bytes("artifacts/files/doc.txt");
        pkcs12 = bytes("artifacts/pkcs12/certificado_teste_hub.pfx");
    }

    @Test
    void signatureReturnsBase64Cms() throws Exception {
        String base64 = signRequest("/signature");

        byte[] cms = Base64.getDecoder().decode(base64);
        assertTrue(indexOf(cms, doc) >= 0, "O documento deveria estar anexado na assinatura");
    }

    @Test
    void signatureAcceptsTrailingSlash() throws Exception {
        signRequest("/signature/");
    }

    @Test
    void signatureWithWrongPasswordIsBadRequest() throws Exception {
        mvc.perform(signBuilder("/signature").param("password", "senha-errada"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void signatureWithoutPasswordIsBadRequest() throws Exception {
        mvc.perform(multipart("/signature")
                        .file(new MockMultipartFile("document", "doc.txt", "text/plain", doc))
                        .file(new MockMultipartFile("pkcs12", "c.pfx", "application/x-pkcs12", pkcs12)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void signatureWithoutDocumentIsBadRequest() throws Exception {
        mvc.perform(multipart("/signature")
                        .file(new MockMultipartFile("pkcs12", "c.pfx", "application/x-pkcs12", pkcs12))
                        .param("password", passwd))
                .andExpect(status().isBadRequest());
    }

    @Test
    void signatureWithEmptyDocumentIsBadRequest() throws Exception {
        mvc.perform(multipart("/signature")
                        .file(new MockMultipartFile("document", "doc.txt", "text/plain", new byte[0]))
                        .file(new MockMultipartFile("pkcs12", "c.pfx", "application/x-pkcs12", pkcs12))
                        .param("password", passwd))
                .andExpect(status().isBadRequest());
    }

    @Test
    void signatureWithGarbagePkcs12IsBadRequest() throws Exception {
        mvc.perform(multipart("/signature")
                        .file(new MockMultipartFile("document", "doc.txt", "text/plain", doc))
                        .file(new MockMultipartFile("pkcs12", "c.pfx", "application/x-pkcs12", "lixo".getBytes()))
                        .param("password", passwd))
                .andExpect(status().isBadRequest());
    }

    @Test
    void verifyReturnsValidWithInfos() throws Exception {
        String base64 = signRequest("/signature");

        mvc.perform(verifyBuilder("/verify", base64.getBytes(StandardCharsets.US_ASCII)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VALIDO"))
                .andExpect(jsonPath("$.infos.nomeSignatario").value("HUB2 TESTES"))
                .andExpect(jsonPath("$.infos.dataAssinatura").exists())
                .andExpect(jsonPath("$.infos.hashDocumento").value(new ChallengeUtils().digestHex(doc)))
                .andExpect(jsonPath("$.infos.algoritmoHash").exists())
                .andExpect(jsonPath("$.infos.certificado.serialNumberHex").exists())
                .andExpect(jsonPath("$.infos.cadeiaConfiavel").exists());
    }

    @Test
    void verifyToleratesLineBreaksInBase64() throws Exception {
        String base64 = signRequest("/signature");
        String wrapped = base64.replaceAll("(.{64})", "$1\n") + "\n";

        mvc.perform(verifyBuilder("/verify/", wrapped.getBytes(StandardCharsets.US_ASCII)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VALIDO"));
    }

    @Test
    void verifyTamperedContentIsInvalid() throws Exception {
        byte[] cms = Base64.getDecoder().decode(signRequest("/signature"));
        int at = indexOf(cms, doc);
        assertTrue(at >= 0);
        cms[at] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(cms);

        mvc.perform(verifyBuilder("/verify", tampered.getBytes(StandardCharsets.US_ASCII)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("INVALIDO"))
                .andExpect(jsonPath("$.infos").exists());
    }

    @Test
    void verifyInvalidBase64IsBadRequest() throws Exception {
        mvc.perform(verifyBuilder("/verify", "%%% não é base64 %%%".getBytes(StandardCharsets.UTF_8)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void verifyValidBase64ButNotCmsIsBadRequest() throws Exception {
        String notCms = Base64.getEncoder().encodeToString("isto não é uma assinatura".getBytes());

        mvc.perform(verifyBuilder("/verify", notCms.getBytes(StandardCharsets.US_ASCII)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void verifyWithoutFileIsBadRequest() throws Exception {
        mvc.perform(multipart("/verify"))
                .andExpect(status().isBadRequest());
    }


    private MockMultipartHttpServletRequestBuilder signBuilder(String url) {
        return multipart(url)
                .file(new MockMultipartFile("document", "doc.txt", "text/plain", doc))
                .file(new MockMultipartFile("pkcs12", "certificado.pfx", "application/x-pkcs12", pkcs12));
    }

    private String signRequest(String url) throws Exception {
        return mvc.perform(signBuilder(url).param("password", passwd))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private MockMultipartHttpServletRequestBuilder verifyBuilder(String url, byte[] content) {
        return multipart(url).file(new MockMultipartFile("signature", "doc.p7s.b64", "text/plain", content));
    }
}