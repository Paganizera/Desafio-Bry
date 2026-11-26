package desafio.service;

import desafio.crypto.*;
import desafio.dto.SignatureInfo;
import desafio.dto.VerifyResponse;
import desafio.exception.InvalidInputException;
import org.slf4j.Logger;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Serviço responsável por efetivar assinaturas e verificações
 */
@Service
public class SignatureService {

    private final TrustChainProvider trustChain;
    private final Logger log;

    public SignatureService(TrustChainProvider trustChain, Logger log) {
        this.trustChain = trustChain;
        this.log = log;
    }


    public String sign(byte[] document, byte[] pkcs12, char[] password) {
        log.info("Starting CMS attached signing process.");
        try {
            SignerCredentials credentials = PKCS12Loader.load(pkcs12, password);
            String encoded = Base64.getEncoder().encodeToString(Signer.signAttached(document, credentials));
            log.info("Document signed successfully for subject '{}'.", credentials.certificate().getSubjectX500Principal());
            return encoded;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public VerifyResponse verify(byte[] base64Signature) {
        log.info("Starting CMS signature verification (payload={} bytes).", base64Signature.length);
        byte[] cms = decodeBase64(base64Signature);
        VerificationResult result = Verifier.verify(cms, trustChain.certificates());

        SignatureDetails details = result.details();
        SignatureInfo infos = new SignatureInfo(
                result.signer() == null ? null : result.signer().commonName(),
                details.signingTime(),
                details.content(),
                details.digestAlgorithm(),
                result.signer(),
                result.trusted(),
                result.trustFailureReason());

        log.info("Verification completed: integrityValid={}, trusted={}, signer='{}'.",
                result.integrityValid(),
                result.trusted(),
                result.signer() != null ? result.signer().commonName() : "unknown");

        return new VerifyResponse(result.integrityValid() ? VerifyResponse.VALID : VerifyResponse.INVALID, infos);
    }


    private static byte[] decodeBase64(byte[] raw) {
        String text = new String(raw, StandardCharsets.US_ASCII).replaceAll("\\s+", "");
        try {
            return Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw new InvalidInputException("O arquivo de assinatura não está em Base64 válido.", e);
        }
    }
}