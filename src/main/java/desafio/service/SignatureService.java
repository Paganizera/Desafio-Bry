package desafio.service;

import desafio.crypto.*;
import desafio.dto.SignatureInfo;
import desafio.dto.VerifyResponse;
import desafio.exception.InvalidInputException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

@Service
public class SignatureService {

    private final TrustChainProvider trustChain;

    public SignatureService(TrustChainProvider trustChain) {
        this.trustChain = trustChain;
    }

    public String sign(byte[] document, byte[] pkcs12, char[] password) {
        try {
            SignerCredentials credentials = PKCS12Loader.load(pkcs12, password);
            return Base64.getEncoder().encodeToString(Signer.signAttached(document, credentials));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public VerifyResponse verify(byte[] base64Signature) {
        byte[] cms = decodeBase64(base64Signature);
        VerificationResult result = Verifier.verify(cms, trustChain.certificates());

        SignatureDetails details = result.details();
        SignatureInfo infos = new SignatureInfo(
                result.signer() == null ? null : result.signer().commonName(),
                details.signingTime(),
                details.contentHashHex(),
                details.digestAlgorithm(),
                result.signer(),
                result.trusted(),
                result.trustFailureReason());

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