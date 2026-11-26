package desafio.crypto;

import desafio.exception.InvalidInputException;
import desafio.exception.InvalidKeystoreException;
import desafio.exception.SignatureProcessingException;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * Classe responsável pelo processo mecânica da geração de uma assinatura
 */
public class Signer {

    public static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
    private static final Logger log = LoggerFactory.getLogger(Signer.class);

    public static byte[] signAttached(byte[] content, SignerCredentials credentials) {
        if (content == null || content.length == 0) {
            throw new InvalidInputException("Não é possível assinar um conteúdo vazio.");
        }
        PrivateKey key = credentials.privateKey();
        if (!"RSA".equalsIgnoreCase(key.getAlgorithm())) {
            throw new InvalidKeystoreException("Invalid algorithm: " + key.getAlgorithm() + "\n Accepting only RSA");
        }
        warnIfOutsideValidity(credentials.certificate());

        try {
            CMSTypedData message = new CMSProcessableByteArray(content);

            ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(key);
            DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build();

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digests)
                    .build(signer, credentials.certificate()));

            // in order to facilitate verification, we add all certificate chain, not needed as we can reconstruct
            generator.addCertificates(new JcaCertStore(credentials.chain()));

            CMSSignedData signed = generator.generate(message, true); // true = attached
            return signed.getEncoded();
        } catch (OperatorCreationException | CMSException | IOException | GeneralSecurityException e) {
            throw new SignatureProcessingException("An error occurred while signing.", e);
        }
    }

    private static void warnIfOutsideValidity(X509Certificate cert) {
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            log.warn("Signer certificate is outside its validity period ({}); signature will be generated, "
                    + "but trust validation will reject it.", e.getMessage());
        }
    }
}