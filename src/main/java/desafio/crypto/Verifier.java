package desafio.crypto;

import desafio.exception.InvalidInputException;
import desafio.exception.SignatureProcessingException;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.cert.*;
import java.util.*;

/**
 * Realiza as etapas de verificação da assinatura
 */
public final class Verifier {

    private static final Provider BC = new BouncyCastleProvider();
    private static final Logger log = LoggerFactory.getLogger(Verifier.class);

    private Verifier() {
    }

    /**
     * Valida integridade, extrai metadados do assinante e verifica a cadeia de confiança relacionada à assinatura
     */
    public static VerificationResult verify(byte[] cms, List<X509Certificate> chainArtifacts) {
        CMSSignedData signed = parse(cms);
        if (signed.getSignedContent() == null) {
            throw new InvalidInputException("Signature not in attached format.");
        }

        List<SignerInformation> signers = List.copyOf(signed.getSignerInfos().getSigners());
        if (signers.isEmpty()) {
            throw new InvalidInputException("Signature has no signer attached.");
        }

        try {
            List<X509Certificate> embedded = embeddedCertificates(signed);
            boolean integrity = true;
            X509Certificate firstSignerCert = null;

            for (SignerInformation signer : signers) {
                X509Certificate cert = findSignerCertificate(signer, embedded, chainArtifacts);
                if (firstSignerCert == null) {
                    firstSignerCert = cert;
                }
                integrity &= cert != null && verifySigner(signer, cert);
            }

            CertificateInfo info = firstSignerCert == null ? null : CertificateInfo.from(firstSignerCert);
            String failure = firstSignerCert == null
                    ? "There is no reference do signer's certificate."
                    : checkTrust(firstSignerCert, embedded, chainArtifacts);

            if (failure != null) {
                log.debug("Certificate trust validation failed: {}", failure);
            }

            return new VerificationResult(integrity, failure == null, failure, info, detailsOf(signed, signers.get(0)));
        } catch (GeneralSecurityException | CMSException | OperatorCreationException | IOException e) {
            throw new SignatureProcessingException("Failure to verify signature.", e);
        }
    }

    private static SignatureDetails detailsOf(CMSSignedData signed, SignerInformation signer)
            throws OperatorCreationException, IOException {
        byte[] content = (byte[]) signed.getSignedContent().getContent();
        DigestCalculator calculator = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()
                .get(signer.getDigestAlgorithmID());
        try (OutputStream out = calculator.getOutputStream()) {
            out.write(content);
        }
        return new SignatureDetails(
                signingTimeOf(signer),
                HexFormat.of().formatHex(calculator.getDigest()),
                new DefaultAlgorithmNameFinder().getAlgorithmName(signer.getDigestAlgorithmID()));
    }

    private static java.time.Instant signingTimeOf(SignerInformation signer) {
        AttributeTable attributes = signer.getSignedAttributes();
        Attribute attribute = attributes == null ? null : attributes.get(CMSAttributes.signingTime);
        if (attribute == null) {
            return null;
        }
        return Time.getInstance(attribute.getAttrValues().getObjectAt(0)).getDate().toInstant();
    }

    private static CMSSignedData parse(byte[] cms) {
        try {
            return new CMSSignedData(cms);
        } catch (CMSException e) {
            throw new InvalidInputException("Invalid or currupted signature file.", e);
        }
    }

    private static boolean verifySigner(SignerInformation signer, X509Certificate cert)
            throws CMSException, OperatorCreationException {
        try {
            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));
        } catch (CMSSignerDigestMismatchException e) {
            log.debug("CMS content digest mismatch detected during signature verification.");
            return false; // Encapsulated content was modified after signing
        }
    }


    private static X509Certificate findSignerCertificate(SignerInformation signer,
                                                         List<X509Certificate> embedded,
                                                         List<X509Certificate> chainArtifacts)
            throws GeneralSecurityException {
        List<X509Certificate> candidates = new ArrayList<>(embedded);
        candidates.addAll(chainArtifacts);
        for (X509Certificate candidate : candidates) {
            if (signer.getSID().match(new JcaX509CertificateHolder(candidate))) {
                return candidate;
            }
        }
        return null;
    }

    private static List<X509Certificate> embeddedCertificates(CMSSignedData signed)
            throws GeneralSecurityException {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        List<X509Certificate> certs = new ArrayList<>();
        for (X509CertificateHolder holder : signed.getCertificates().getMatches(null)) {
            certs.add(converter.getCertificate(holder));
        }
        return certs;
    }

    /**
     * Constrói e valida o caminho de certificação PKIX até uma âncora.
     */
    private static String checkTrust(X509Certificate signerCert,
                                     List<X509Certificate> embedded,
                                     List<X509Certificate> chainArtifacts) throws GeneralSecurityException {
        Set<TrustAnchor> anchors = new HashSet<>();
        List<X509Certificate> pool = new ArrayList<>(embedded);
        pool.add(signerCert);
        for (X509Certificate c : chainArtifacts) {
            if (c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) {
                anchors.add(new TrustAnchor(c, null));
            } else {
                pool.add(c);
            }
        }
        if (anchors.isEmpty()) {
            return "No root ac provided.";
        }

        X509CertSelector target = new X509CertSelector();
        target.setCertificate(signerCert);

        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
            // desabilitamos análise de revogação em decorrência do escopo solicitado
            params.setRevocationEnabled(false);
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(pool)));
            CertPathBuilder.getInstance("PKIX").build(params);
            return null;
        } catch (CertPathBuilderException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return "Invalid certpath: " + cause.getMessage();
        } catch (InvalidAlgorithmParameterException e) {
            return "Invalid validation parameters: " + e.getMessage();
        }
    }
}