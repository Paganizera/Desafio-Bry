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

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.cert.*;
import java.util.*;

public final class Verifier {

    private static final Provider BC = new BouncyCastleProvider();

    private Verifier() {
    }

    public static VerificationResult verify(byte[] cms, List<X509Certificate> chainArtifacts) {
        CMSSignedData signed = parse(cms);
        if (signed.getSignedContent() == null) {
            throw new InvalidInputException("A assinatura não contém o conteúdo anexado (attached).");
        }

        List<SignerInformation> signers = List.copyOf(signed.getSignerInfos().getSigners());
        if (signers.isEmpty()) {
            throw new InvalidInputException("A assinatura não possui nenhum signatário.");
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
                    ? "Certificado do signatário não está embutido na assinatura nem nos artefatos fornecidos."
                    : checkTrust(firstSignerCert, embedded, chainArtifacts);

            return new VerificationResult(integrity, failure == null, failure, info, detailsOf(signed, signers.get(0)));
        } catch (GeneralSecurityException | CMSException | OperatorCreationException | IOException e) {
            throw new SignatureProcessingException("Falha ao verificar a assinatura CMS.", e);
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
            throw new InvalidInputException("Assinatura CMS inválida ou corrompida.", e);
        }
    }

    private static boolean verifySigner(SignerInformation signer, X509Certificate cert)
            throws CMSException, OperatorCreationException {
        try {
            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));
        } catch (CMSSignerDigestMismatchException e) {
            return false; // o conteúdo foi alterado: o hash não bate com o assinado
        }
    }

    /**
     * Procura primeiro entre os certificados embutidos na assinatura e depois nos artefatos fornecidos.
     */
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
     * @return {@code null} se o certificado é confiável; caso contrário, o motivo.
     */
    private static String checkTrust(X509Certificate signerCert,
                                     List<X509Certificate> embedded,
                                     List<X509Certificate> chainArtifacts) throws GeneralSecurityException {
        Set<TrustAnchor> anchors = new HashSet<>();
        List<X509Certificate> pool = new ArrayList<>(embedded); // só ajudam a montar o caminho, nunca são âncora
        pool.add(signerCert);
        for (X509Certificate c : chainArtifacts) {
            if (c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) {
                anchors.add(new TrustAnchor(c, null));
            } else {
                pool.add(c);
            }
        }
        if (anchors.isEmpty()) {
            return "Nenhuma autoridade certificadora raiz (autoassinada) foi fornecida.";
        }

        X509CertSelector target = new X509CertSelector();
        target.setCertificate(signerCert);

        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
            params.setRevocationEnabled(false); // não há CRL/OCSP nos artefatos do desafio
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(pool)));
            CertPathBuilder.getInstance("PKIX").build(params);
            return null;
        } catch (CertPathBuilderException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return "Caminho de certificação inválido: " + cause.getMessage();
        } catch (InvalidAlgorithmParameterException e) {
            return "Parâmetros de validação inválidos: " + e.getMessage();
        }
    }
}