package desafio.crypto;

import desafio.exception.InvalidInputException;
import desafio.exception.SignatureProcessingException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class Verifier {


    private Verifier() {
    }


    public static VerificationResult verify(byte[] cms, List<X509Certificate> chainArtifacts) {
        CMSSignedData signed = parse(cms);
        if (signed.getSignedContent() == null) {
            throw new InvalidInputException("Signature is not attached.");
        }

        List<SignerInformation> signers = List.copyOf(signed.getSignerInfos().getSigners());
        if (signers.isEmpty()) {
            throw new InvalidInputException("Signature has no signer information.");
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
                    ? "Signature has no reference to signing certificate."
                    : checkTrust(firstSignerCert, embedded, chainArtifacts);

            return new VerificationResult(integrity, failure == null, failure, info);
        } catch (GeneralSecurityException | CMSException | OperatorCreationException e) {
            throw new SignatureProcessingException("Failure while verifying signature.", e);
        }
    }

    private static CMSSignedData parse(byte[] cms) {
        try {
            return new CMSSignedData(cms);
        } catch (CMSException e) {
            throw new InvalidInputException("Invalid or corrupted CMS file file", e);
        }
    }

    private static boolean verifySigner(SignerInformation signer, X509Certificate cert)
            throws CMSException, OperatorCreationException {
        try {
            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert));
        } catch (CMSSignerDigestMismatchException e) {
            return false; // hash is not what was expected
        }
    }

    private static X509Certificate findSignerCertificate(SignerInformation signer,
                                                         List<X509Certificate> embedded,
                                                         List<X509Certificate> chainArtifacts) throws GeneralSecurityException {
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
            return "No AC certificate found.";
        }

        X509CertSelector target = new X509CertSelector();
        target.setCertificate(signerCert);

        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
            params.setRevocationEnabled(false);
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(pool)));
            CertPathBuilder.getInstance("PKIX").build(params);
            return null;
        } catch (CertPathBuilderException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return "Invalid cert path: " + cause.getMessage();
        } catch (InvalidAlgorithmParameterException e) {
            return "Invalid algorithm parameters: " + e.getMessage();
        }
    }
}