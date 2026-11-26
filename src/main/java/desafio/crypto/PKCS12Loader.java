package desafio.crypto;

import desafio.exception.InvalidKeystoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Classe responsável por intermediar tratamento e manuseio de repositórios PKCS#12
 */
public final class PKCS12Loader {

    private static final Logger log = LoggerFactory.getLogger(PKCS12Loader.class);

    private PKCS12Loader() {
    }


    public static SignerCredentials load(byte[] pkcs12, char[] password) {
        return load(pkcs12, password, null);
    }


    public static SignerCredentials load(byte[] pkcs12, char[] password, String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(pkcs12), password);

            if (alias != null) {
                SignerCredentials creds = credentialsOf(ks, alias, password);
                if (creds == null) {
                    // Existem arquivos que encapsulam o alias por chaves
                    creds = credentialsOf(ks, "{" + alias + "}", password);
                }
                if (creds == null) {
                    throw new InvalidKeystoreException("The alias '" + alias + "' is inexistent or has no private keys associated");
                }
                log.debug("Loaded PKCS#12 credentials using explicit alias '{}'.", alias);
                return creds;
            }

            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String currentAlias = aliases.nextElement();
                SignerCredentials creds = credentialsOf(ks, currentAlias, password);
                if (creds != null) {
                    log.debug("Loaded PKCS#12 credentials using first available key alias '{}'.", currentAlias);
                    return creds;
                }
            }
            throw new InvalidKeystoreException("The PKCS12 has no associate privatekey certificate pair.");
        } catch (IOException e) {
            throw new InvalidKeystoreException("Invalid PKCS12 file or invalid password.", e);
        } catch (GeneralSecurityException e) {
            throw new InvalidKeystoreException("Failed to read PKCS12: " + e.getMessage(), e);
        }
    }

    private static SignerCredentials credentialsOf(KeyStore ks, String alias, char[] password)
            throws GeneralSecurityException {
        if (!ks.isKeyEntry(alias)) {
            return null;
        }
        Key key = ks.getKey(alias, password);
        Certificate[] chain = ks.getCertificateChain(alias);
        if (!(key instanceof PrivateKey privateKey) || chain == null) {
            return null;
        }
        List<X509Certificate> certs = new ArrayList<>();
        for (Certificate c : chain) {
            if (c instanceof X509Certificate x509) {
                certs.add(x509);
            }
        }
        return certs.isEmpty() ? null : new SignerCredentials(privateKey, certs.get(0), List.copyOf(certs));
    }
}