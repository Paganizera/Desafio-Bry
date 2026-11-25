package desafio.service;

import desafio.crypto.CertificateLoader;
import desafio.exception.InvalidInputException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Component
public class TrustChainProvider {

    private static final Logger log = LoggerFactory.getLogger(TrustChainProvider.class);
    private static final String PATTERN = "classpath*:artifacts/chain/*.cer";

    private final List<X509Certificate> certificates;

    public TrustChainProvider() {
        Set<X509Certificate> loaded = new LinkedHashSet<>();
        try {
            for (Resource resource : new PathMatchingResourcePatternResolver().getResources(PATTERN)) {
                try {
                    loaded.add(CertificateLoader.load(resource.getContentAsByteArray()));
                } catch (InvalidInputException | IOException ignored) {}
            }
        } catch (IOException ignored) {}
        this.certificates = List.copyOf(loaded);
    }

    public List<X509Certificate> certificates() {
        return certificates;
    }
}