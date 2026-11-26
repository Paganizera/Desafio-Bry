package desafio.service;

import desafio.exception.InvalidInputException;
import desafio.util.ChallengeUtils;
import org.slf4j.Logger;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Componente responsável por carregar as Ancoras de confiança
 */
@Component
public class TrustChainProvider {

    private static final List<String> PATTERNS = List.of(
            "classpath*:artifacts/chain/*.cer",
            "classpath*:cadeia/*.cer"
    );

    private final List<X509Certificate> certificates;

    public TrustChainProvider(Logger log) {
        Set<X509Certificate> loaded = new LinkedHashSet<>();
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();

        for (String pattern : PATTERNS) {
            try {
                for (Resource resource : resolver.getResources(pattern)) {
                    try {
                        X509Certificate cert = ChallengeUtils.load(resource.getContentAsByteArray());
                        loaded.add(cert);
                        log.debug("Loaded trust chain certificate '{}' (subject='{}').",
                                resource.getFilename(), cert.getSubjectX500Principal());
                    } catch (InvalidInputException | IOException e) {
                        log.warn("Skipping invalid or unreadable certificate resource '{}': {}",
                                resource.getFilename(), e.getMessage());
                    }
                }
            } catch (IOException e) {
                log.warn("Failed to scan classpath for pattern '{}': {}", pattern, e.getMessage());
            }
        }

        this.certificates = List.copyOf(loaded);
        log.info("TrustChainProvider initialized with {} certificate(s).", this.certificates.size());
    }

    public List<X509Certificate> certificates() {
        return certificates;
    }
}