package utils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public final class TestArtifacts {

    /** Onde as assinaturas geradas pelos testes são gravadas. */
    public static final Path OUTPUT_DIR = Paths.get("src", "main", "resources", "output");

    private TestArtifacts() {
    }

    public static byte[] bytes(String classpathResource) throws Exception {
        var url = TestArtifacts.class.getClassLoader().getResource(classpathResource);
        assertNotNull(url, "Artefato não encontrado no classpath: " + classpathResource);
        return Files.readAllBytes(Paths.get(url.toURI()));
    }

    /** Posição da primeira ocorrência de {@code pattern} em {@code data}, ou -1. */
    public static int indexOf(byte[] data, byte[] pattern) {
        outer:
        for (int i = 0; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}