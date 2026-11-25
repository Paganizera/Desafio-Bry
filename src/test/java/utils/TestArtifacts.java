package utils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public final class TestArtifacts {
    // default path to writing files
    public static final Path OUTPUT_DIR = Paths.get("src", "main", "resources", "output");

    private TestArtifacts() {
    }

    public static byte[] bytes(String classpathResource) throws Exception {
        var url = TestArtifacts.class.getClassLoader().getResource(classpathResource);
        assertNotNull(url);
        return Files.readAllBytes(Paths.get(url.toURI()));
    }
}