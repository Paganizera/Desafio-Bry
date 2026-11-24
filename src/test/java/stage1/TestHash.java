package stage1;

import desafio.util.DigestUtils;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

// gonna elaborate this later
public class TestHash {
    private final String docHash = "dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b045884fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35";

    private final DigestUtils utils = new DigestUtils();

    @Test
    void fileDigestMatchesBytesDigest() throws Exception {
        URL resource = getClass().getClassLoader().getResource("artifacts/files/doc.txt");
        assertNotNull(resource, "Test artifact doc.txt not found on classpath");

        Path f = Paths.get(resource.toURI());
        assertEquals(docHash, utils.digestHex(f));
    }
}
