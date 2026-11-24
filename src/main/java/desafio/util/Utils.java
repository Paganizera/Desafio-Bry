package desafio.util;

import desafio.exception.SignatureProcessingException;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public final class Utils {

    public static final String ALGORITHM = "SHA-512";

    public byte[] digest(byte[] content) {
        return newDigest().digest(content);
    }

    public String digestHex(byte[] content) {
        return HexFormat.of().formatHex(digest(content));
    }

    // useful for api stuff
    public String digestHex(Path file) throws IOException {
        MessageDigest md = newDigest();
        try (InputStream in = new DigestInputStream(Files.newInputStream(file), md)) {
            in.transferTo(OutputStream.nullOutputStream());
        }
        return HexFormat.of().formatHex(md.digest());
    }

    private MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureProcessingException("Algoritmo " + ALGORITHM + " indisponível.", e);
        }
    }
}
