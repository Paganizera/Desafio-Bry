package desafio.controllers;

import desafio.dto.VerifyResponse;
import desafio.exception.InvalidInputException;
import desafio.service.SignatureService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
public class SigningController {

    private final SignatureService service;

    public SigningController(SignatureService service) {
        this.service = service;
    }

    /** multipart/form-data: document (arquivo), pkcs12 (arquivo) e password (texto). Retorna o CMS em Base64. */
    @PostMapping(value = {"/signature", "/signature/"}, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> sign(@RequestParam("document") MultipartFile document,
                                       @RequestParam("pkcs12") MultipartFile pkcs12,
                                       @RequestParam("password") String password) {
        String base64 = service.sign(read(document, "document"), read(pkcs12, "pkcs12"), password.toCharArray());
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(base64);
    }

    /** multipart/form-data: signature (arquivo com o CMS attached em Base64). */
    @PostMapping(value = {"/verify", "/verify/"}, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public VerifyResponse verify(@RequestParam("signature") MultipartFile signature) {
        return service.verify(read(signature, "signature"));
    }

    private static byte[] read(MultipartFile file, String part) {
        if (file.isEmpty()) {
            throw new InvalidInputException("O arquivo '" + part + "' está vazio.");
        }
        try {
            return file.getBytes();
        } catch (IOException e) {
            throw new InvalidInputException("Não foi possível ler o arquivo '" + part + "'.", e);
        }
    }
}