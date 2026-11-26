package desafio.controllers;

import desafio.dto.VerifyResponse;
import desafio.exception.InvalidInputException;
import desafio.service.SignatureService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.slf4j.Logger;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

/**
 * REST controller responsável por receber requisiões de assinatura e verificação
 */
@RestController
public class SigningController {

    private final SignatureService service;
    private final Logger log;

    public SigningController(SignatureService service, Logger log) {
        this.service = service;
        this.log = log;
    }

    @Operation(
            summary = "Assinar documento",
            description = "Recebe um documento e um repositório PKCS#12 com sua respectiva senha via multipart/form-data, "
                    + "gerando uma assinatura CMS anexada."
    )
    @ApiResponse(
            responseCode = "200",
            description = "Documento assinado com sucesso.p",
            content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE, schema = @Schema(type = "string", example = "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgMFADCABgkqhkiG9w0BBwGggCSAB..."))
    )
    @PostMapping(value = {"/signature", "/signature/"}, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> sign(
            @Parameter(description = "Arquivo original a ser assinado.", required = true)
            @RequestParam("document") MultipartFile document,
            @Parameter(description = "Arquivo PKCS#12 (.pfx ou .p12) contendo a chave privada e o certificado do signatário.", required = true)
            @RequestParam("pkcs12") MultipartFile pkcs12,
            @Parameter(description = "Senha de acesso ao repositório PKCS#12.", required = true, example = "bry123456")
            @RequestParam("password") String password) {
        log.debug("Received POST /signature request (document='{}', size={} bytes, pkcs12='{}').",
                document.getOriginalFilename(), document.getSize(), pkcs12.getOriginalFilename());

        String base64 = service.sign(read(document, "document"), read(pkcs12, "pkcs12"), password.toCharArray());
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(base64);
    }

    @Operation(
            summary = "Verificar assinatura digital CMS",
            description = "Recebe um arquivo contendo uma assinatura CMS anexada, valida sua integridade, e verifica conformidade."
    )
    @ApiResponse(
            responseCode = "200",
            description = "Verificação concluída.",
            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = VerifyResponse.class))
    )
    @PostMapping(value = {"/verify", "/verify/"}, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public VerifyResponse verify(
            @Parameter(description = "Arquivo contendo a assinatura CMS attached codificada em Base64.", required = true)
            @RequestParam("signature") MultipartFile signature) {
        log.debug("Received POST /verify request (signature='{}', size={} bytes).",
                signature.getOriginalFilename(), signature.getSize());

        return service.verify(read(signature, "signature"));
    }

    /**
     * Método responsavel por validar a existência de conteúdo de um arquivo
     */
    private static byte[] read(MultipartFile file, String part) {
        if (file.isEmpty()) {
            throw new InvalidInputException("Empty File.");
        }
        try {
            return file.getBytes();
        } catch (IOException e) {
            throw new InvalidInputException("File couldn't be read: ", e);
        }
    }
}