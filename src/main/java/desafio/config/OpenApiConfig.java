package desafio.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;


@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "API de Assinatura e Verificação Digital CMS",
                version = "1.0.0",
                description = "API REST desenvolvida para o Desafio Java da BRy Tecnologia. ",
                contact = @Contact(name = "bruno@pagani.rocks")
        ),
        servers = {
                @Server(url = "http://localhost:8080", description = "Localhost")
        }
)
public class OpenApiConfig {
}