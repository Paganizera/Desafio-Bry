package desafio.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InjectionPoint;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

/**
 * Classe de configuração Spring para logger configurável compatível com logger padrão do spring
 */
@Configuration
public class LoggerConfig {

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public Logger logger(InjectionPoint injectionPoint) {
        return LoggerFactory.getLogger(resolveTargetClass(injectionPoint));
    }

    private Class<?> resolveTargetClass(InjectionPoint injectionPoint) {
        if (injectionPoint.getMethodParameter() != null) {
            return injectionPoint.getMethodParameter().getContainingClass();
        }
        if (injectionPoint.getField() != null) {
            return injectionPoint.getField().getDeclaringClass();
        }
        return LoggerConfig.class;
    }
}