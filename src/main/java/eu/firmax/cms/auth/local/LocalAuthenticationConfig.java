package eu.firmax.cms.auth.local;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configures the beans necessary to perform a local authentication.
 */
@Configuration(proxyBeanMethods = false)
public class LocalAuthenticationConfig {

    /**
     * Returns the bcrypt password encoder used for all passwords stored directly by us.
     *
     * @return the bcrypt password encoder used for all passwords stored directly by us.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
