package eu.firmax.cms.auth.security;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.controller.TestLoginController;
import eu.firmax.cms.auth.controller.TokenController;
import eu.firmax.cms.auth.local.LocalAuthenticationEndpointProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configures the default spring security filter chain.
 * <p>
 * The default chain is used whenever no other chain with a higher priority (like the ones from
 * {@link AuthorizationServerConfig}) is matching.
 */
@EnableWebSecurity
@RequiredArgsConstructor
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    @NonNull
    private final LocalAuthenticationEndpointProperties localAuthenticationEndpointProperties;

    /**
     * Returns the default spring security filter chain.
     * The default chain only allows unauthenticated requests to a few specified endpoints.
     * All other requests must be made with a valid authentication.
     * <p>
     * Also, a lot of other configurations is being made by the {@link FederatedIdentityConfigurer} to this chain.
     *
     * @param http the http object for which the filter chain will be registered.
     * @return the default spring security filter chain.
     * @throws Exception if building the chain failed.
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(@NonNull final HttpSecurity http) throws Exception {
        final FederatedIdentityConfigurer federatedIdentityConfigurer = new FederatedIdentityConfigurer();

        http.authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers(
                                        localAuthenticationEndpointProperties.getLoginEndpoint(),
                                        TestLoginController.CLEAR_ATTEMPTS_ENDPOINT,
                                        TokenController.ACCESS_TOKENS_ENDPOINT,
                                        TokenController.ACCESS_TOKEN_DELETE_ENDPOINT).permitAll()
                                .anyRequest().authenticated())
                .apply(federatedIdentityConfigurer);

        return http.build();
    }
}
