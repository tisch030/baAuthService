package eu.firmax.cms.auth.security;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.IdentityProviderService;
import eu.firmax.cms.auth.local.LocalAuthenticationEndpointProperties;
import eu.firmax.cms.auth.local.settings.LocalAuthenticationSettingsCache;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Contains the configuration for the authorization server endpoints and settings.
 */
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    @NonNull
    private final SecurityEndpointProperties securityEndpointProperties;

    @NonNull
    private final LocalAuthenticationEndpointProperties localAuthenticationEndpointProperties;

    @NonNull
    private final LocalAuthenticationSettingsCache localAuthenticationSettingsCache;

    @NonNull
    private final IdentityProviderService identityProviderService;

    @NonNull
    private final CookieCsrfTokenRepository cookieCsrfTokenRepository;

    @NonNull
    private final CsrfTokenRequestHandler csrfTokenRequestHandler;

    /**
     * Returns a spring security filter chain used for endpoints provided by the authorization server.
     * Most of the endpoints resolve around the authorization and token endpoints.
     *
     * @param http the http object for which the filter chain will be registered.
     * @return a spring security filter chain used for endpoints provided by the authorization server.
     * @throws Exception if building the chain failed.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(@NonNull final HttpSecurity http) throws Exception {

        final LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(localAuthenticationEndpointProperties.getLoginEndpoint());
        final AuthenticationEntryPoint authenticationEntryPoint =
                new RedirectToIdentityProviderIfUnambiguousElseToLoginPageEntryPoint(loginUrlAuthenticationEntryPoint, localAuthenticationSettingsCache, identityProviderService);

        final OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        final RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();


        http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(authenticationEntryPoint))
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher));

        http.apply(authorizationServerConfigurer);
        return http.build();
    }

    /**
     * Creates a bean that constructs the AuthorizationServerSettings based upon the
     * configurations from {@link SecurityEndpointProperties}.
     *
     * @return the oauth2 provider settings created from the {@link SecurityEndpointProperties}.
     */
    @Bean
    public AuthorizationServerSettings providerSettings() {
        return AuthorizationServerSettings.builder()
                .authorizationEndpoint(securityEndpointProperties.getAuthorizeEndpoint())
                .tokenEndpoint(securityEndpointProperties.getTokenEndpoint())
                .jwkSetEndpoint(securityEndpointProperties.getJwksEndpoint())
                .build();
    }
}
