package eu.firmax.cms.auth.security;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.controller.TestLoginController;
import eu.firmax.cms.auth.idp.IdentityProviderService;
import eu.firmax.cms.auth.idp.openid.OidcIdentityProviderEndpointProperties;
import eu.firmax.cms.auth.idp.saml.SamlIdentityProviderEndpointProperties;
import eu.firmax.cms.auth.idp.saml.bundid.BundIdHelper;
import eu.firmax.cms.auth.idp.saml.relyingpartyregistration.SamlIdentityProviderRepository;
import eu.firmax.cms.auth.idp.saml.samlsettings.SamlSettingsCache;
import eu.firmax.cms.auth.idp.saml.serviceprovidermetadata.SamlServiceProviderMetadataCache;
import eu.firmax.cms.auth.idp.saml.serviceprovidermetadata.SamlServiceProviderMetadataService;
import eu.firmax.cms.auth.idp.saml.usermapping.SamlPrincipalService;
import eu.firmax.cms.auth.local.BannedIpAuthenticationException;
import eu.firmax.cms.auth.local.LocalAuthenticationEndpointProperties;
import eu.firmax.cms.auth.local.settings.LocalAuthenticationSettingsCache;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;

/**
 * Configurer that enables the necessary settings in order to support single sign on (SSO) with different
 * identity providers in the spring security filter chain to which this configurer is applied to.
 */
@RequiredArgsConstructor
public final class FederatedIdentityConfigurer extends AbstractHttpConfigurer<FederatedIdentityConfigurer, HttpSecurity> {

    public static final String BASE_URL_VARIABLE = "{baseUrl}";

    @Override
    public void init(@NonNull final HttpSecurity http) throws Exception {

        final ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);

        // Property beans
        final SecurityEndpointProperties securityEndpointProperties = applicationContext.getBean(SecurityEndpointProperties.class);
        final LocalAuthenticationEndpointProperties localAuthenticationEndpointProperties = applicationContext.getBean(LocalAuthenticationEndpointProperties.class);
        final SamlIdentityProviderEndpointProperties samlIdentityProviderEndpointProperties = applicationContext.getBean(SamlIdentityProviderEndpointProperties.class);
        final OidcIdentityProviderEndpointProperties oidcIdentityProviderEndpointProperties = applicationContext.getBean(OidcIdentityProviderEndpointProperties.class);

        // Cache beans
        final LocalAuthenticationSettingsCache localAuthenticationSettingsCache = applicationContext.getBean(LocalAuthenticationSettingsCache.class);
        final SamlServiceProviderMetadataCache samlServiceProviderMetadataCache = applicationContext.getBean(SamlServiceProviderMetadataCache.class);
        final SamlSettingsCache samlSettingsCache = applicationContext.getBean(SamlSettingsCache.class);

        // Service beans
        final IdentityProviderService identityProviderService = applicationContext.getBean(IdentityProviderService.class);
        final SamlPrincipalService samlPrincipalService = applicationContext.getBean(SamlPrincipalService.class);
        final SamlServiceProviderMetadataService samlServiceProviderMetadataService = applicationContext.getBean(SamlServiceProviderMetadataService.class);

        // Repository beans
        final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository = applicationContext.getBean(RelyingPartyRegistrationRepository.class);
        final ClientRegistrationRepository clientRegistrationRepository = applicationContext.getBean(ClientRegistrationRepository.class);
        final Saml2LogoutRequestRepository saml2LogoutRequestRepository = applicationContext.getBean(Saml2LogoutRequestRepository.class);
        final CookieCsrfTokenRepository cookieCsrfTokenRepository = applicationContext.getBean(CookieCsrfTokenRepository.class);
        final CsrfTokenRequestHandler csrfTokenRequestHandler = applicationContext.getBean(CsrfTokenRequestHandler.class);

        // Misc beans
        final AuthenticationEventPublisher authenticationEventPublisher = applicationContext.getBean(AuthenticationEventPublisher.class);

        // New objects and configurations
        final AuthFailureHandler authFailureHandler = new AuthFailureHandler(localAuthenticationEndpointProperties);
        final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        final OpenSaml4AuthenticationRequestResolver openSaml4AuthenticationRequestResolver = new OpenSaml4AuthenticationRequestResolver(relyingPartyRegistrationResolver);

        final LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(localAuthenticationEndpointProperties.getLoginEndpoint());
        final RedirectToIdentityProviderIfUnambiguousElseToLoginPageEntryPoint authenticationEntryPoint = new RedirectToIdentityProviderIfUnambiguousElseToLoginPageEntryPoint(loginUrlAuthenticationEntryPoint, localAuthenticationSettingsCache, identityProviderService);

        final Saml2MetadataFilter relyingPartyMetaDataEndpointFilter = samlServiceProviderMetadataService.createRelyingPartyMetaDataEndpointFilter(relyingPartyRegistrationResolver, samlServiceProviderMetadataCache);

        final OidcClientInitiatedLogoutSuccessHandler oidcClientInitiatedLogoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        oidcClientInitiatedLogoutSuccessHandler.setPostLogoutRedirectUri(BASE_URL_VARIABLE);

        http
                // Populates ExceptionTranslationFilter with our custom authenticationEntryPoint, which will be called by spring, if a AuthenticationException or AccessDeniedException gets thrown.
                .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(authenticationEntryPoint))
                // Configures the local authentication (e.g. username/password)
                .formLogin(formLogin -> formLogin
                        .loginPage(localAuthenticationEndpointProperties.getLoginEndpoint())
                        .failureHandler(authFailureHandler))
                // Configures the oauth2 sso procedure.
                .oauth2Login(oauth2Login -> oauth2Login
                        .failureHandler(authFailureHandler)
                        .loginProcessingUrl(oidcIdentityProviderEndpointProperties.getLoginProcessingEndpoint())
                        .defaultSuccessUrl("/")
                        .authorizationEndpoint(authorizationEndpointConfig ->
                                authorizationEndpointConfig.baseUri(oidcIdentityProviderEndpointProperties.getLoginInitiateEndpoint()))
                )
                // Configures the saml2 sso procedure.
                .saml2Login(saml2Login -> saml2Login
                        .failureHandler(authFailureHandler)
                        .authenticationRequestResolver(new CustomSaml2AuthenticationRequestResolver(
                                openSaml4AuthenticationRequestResolver, samlSettingsCache))
                        .loginProcessingUrl(samlIdentityProviderEndpointProperties.getLoginProcessingEndpoint())
                        .defaultSuccessUrl("/")
                        .withObjectPostProcessor(new SamlAuthenticationConverterPostProcessor(samlPrincipalService)))
                // Configures the oauth and local authentication single logout (SLO) procedure.
                .logout(logout -> logout
                        .logoutUrl(securityEndpointProperties.getLogoutInitiateEndpoint())
                        .logoutSuccessHandler(oidcClientInitiatedLogoutSuccessHandler))
                // Configures the saml2 single logout (SLO) procedure.
                .saml2Logout(logout -> logout
                        .logoutUrl(securityEndpointProperties.getLogoutInitiateEndpoint())
                        .logoutRequest(req -> req
                                .logoutUrl(samlIdentityProviderEndpointProperties.getLogoutRequestEndpoint())
                                .logoutRequestRepository(saml2LogoutRequestRepository))
                        .logoutResponse(res -> res
                                .logoutUrl(samlIdentityProviderEndpointProperties.getLogoutResponseEndpoint())))
                // Adds the endpoint that handles requests for requesting the saml2 service provider metadata information.
                .addFilterBefore(relyingPartyMetaDataEndpointFilter, Saml2WebSsoAuthenticationFilter.class)
                // Configures the defense mechanism for CSRF.
                .csrf(csrf -> csrf
                        .csrfTokenRepository(cookieCsrfTokenRepository)
                        .csrfTokenRequestHandler(csrfTokenRequestHandler)
                        .ignoringRequestMatchers(TestLoginController.CLEAR_ATTEMPTS_ENDPOINT));

        http.getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationEventPublisher(authenticationEventPublisher);

    }

    /**
     * Configures an authentication failure handler, that adds the authentication error to the url parameters
     * and redirects the user back to the login page.
     */
    @RequiredArgsConstructor
    public static class AuthFailureHandler extends SimpleUrlAuthenticationFailureHandler {

        public static final String BANNED_ERROR = "banned";
        public static final String BAD_CREDENTIALS_ERROR = "badcredentials";
        public static final String BASE_ERROR_ENDPOINT = "?error=";

        @NonNull
        private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

        @NonNull
        private final LocalAuthenticationEndpointProperties localAuthenticationEndpointProperties;

        @Override
        public void onAuthenticationFailure(@NonNull final HttpServletRequest request,
                                            @NonNull final HttpServletResponse response,
                                            @NonNull final AuthenticationException exception) throws IOException {

            final String error;
            if (exception instanceof BannedIpAuthenticationException) {
                error = BANNED_ERROR;
            } else {
                error = BAD_CREDENTIALS_ERROR;
            }

            redirectStrategy.sendRedirect(request, response, localAuthenticationEndpointProperties.getLoginEndpoint() + BASE_ERROR_ENDPOINT + error);
        }
    }

    /**
     * Spring doesn't provide a {@link OAuth2UserService} equivalent for saml user, which is why we have to
     * manually override the response authentication converter to convert the received saml response
     * into an applicable saml principal for our application.
     */
    @RequiredArgsConstructor
    private static class SamlAuthenticationConverterPostProcessor implements ObjectPostProcessor<OpenSaml4AuthenticationProvider> {

        @NonNull
        private final SamlPrincipalService samlPrincipalService;

        @Override
        public <O extends OpenSaml4AuthenticationProvider> O postProcess(@NonNull final O object) {
            object.setResponseAuthenticationConverter(samlPrincipalService);
            return object;
        }
    }

    /**
     * Used to customize the {@link Saml2WebSsoAuthenticationRequestFilter}.
     * Customizes currently the following:
     * <ul>
     *     <li>URL on which the filter listens to initiated saml authentication requests, before sending Saml2 AuthNRequests</li>
     *     <li>Customizes the AuthNRequest itself by adding a applicable saml extension</li>
     * </ul>
     */
    @RequiredArgsConstructor
    private static class CustomSaml2AuthenticationRequestResolver implements Saml2AuthenticationRequestResolver {

        @NonNull
        private final SamlIdentityProviderEndpointProperties samlIdentityProviderEndpointProperties = new SamlIdentityProviderEndpointProperties();

        @NonNull
        private final RequestMatcher requestMatcher = new AntPathRequestMatcher(samlIdentityProviderEndpointProperties.getLoginInitiateEndpoint());

        @NonNull
        private final OpenSaml4AuthenticationRequestResolver delegate;

        @NonNull
        private final SamlSettingsCache samlSettingsCache;

        @Override
        public <T extends AbstractSaml2AuthenticationRequest> T resolve(@NonNull final HttpServletRequest request) {
            final RequestMatcher.MatchResult matcher = this.requestMatcher.matcher(request);
            if (!matcher.isMatch()) {
                return null;
            }

            delegate.setAuthnRequestCustomizer(this::customizeAuthnRequest);
            delegate.setRequestMatcher(requestMatcher);

            return delegate.resolve(request);
        }

        /**
         * Customizes the Saml2-AuthNRequest by adding a custom requested authN context that adds the STORK QAA Level,
         * depending on the resolved relying on party registration.
         *
         * @param requestContext the AuthNRequestContext which will be modified to use the STORK QAA Level if applicable.
         */
        private void customizeAuthnRequest(@NonNull final OpenSaml4AuthenticationRequestResolver.AuthnRequestContext requestContext) {

            final SamlIdentityProviderRepository.SamlProviderSettings samlProviderSettings = samlSettingsCache.getSamlProviderSettings(
                    requestContext.getRelyingPartyRegistration().getRegistrationId());

            if (samlProviderSettings.storkQaaLevel() != null) {
                final AuthnRequest authnRequest = requestContext.getAuthnRequest();
                authnRequest.setRequestedAuthnContext(BundIdHelper.createRequestedContext(samlProviderSettings.storkQaaLevel()));
            }
        }
    }
}
