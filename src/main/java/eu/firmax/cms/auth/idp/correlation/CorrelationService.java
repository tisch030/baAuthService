package eu.firmax.cms.auth.idp.correlation;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.IdentityProviderCache;
import eu.firmax.cms.auth.idp.IdentityProviderService;
import eu.firmax.cms.auth.idp.openid.usermapping.CustomOidcPrincipal;
import eu.firmax.cms.auth.idp.saml.usermapping.CustomSamlPrincipal;
import eu.firmax.cms.auth.local.LocalAuthenticationProvider;
import eu.firmax.cms.auth.user.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;


/**
 * Service that correlates the authentication provided by an identity provider with a user's local credentials
 */
@Service
@RequiredArgsConstructor
public class CorrelationService {

    @NonNull
    private final IdentityProviderService identityProviderService;

    @NonNull
    private final IdentityProviderCache identityProviderCache;

    @NonNull
    private final CorrelationRepository correlationRepository;

    @NonNull
    private final LocalAuthenticationProvider localAuthenticationProvider;

    @NonNull
    private final OAuth2AuthorizationService oAuth2AuthorizationService;


    /**
     * Creates the correlation between an already existing local access of a user with the provided authentication
     * information of an identity provider, which the user used to authenticate himself with.
     * <p>
     * The first step in creating a correlation is to check the given username and password,
     * which are used as credentials for local access. The correlation is therefore only created if the specified credentials are valid.
     * After that we create a new {@link Saml2Authentication} or {@link OAuth2AuthenticationToken}, depending
     * on the given authentication which has been created after the user authenticated himself at a provider.
     * The new authentication still contains the information that came from the identity provider, but now also
     * contains the user details of a person based upon the previously executed local authentication.
     * Once that's done, we exchange the old authentication with the new authentication in the {@link SecurityContext}
     * and save the updated security context in the session of the authenticated user.
     * <p>
     * We need to create a new {@link Saml2Authentication} or {@link OAuth2AuthenticationToken}, otherwise the
     * single logout mechanism will not work anymore.
     * Spring decides depending on the authentication if the user used an identity provider.
     * This is why we cant just replace the previous authentication in the security context with a {@link UsernamePasswordAuthenticationToken}
     * <p>
     * After a successful authentication at an identity provider, our authorization server creates a
     * {@link OAuth2Authorization} which contains the created authorization code and the authentication object, which
     * links to either a SAML or OIDC authentication.
     * When a client exchanges the authorization code against an access token,
     * the {@link OAuth2AuthorizationCodeAuthenticationProvider} will retrieve that {@link OAuth2Authorization}
     * based on the received authorization code and creates an access token based on the {@link Authentication} that
     * is included in the determined {@link OAuth2Authorization}.
     * That authentication does not have a principal with user details, because the {@link OAuth2Authorization}
     * does not contain the new authentication of the security context.
     * This would lead to an authentication error at the resource server, because the generated access token does not
     * contain information about a person.
     * In order to prevent that, we also update the authentication inside a {@link OAuth2Authorization} that
     * correlates to the authorization code.
     *
     * @param username                 the username of a user.
     * @param password                 the password af a user.
     * @param authorizationCode        the authorization code which has been issued after the authentication at an identity provider.
     * @param authenticationAtProvider the authentication that has been created after the user authenticated at an identity provider.
     * @param request                  the request which contains the session of the authenticated user.
     * @throws AuthenticationException  if the given username and password combination could not be verified.
     * @throws IllegalArgumentException if for the given authorization code no saved {@link OAuth2Authorization} could be found.
     */
    public void createCorrelationBetweenLocalCredentialsAndProvider(@NonNull final String username,
                                                                    @NonNull final String password,
                                                                    @NonNull final String authorizationCode,
                                                                    @NonNull final Authentication authenticationAtProvider,
                                                                    @NonNull final HttpServletRequest request) throws AuthenticationException, IllegalArgumentException {

        // Make sure that we have an existing authorization that contains the received authorization code.
        // Otherwise, we got a not allowed authorization code which means we won't issue that code and thus don't need
        // to map idp information with the local credentials.
        final OAuth2Authorization authorizationOfOldAuthentication = oAuth2AuthorizationService.findByToken(authorizationCode, new OAuth2TokenType(OAuth2ParameterNames.CODE));
        if (authorizationOfOldAuthentication == null) {
            throw new IllegalArgumentException();
        }

        // Authenticate user with local credentials - authentication errors for example wrong credentials will
        // lead to an authentication exception and will be propagated up.
        final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        final Authentication authenticationWithLocalCredentials = localAuthenticationProvider.authenticate(usernamePasswordAuthenticationToken);

        // Create correlation, depending on the used identity provider.
        final Authentication idpAuthenticationWithCorrelatedUserDetails;
        if (authenticationAtProvider.getPrincipal() instanceof CustomSamlPrincipal) {
            idpAuthenticationWithCorrelatedUserDetails = this.createCorrelationForSamlProvider(authenticationAtProvider, authenticationWithLocalCredentials);
        } else {
            idpAuthenticationWithCorrelatedUserDetails = this.createCorrelationForOidcProvider(authenticationAtProvider, authenticationWithLocalCredentials);
        }

        // Exchange authorization which contains the old authentication with a new authorization that contains the new authentication.
        final OAuth2Authorization authorizationOfNewAuthentication = OAuth2Authorization.from(authorizationOfOldAuthentication)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .principalName(authenticationWithLocalCredentials.getName())
                .attribute(Principal.class.getName(), idpAuthenticationWithCorrelatedUserDetails)
                .build();
        oAuth2AuthorizationService.remove(authorizationOfOldAuthentication);
        oAuth2AuthorizationService.save(authorizationOfNewAuthentication);

        // Update security context and session.
        final SecurityContext sc = SecurityContextHolder.getContext();
        sc.setAuthentication(idpAuthenticationWithCorrelatedUserDetails);
        final HttpSession session = request.getSession();
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);
    }


    /**
     * Creates a new {@link Saml2Authentication} based upon the original authentication at a provider
     * and which contains the user details that are being provided by the authentication that has been executed
     * by verifying the local credentials of a user.
     * Performs also the saving of the correlation value.
     *
     * @param authenticationAtProvider           the authentication at the provider.
     * @param authenticationWithLocalCredentials the authentication based upon local credentials.
     * @return the newly created authentication which contains the saml information and local user detail information.
     */
    @NonNull
    private Authentication createCorrelationForSamlProvider(@NonNull final Authentication authenticationAtProvider,
                                                            @NonNull final Authentication authenticationWithLocalCredentials) {

        // Create the new SAML authentication based on the information of the original SAML authentication
        // and the user details provided by the authentication done by checking the username and password.
        final CustomSamlPrincipal samlPrincipalAtProvider = (CustomSamlPrincipal) authenticationAtProvider.getPrincipal();
        final CustomSamlPrincipal samlPrincipalWithUserDetails = new CustomSamlPrincipal(
                (CustomUserDetails) authenticationWithLocalCredentials.getPrincipal(),
                samlPrincipalAtProvider.getName(),
                samlPrincipalAtProvider.getAttributes(),
                samlPrincipalAtProvider.getRelyingPartyRegistrationId(),
                samlPrincipalAtProvider.getSessionIndexes());

        final Saml2Authentication saml2AuthenticationAtProvider = (Saml2Authentication) authenticationAtProvider;
        final Saml2Authentication saml2AuthenticationWithUserDetails = new Saml2Authentication(
                samlPrincipalWithUserDetails, saml2AuthenticationAtProvider.getSaml2Response(), saml2AuthenticationAtProvider.getAuthorities());
        copyDetails(authenticationAtProvider, saml2AuthenticationWithUserDetails);
        saml2AuthenticationWithUserDetails.setAuthenticated(authenticationAtProvider.isAuthenticated());

        // Determine the correlation value and save it.
        final Map<String, List<Object>> attributes = samlPrincipalAtProvider.getAttributes();
        final IdentityProviderService.IdentityProviderAndUniqueIdentifierMappingAttribute mapping = getIdpMappings(samlPrincipalAtProvider.getRelyingPartyRegistrationId());

        final List<Object> mappingValues = attributes.get(mapping.mappingAttribute());
        if (mappingValues == null || mappingValues.size() != 1) {
            throw new AuthenticationServiceException("The mapping attribute is not part of or doesn't have a single value in the SAML assertions in the response");
        }
        final Object mappingValue = mappingValues.iterator().next();

        final String identityProviderId = identityProviderCache.getIdentityProviderId(samlPrincipalAtProvider.getRelyingPartyRegistrationId());
        correlationRepository.saveCorrelation(mappingValue.toString(), samlPrincipalWithUserDetails.getCredentialId(), identityProviderId);

        return saml2AuthenticationWithUserDetails;
    }

    /**
     * Creates a new {@link OAuth2AuthenticationToken} based upon the original authentication at a provider
     * and which contains the user details that are being provided by the authentication that has been executed
     * by verifying the local credentials of a user.
     * Performs also the saving of the correlation value.
     *
     * @param authenticationAtProvider           the authentication at the provider.
     * @param authenticationWithLocalCredentials the authentication based upon local credentials.
     * @return the newly created authentication which contains the saml information and local user detail information.
     */
    @NonNull
    private Authentication createCorrelationForOidcProvider(@NonNull final Authentication authenticationAtProvider,
                                                            @NonNull final Authentication authenticationWithLocalCredentials) {

        // Create the new OIDC authentication based on the information of the original OIDC authentication
        // and the user details provided by the authentication done by checking the username and password.
        final CustomOidcPrincipal oidcPrincipalAtProvider = (CustomOidcPrincipal) authenticationAtProvider.getPrincipal();
        final CustomOidcPrincipal oidcPrincipalWithUserDetails = new CustomOidcPrincipal(
                (CustomUserDetails) authenticationWithLocalCredentials.getPrincipal(),
                oidcPrincipalAtProvider.getIdToken(),
                oidcPrincipalAtProvider.getClientRegistrationId());

        final OAuth2AuthenticationToken oidcAuthenticationAtProvider = (OAuth2AuthenticationToken) authenticationAtProvider;
        final OAuth2AuthenticationToken oidcAuthenticationWithUserDetails = new OAuth2AuthenticationToken(
                oidcPrincipalWithUserDetails, oidcAuthenticationAtProvider.getAuthorities(), oidcAuthenticationAtProvider.getAuthorizedClientRegistrationId());
        copyDetails(authenticationAtProvider, oidcAuthenticationWithUserDetails);
        oidcAuthenticationWithUserDetails.setAuthenticated(authenticationAtProvider.isAuthenticated());


        // Determine the correlation value and save it.
        final Map<String, Object> claims = oidcPrincipalAtProvider.getClaims();
        final IdentityProviderService.IdentityProviderAndUniqueIdentifierMappingAttribute mapping = getIdpMappings(oidcPrincipalAtProvider.getClientRegistrationId());

        final Object mappingValue = claims.get(mapping.mappingAttribute());
        if (mappingValue == null) {
            throw new AuthenticationServiceException("The mapping attribute is not part of the OIDC claims in the id token");
        }

        final String identityProviderId = identityProviderCache.getIdentityProviderId(oidcPrincipalAtProvider.getClientRegistrationId());
        correlationRepository.saveCorrelation(mappingValue.toString(), oidcPrincipalWithUserDetails.getCredentialId(), identityProviderId);

        return oidcAuthenticationWithUserDetails;
    }

    /**
     * Retrieves the {@link IdentityProviderService.IdentityProviderAndUniqueIdentifierMappingAttribute} of the given
     * identity provider.
     *
     * @param identityProviderName the name of the identity provider for which one wants the unique identifier attribute.
     * @return the {@link IdentityProviderService.IdentityProviderAndUniqueIdentifierMappingAttribute} of the given identity provider.
     */
    @NonNull
    private IdentityProviderService.IdentityProviderAndUniqueIdentifierMappingAttribute getIdpMappings(@NonNull final String identityProviderName) {
        return identityProviderService.getIdentityProviderUniqueIdentifierMappingAttribute(identityProviderName)
                .orElseThrow(() -> new AuthenticationServiceException("Unknown identity provider " + identityProviderName));
    }

    /**
     * Based upon the implemenation in {@link ProviderManager}. Copies information like IP-Address.
     *
     * @param source the source authentication from which the details should be copied.
     * @param dest   the authentication which should contain the copied details.
     */
    private void copyDetails(@NonNull final Authentication source,
                             @NonNull final Authentication dest) {
        if (dest instanceof final AbstractAuthenticationToken token && dest.getDetails() == null) {
            token.setDetails(source.getDetails());
        }
    }


}
