package eu.firmax.cms.auth.idp.openid.usermapping;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.IdentityProviderService;
import eu.firmax.cms.auth.local.database.UserDetailsRepository;
import eu.firmax.cms.auth.user.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Creates a {@link CustomOidcPrincipal} based upon the claims and "sub" value of the received id token.
 * If the user is a recurring user, we want to load the user details from the database and add them to the OIDC principal.
 * <p>
 * For each identity provider configuration, a unique identifier attribute had to be configured.
 * This unique identifier attribute is used to determine the identity provider's correlation attribute, by which
 * a user is uniquely identified and through a look-up in the database with that correlation value the service determines
 * if the user is a recurring user.
 * <p>
 * If no correlated user could be found, a custom user details object will be mapped to the OIDC principal,
 * indicating that the user is new and does not yet have a profile in our application.
 */
@Component
@RequiredArgsConstructor
public class OidcPrincipalService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    @NonNull
    private final UserDetailsRepository userDetailsRepository;

    @NonNull
    private final IdentityProviderService identityProviderService;

    @Override
    public OidcUser loadUser(@NonNull final OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        final String identityProviderRegistrationId = userRequest.getClientRegistration().getRegistrationId();
        final CustomUserDetails userDetails = retrieveUserDetails(identityProviderRegistrationId, userRequest.getIdToken().getClaims());
        return new CustomOidcPrincipal(userDetails, userRequest.getIdToken(), identityProviderRegistrationId);
    }

    @NonNull
    private CustomUserDetails retrieveUserDetails(@NonNull final String identityProviderRegistrationId,
                                                  @NonNull final Map<String, Object> claims) {

        final IdentityProviderService.IdentityProviderAndUniqueIdentifierMappingAttribute mapping =
                identityProviderService.getIdentityProviderUniqueIdentifierMappingAttribute(identityProviderRegistrationId)
                        .orElseThrow(() -> new AuthenticationServiceException("Unknown identity provider " + identityProviderRegistrationId));

        final Object mappingValue = claims.get(mapping.mappingAttribute());
        if (mappingValue == null) {
            throw new AuthenticationServiceException("The mapping attribute is not part of the OIDC claims in the id token.");
        }

        return userDetailsRepository.lookupUserByIdentityProviderMapping(mapping.identityProviderId(), mappingValue.toString())
                .orElse(new CustomUserDetails(
                        null,
                        null,
                        false,
                        false,
                        null,
                        null
                ));
    }
}
