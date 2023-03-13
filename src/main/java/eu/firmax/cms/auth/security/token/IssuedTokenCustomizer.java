package eu.firmax.cms.auth.security.token;

import eu.firmax.cms.auth.user.CustomPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Customizes the access token which is being handed out by our authorization server after
 * a successful authentication and the exchange of an authorization code.
 * <p>
 * The following customization is currently being made:
 * <ul>
 *     <li>Adds a unique id to the token</li>
 *     <li>Replace the JWT.SUB claim (which by default contains the username) with the person's id</li>
 *     <li>Sets the username for the JWT.PREFERRED_USERNAME, which was previously the SUB claim.</li>
 * </ul>
 */
@Component
public final class IssuedTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(final JwtEncodingContext context) {
        if (OAuth2ParameterNames.ACCESS_TOKEN.equals(context.getTokenType().getValue())) {
            final Authentication token = context.getPrincipal();
            final CustomPrincipal principal = (CustomPrincipal) token.getPrincipal();
            final String personId = principal.getPersonId();
            final String username = principal.getUsername();

            context.getClaims().claims(existingClaims -> {
                // Currently the subject is the username, but we want that to be the person id.
                existingClaims.put(StandardClaimNames.SUB, personId);
                existingClaims.put(StandardClaimNames.PREFERRED_USERNAME, username);

                // Add a unique ID to each token to make identification possible.
                existingClaims.put(JwtClaimNames.JTI, UUID.randomUUID().toString());
            });
        }
    }

}
