package eu.firmax.cms.auth.idp.openid.usermapping;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.user.AbstractDelegatingCustomPrincipal;
import eu.firmax.cms.auth.user.CustomPrincipal;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

/**
 * Principal used for all authentications made via OpenID Connect.
 * Delegates all calls to another principal except for the claims and the name,
 * which are extracted from the ID token.
 */
public class CustomOidcPrincipal extends AbstractDelegatingCustomPrincipal implements OidcUser {

    @Getter
    @NonNull
    private final OidcIdToken idToken;

    @Getter
    @NonNull
    private final String clientRegistrationId;


    public CustomOidcPrincipal(@NonNull final CustomPrincipal principal,
                               @NonNull final OidcIdToken idToken,
                               @NonNull final String clientRegistrationId) {
        super(principal);
        this.idToken = idToken;
        this.clientRegistrationId = clientRegistrationId;
    }

    @Override
    @NonNull
    public Map<String, Object> getClaims() {
        return this.idToken.getClaims();
    }

    /**
     * In contrast to the default {@link OidcUserService} and {@link DefaultOidcUser}, we don't need to wrap the
     * claims inside a {@link OidcUserInfo}.
     * We get the necessary information directly from the received claims.
     * <p>
     * If future requirements require to implement the use of the UserInfoEndpoint, make sure to correctly validate them.
     * This means to make sure that the user info response contain a SUB claim as per OIDC specification https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
     * and that the SUB claim received from the user info endpoint matches the SUB claim of the ID-Token.
     * See {@link OidcUserService} for more information.
     *
     * @return always null as the OidcUserInfo. Use the claims to get information about the user.
     */
    @Override
    @Nullable
    public OidcUserInfo getUserInfo() {
        return null;
    }

    @Override
    @NonNull
    public Map<String, Object> getAttributes() {
        return this.getClaims();
    }

    @Override
    @NonNull
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptySet();
    }

    @Override
    @NonNull
    public String getName() {
        return this.getClaims().get(IdTokenClaimNames.SUB).toString();
    }

    @Override
    @NonNull
    public String toString() {
        return getClass().getName() + "[super=" + super.toString() + ", idToken=" + idToken + ", clientRegistrationId=" + clientRegistrationId + "]";
    }
}
