package eu.firmax.cms.auth.idp.saml.usermapping;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.user.AbstractDelegatingCustomPrincipal;
import eu.firmax.cms.auth.user.CustomPrincipal;
import lombok.Getter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;

import java.util.List;
import java.util.Map;

/**
 * Principal used for all authentications made via SAML.
 * Delegates all calls to another principal except for the assertion attributes and the name,
 * which are extracted from the SAML response.
 */
public class CustomSamlPrincipal extends AbstractDelegatingCustomPrincipal implements Saml2AuthenticatedPrincipal {

    @Getter
    @NonNull
    private final String name;

    @Getter
    @NonNull
    private final Map<String, List<Object>> attributes;

    @Getter
    @NonNull
    private final String relyingPartyRegistrationId;

    @Getter
    @NonNull
    private final List<String> sessionIndexes;

    public CustomSamlPrincipal(@NonNull final CustomPrincipal principal,
                               @NonNull final String name,
                               @NonNull final Map<String, List<Object>> attributes,
                               @NonNull final String relyingPartyRegistrationId,
                               @NonNull final List<String> sessionIndexes) {
        super(principal);
        this.name = name;
        this.attributes = attributes;
        this.relyingPartyRegistrationId = relyingPartyRegistrationId;
        this.sessionIndexes = sessionIndexes;
    }

    @Override
    @NonNull
    public String toString() {
        return getClass().getName() + "[super=" + super.toString() + ", name=" + name + ", attributes=" +
                attributes + ", relyingPartyRegistrationId=" + relyingPartyRegistrationId + ", sessionIndexes=" +
                sessionIndexes + "]";
    }
}
