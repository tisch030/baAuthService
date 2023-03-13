package eu.firmax.cms.auth.security;

import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.stereotype.Component;

/**
 * Customizes the session cookie by extending the {@link DefaultCookieSerializer}.
 * <p>
 * Currently, customizes the following settings:
 * <ul>
 *     <li>Cookie name (in order to prevent the overlapping of the session cookie name of the temporary client implementation)</li>
 * </ul>
 */
@Component
public class CustomSessionCookieSerializer extends DefaultCookieSerializer {

    private static final String COOKIE_NAME = "AUTHSESSIONID";

    // There is no other way to set the settings in the parent class, so a non-final method call is necessary here.
    public CustomSessionCookieSerializer() {
        super();
        this.setCookieName(COOKIE_NAME);
        this.setUseSecureCookie(true);
        // Since we can get redirected from an identity provider to the auth server and we need the cookie for that,
        // we can't enforce the same site policy. This makes the cookie vulnerable towards CSRF attacks, which is why
        // we enforce CSRF cookies for all auth endpoints.
        this.setSameSite("none");
    }
}
