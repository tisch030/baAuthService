package eu.firmax.cms.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

/**
 * Configures the {@link CookieCsrfTokenRepository} and {@link CsrfTokenRequestHandler} bean.
 * The token repository stores the csrf token inside a cookie and http only is set to false in order to allow
 * the frontend/client to read the cookie and add it to request.
 * Springs default request handler is {@link XorCsrfTokenRequestAttributeHandler}, but this is not applicable
 * because the frontend is not able to create or read the XOR'd csrf value.
 * Thats why we use the {@link CsrfTokenRequestHandler}, which accepts and validates the raw csrf value.
 * The XOR'd csrf value is needed to mitigate the CSRF BREACH vulnerability/attack pattern, but that attack pattern
 * is not applicable for our authorization server because of the following things:
 * <ul>
 *     <li>We dont use http compression for the authorization server endpoints</li>
 *     <li>The "only" endpoints which are protected against csrf are the login and logout endpoints (currently, be careful in future updates.
 *     All other endpoints, like initiating the login procedure, receiving saml post response etc are handled separately by spring and are not
 *      handled by the {@link CsrfFilter} anyway, because the CSRF protection there is implemented trough the state
 *      parameter defined by the oauth standard.</li>
 *      <li>Even if http compression is enabled for the authorization server endpoints, the implementation of
 *      the rate limiter prevents an attacker of sending multiple wrong credentials in a short period of time.
 *      This way we should be able to monitor potential security threats early enough and act accordingly.
 *      And in case the attacker still gets access to the correct CSRF token for the authentication endpoint, the
 *      session fixation protection prevents the attack, where the attacker tries to inject his session
 *      into the browser/client of an victim, because after a sucessfull authentication, spring creates
 *      automatically a new session.
 *      And in case the attacker gets the CSRF token for the logout endpoint, the attacker does not pose
 *      a high security threat, because the victim just gets only logged out and gets annoyed at most.</li>
 *
 * </ul>
 *
 * @see <a href="https://www.breachattack.com">CSRF BREACH</a>
 * <p>
 */
@Configuration
public class CsrfTokenConfig {

    @Bean
    public CookieCsrfTokenRepository cookieCsrfTokenRepository() {
        return CookieCsrfTokenRepository.withHttpOnlyFalse();
    }

    @Bean
    public CsrfTokenRequestHandler csrfTokenRequestHandler() {
        return new CsrfTokenRequestAttributeHandler();
    }
}
