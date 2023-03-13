package eu.firmax.cms.auth.security;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.IdentityProviderService;
import eu.firmax.cms.auth.local.settings.LocalAuthenticationSettings;
import eu.firmax.cms.auth.local.settings.LocalAuthenticationSettingsCache;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import java.io.IOException;

/**
 * {@link AuthenticationEntryPoint} implementation that determines if the login site should be displayed for
 * the authentication procedure in case multiple authentication methods can be used (e.g. username/password or
 * oauth/saml identity providers given).
 * <p>
 * If the local authentication is disabled (i.e. username/password) and exactly one identity provider has been
 * configured (doesn't matter which type is used), then the user will be directly redirected to that
 * identity provider for authentication.
 */
@RequiredArgsConstructor
public final class RedirectToIdentityProviderIfUnambiguousElseToLoginPageEntryPoint implements AuthenticationEntryPoint {

    @NonNull
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @NonNull
    private final AuthenticationEntryPoint delegate;

    @NonNull
    private final LocalAuthenticationSettingsCache localAuthenticationSettingsCache;

    @NonNull
    private final IdentityProviderService identityProviderService;

    @Override
    public void commence(@NonNull final HttpServletRequest request,
                         @NonNull final HttpServletResponse response,
                         @NonNull final AuthenticationException authenticationException) throws IOException, ServletException {

        // Check if we can only authenticate with exactly one external IdP and redirect to the login page of that IdP.
        final LocalAuthenticationSettings settings = localAuthenticationSettingsCache.getLocalAuthenticationSettings();
        if (settings == null || !settings.localAuthenticationEnabled()) {
            final String idpUrl = identityProviderService.getIdentityProviderUrlIfUnambiguous(request);
            if (idpUrl != null) {
                this.redirectStrategy.sendRedirect(request, response, idpUrl);
                return;
            }
        }

        // Not exactly sure how to log in => redirect to login page.
        this.delegate.commence(request, response, authenticationException);
    }

}
