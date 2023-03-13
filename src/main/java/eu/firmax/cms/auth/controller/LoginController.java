package eu.firmax.cms.auth.controller;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.IdentityProviderService;
import eu.firmax.cms.auth.idp.correlation.CorrelationService;
import eu.firmax.cms.auth.idp.openid.usermapping.CustomOidcPrincipal;
import eu.firmax.cms.auth.idp.saml.usermapping.CustomSamlPrincipal;
import eu.firmax.cms.auth.local.BannedIpAuthenticationException;
import eu.firmax.cms.auth.local.ratelimiting.LoginAttemptService;
import eu.firmax.cms.auth.security.FederatedIdentityConfigurer;
import eu.firmax.cms.auth.user.CustomPrincipal;
import eu.firmax.cms.auth.user.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;

/**
 * This controller provides all endpoints necessary to HTML pages which are used during the login procedure.
 */
@Controller
@RequiredArgsConstructor
public class LoginController {

    private static final String FORM_USERNAME = "username";
    private static final String FORM_PASSWORD = "password";
    private static final String LOGIN_ENDPOINT = "/api/auth/login";
    private static final String LOGIN_RESULT_ENDPOINT = "/api/auth/result";
    private static final String IDP_MAPPING_ENDPOINT = "/api/auth/idp-mapping";

    @NonNull
    private final CorrelationService correlationService;

    @NonNull
    private final IdentityProviderService identityProviderService;

    @NonNull
    private final LoginAttemptService loginAttemptService;

    @NonNull
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @NonNull
    private final OAuth2AuthorizationService oAuth2AuthorizationService;


    @GetMapping("/")
    public String index(@NonNull final Model model,
                        @NonNull final Principal principal) {
        if (principal instanceof UsernamePasswordAuthenticationToken) {
            model.addAttribute("localAuthentication", ((UsernamePasswordAuthenticationToken) principal).getPrincipal());
        } else if (principal instanceof Saml2Authentication) {
            final CustomSamlPrincipal samlPrincipal = (CustomSamlPrincipal) ((Saml2Authentication) principal).getPrincipal();
            final CustomUserDetails customUserDetails = (CustomUserDetails) samlPrincipal.getPrincipal();
            model.addAttribute("samlPrincipal", samlPrincipal);
            model.addAttribute("samlUserDetails", customUserDetails);
        } else if (principal instanceof OAuth2AuthenticationToken) {
            final CustomOidcPrincipal oidcPrincipal = (CustomOidcPrincipal) ((OAuth2AuthenticationToken) principal).getPrincipal();
            final CustomUserDetails customUserDetails = (CustomUserDetails) oidcPrincipal.getPrincipal();
            model.addAttribute("oidcPrincipal", oidcPrincipal);
            model.addAttribute("oidcUserDetails", customUserDetails);
        }
        return "index";
    }

    @GetMapping("${companyx.auth.endpoint.local.login-endpoint:" + LOGIN_ENDPOINT + "}")
    public String loginPage(@RequestParam(required = false) final String error,
                            @NonNull final Model model) {
        model.addAttribute("identityProviders", identityProviderService.getIdentityProviderForLoginPageOverview());
        model.addAttribute("loginEndpoint", LOGIN_ENDPOINT);
        model.addAttribute("maxLoginsPerMinute", loginAttemptService.getMaxFailedAttemptsPerUsernameAndIpInOneMinute());
        model.addAttribute("error", error);
        return "login";
    }

    @GetMapping("${cc.auth.endpoint.security.login-result-endpoint:" + LOGIN_RESULT_ENDPOINT + "}")
    public String result(@NonNull final Authentication authentication) {
        final CustomPrincipal principal = (CustomPrincipal) authentication.getPrincipal();
        // As we currently only serve one client, which is in our control, and that client manages
        // recurring users with profiles, it is necessary that the user has a profile.
        // But because the resource server currently does not provide the necessary means to create user profiles
        // and only allows to map the IDP authentication information to an already existing local account,
        // we have to make sure that the user has mapped the IDP information to an existing account.
        // This means, before issuing the authorization code, we have to check if a personId has been
        // mapped for the authentication. If not, require the user to map it first.
        if (principal.getPersonId() == null) {
            return "idp-mapping";
        }
        return "result";
    }

    @PostMapping(path = "${cc.auth.endpoint.security.login-result-endpoint:" + LOGIN_RESULT_ENDPOINT + "}",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public void result(@NonNull @RequestParam final Map<String, String> urlParameter,
                       @NonNull final HttpServletRequest request,
                       @NonNull final HttpServletResponse response) {

        final String authorizationCode = urlParameter.get("code");
        final String state = urlParameter.get("state");
        final OAuth2Authorization authorization = oAuth2AuthorizationService.findByToken(authorizationCode, new OAuth2TokenType(OAuth2ParameterNames.CODE));
        if (authorization == null) {
            throw new UnsupportedOperationException("No corresponding authorization found for the given authorization code.");
        }

        final UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString("http://127.0.0.1:8090/login/oauth2/code/" + authorization.getRegisteredClientId())
                .queryParam(OAuth2ParameterNames.CODE, authorizationCode)
                .queryParam(OAuth2ParameterNames.STATE, state);

        try {
            this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }

    }

    @PostMapping(path = "${companyx.auth.endpoint.security.idp-mapper-endpoint:" + IDP_MAPPING_ENDPOINT + "}",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public void idpMapper(@NonNull final Authentication authenticationAtProvider,
                          @NonNull @RequestParam final Map<String, String> urlParameter,
                          @NonNull final HttpServletRequest request,
                          @NonNull final HttpServletResponse response) {

        final String authorizationCode = urlParameter.get("code");
        final String state = urlParameter.get("state");
        String error = null;

        try {
            correlationService.createCorrelationBetweenLocalCredentialsAndProvider(
                    urlParameter.get(FORM_USERNAME), urlParameter.get(FORM_PASSWORD), authorizationCode, authenticationAtProvider, request);
        } catch (final AuthenticationException authenticationException) {
            if (authenticationException instanceof BannedIpAuthenticationException) {
                error = FederatedIdentityConfigurer.AuthFailureHandler.BANNED_ERROR;
            } else {
                error = FederatedIdentityConfigurer.AuthFailureHandler.BAD_CREDENTIALS_ERROR;
            }
        } catch (final IllegalArgumentException e) {
            throw new RuntimeException(e);
        }

        final UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString(LOGIN_RESULT_ENDPOINT)
                .queryParam(OAuth2ParameterNames.CODE, authorizationCode);

        if (StringUtils.hasText(state)) {
            uriBuilder.queryParam(OAuth2ParameterNames.STATE, state);
        }

        if (StringUtils.hasText(error)) {
            uriBuilder.queryParam("error", error);
        }

        try {
            this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }
}
