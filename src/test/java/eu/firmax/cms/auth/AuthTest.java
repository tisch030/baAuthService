package eu.firmax.cms.auth;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.controller.TestLoginController;
import eu.firmax.cms.auth.local.LocalAuthenticationEndpointProperties;
import eu.firmax.cms.auth.local.database.TestUserDetailsRepository;
import eu.firmax.cms.auth.local.settings.LocalAuthenticationSettingsRepository;
import eu.firmax.cms.auth.local.settings.TestLocalAuthenticationSettingsRepository;
import eu.firmax.cms.auth.security.FederatedIdentityConfigurer;
import eu.firmax.cms.auth.security.SecurityEndpointProperties;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.unbescape.html.HtmlEscape;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = {"server.port=46000", "server.ssl.enabled=false"},
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ContextConfiguration(classes = {
        AuthTest.Config.class,
        AuthTest.AuthTestController.class,
        OAuth2ResourceServerAutoConfiguration.class,
        ServletWebServerFactoryAutoConfiguration.class,
        DispatcherServletAutoConfiguration.class,
        WebMvcAutoConfiguration.class})
class AuthTest {

    @SpyBean
    private TestLocalAuthenticationSettingsRepository localAuthenticationSettingsRepository;

    @SpyBean
    private SecurityEndpointProperties securityEndpointProperties;

    @SpyBean
    private LocalAuthenticationEndpointProperties localAuthenticationEndpointProperties;

    private final String clientId = "ba-client";
    private final String redirectUrl = "http://127.0.0.1:9500/api/auth/result";
    // PKCE
    private final String authServer = "http://127.0.0.1:9500";
    private final String codeVerifier = "tu2SK3hoswqQ0Z1wLAGasAD0AuZem3eePgq9IRurd5U";
    private final String codeChallenge = createCodeChallenge(codeVerifier);


    private final String authorizeInitiateUrl = "?response_type=code&client_id=" + clientId + "&state=v8LmjPn5yaXnPaO77GsMCOoDekthGm5yhhH7LdPoyec=&redirect_uri=" + redirectUrl + "&code_challenge=" + codeChallenge + "&code_challenge_method=S256";
    private final String resourceUrl = "http://localhost:46000/test";
    private final String logoutResourceUrl = authServer + "/api/auth/test";
    private final String clearLoginAttemptsEndpoint = authServer + TestLoginController.CLEAR_ATTEMPTS_ENDPOINT;

    private final String AUTH_SESSION_COOKIE_NAME = "AUTHSESSIONID";
    private final String XSRF_COOKIE_NAME = "XSRF-TOKEN";
    private final String localLoginFormUsernameParam = "username";
    private final String localLoginFormPasswordParam = "password";
    private final String localLoginFormCsrfParam = "_csrf";
    private final String localLoginUsername = TestUserDetailsRepository.USERNAME;
    private final String localLoginPasswordCorrect = TestUserDetailsRepository.PASSWORD_RAW;
    private final String localLoginPasswordIncorrect = "wrongpassword";
    private final String keyCloakFormUsernameParam = "username";
    private final String keyCloakLoginFormPasswordParam = "password";
    private final String keyCloakUsername = "oidc.schulz";
    private final String keyCloakPassword = "test";


    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    static class Config {

        private final String jwtIssuer = "http://127.0.0.1:9500"; // Same as the authServer url from above.
        private final String jwkSetUrl = jwtIssuer + "/api/auth/jwks";

        @Bean
        public SecurityFilterChain securityFilterChain(@NonNull final HttpSecurity http) throws Exception {
            http
                    .securityMatcher("/test/**")
                    .authorizeHttpRequests().anyRequest().authenticated()
                    .and()
                    .oauth2ResourceServer()
                    .jwt();
            return http.build();
        }

        @Bean
        public JwtDecoder jwtDecoder() {
            final NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUrl).build();
            final OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(jwtIssuer);
            final OAuth2TokenValidator<Jwt> standardValidatorWithBlacklistValidation = new DelegatingOAuth2TokenValidator<>(withIssuer);
            jwtDecoder.setJwtValidator(standardValidatorWithBlacklistValidation);
            return jwtDecoder;
        }
    }

    @RestController
    static class AuthTestController {

        @GetMapping("/test")
        public Map<String, Object> getStuff(final Principal principal) {
            final JwtAuthenticationToken token = (JwtAuthenticationToken) principal;
            return token.getTokenAttributes();
        }
    }


    @Test
    void test_auth_usernamePassword_correctPassword() {
        usernamePasswordLogin();
    }

    @Test
    void test_auth_usernamePassword_wrongPassword_onceFailed() {
        final LoginPageInfo loginPageInfo = usernamePasswordLoginPrepare();

        final SessionIdAndRedirectUrl badLoginResult = performLogin(
                loginPageInfo.loginUrl(),
                localLoginUsername,
                localLoginPasswordIncorrect,
                loginPageInfo.authSessionId(),
                loginPageInfo.xsrfToken());

        assertBadCredentialsUrl(badLoginResult.url());

        final SessionIdAndRedirectUrl loginResult = performLogin(
                loginPageInfo.loginUrl(),
                localLoginUsername,
                localLoginPasswordCorrect,
                loginPageInfo.authSessionId(),
                loginPageInfo.xsrfToken());

        usernamePasswordLoginCheckSession(loginResult.sessionId());
    }

    @Test
    void test_auth_usernamePassword_wrongPassword_multipleFailed_maxTriesExceeded_overTimeLimit() {
        final LoginPageInfo loginPageInfo = usernamePasswordLoginPrepare();

        for (int loginTry = 0; loginTry < getMaxAllowedLoginAttempts(); loginTry++) {
            final SessionIdAndRedirectUrl badLoginResult = performLogin(
                    loginPageInfo.loginUrl(),
                    localLoginUsername,
                    localLoginPasswordIncorrect,
                    loginPageInfo.authSessionId(),
                    loginPageInfo.xsrfToken());

            assertBadCredentialsUrl(badLoginResult.url());
        }

        final SessionIdAndRedirectUrl loginResult = performLogin(
                loginPageInfo.loginUrl(),
                localLoginUsername,
                localLoginPasswordCorrect,
                loginPageInfo.authSessionId(),
                loginPageInfo.xsrfToken());

        assertBannedUrl(loginResult.url());
    }

    @Test
    void test_auth_usernamePassword_wrongPassword_multipleFailed_maxTriesExceeded_withinTimeLimit() {
        final LoginPageInfo loginPageInfo = usernamePasswordLoginPrepare();

        for (int loginTry = 0; loginTry < getMaxAllowedLoginAttempts(); loginTry++) {
            final SessionIdAndRedirectUrl badLoginResult = performLogin(
                    loginPageInfo.loginUrl(),
                    localLoginUsername,
                    localLoginPasswordIncorrect,
                    loginPageInfo.authSessionId(),
                    loginPageInfo.xsrfToken());

            assertBadCredentialsUrl(badLoginResult.url());
        }

        clearLoginAttempts();

        final SessionIdAndRedirectUrl loginResult = performLogin(
                loginPageInfo.loginUrl(),
                localLoginUsername,
                localLoginPasswordCorrect,
                loginPageInfo.authSessionId(),
                loginPageInfo.xsrfToken());

        usernamePasswordLoginCheckSession(loginResult.sessionId());
    }

    @Test
    void test_auth_openidConnect() {
        openidConnectLogin();
    }

    @Test
    void test_auth_saml_post() {
        samlLoginWithPostBinding();
    }


    @Test
    void test_logout_usernamePassword() {
        final String authSessionId = usernamePasswordLogin();
        usernamePasswordLogout(authSessionId);
    }

    @Test
    void test_logout_openidConnect() {
        final String authSessionId = openidConnectLogin();
        oidcLogout(authSessionId);
    }

    @Test
    void test_logout_saml() {
        final String authSessionId = samlLoginWithPostBinding();
        samlLogout(authSessionId);
    }


    private void fetchResource(final String accessToken) {
        // Access resources using access token
        final Response response = RestAssured.given()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .get(resourceUrl);
        assertThat(response.as(Map.class)).hasSizeGreaterThan(0);
    }

    @NonNull
    private String usernamePasswordLogin() {
        final LoginPageInfo loginPageInfo = usernamePasswordLoginPrepare();

        final SessionIdAndRedirectUrl loginResult = performLogin(
                loginPageInfo.loginUrl(),
                localLoginUsername,
                localLoginPasswordCorrect,
                loginPageInfo.authSessionId(),
                loginPageInfo.xsrfToken());

        return usernamePasswordLoginCheckSession(loginResult.sessionId());
    }

    @NonNull
    private LoginPageInfo usernamePasswordLoginPrepare() {
        // Make sure we are currently not banned from entering the credentials, because some other tests had to many tries or whatever.
        clearLoginAttempts();

        // Call authorization endpoint to get an authorization code, but without an authenticated session,
        // in order to trigger the redirect to the login form.
        final SessionIdAndRedirectUrl authorize = visitAuthorizeEndpoint(null);
        assertThat(authorize.sessionId()).isNotNull();
        final CsrfTokenAndBody loginPage = visitLoginPage(authorize.sessionId(), authorize.url());

        return new LoginPageInfo(authorize.url(), authorize.sessionId(), loginPage.xsrfToken());
    }

    @NonNull
    private String usernamePasswordLoginCheckSession(@Nullable final String authSessionId) {
        assertThat(authSessionId).isNotNull();

        // Call authorization endpoint to get an authorization code, but this time with an authenticated user session.
        final SessionIdAndRedirectUrl authorize2 = visitAuthorizeEndpoint(authSessionId);
        final String authorizationCode = extractAuthorizationCodeFromRedirectUrl(authorize2.url());

        // Exchange authorization code for access token and fetch resource.
        final String accessToken = exchangeAuthorizationCodeForAccessToken(authorizationCode, authSessionId);
        fetchResource(accessToken);

        return authSessionId;
    }

    @NonNull
    private String openidConnectLogin() {
        // Try to get authorization code from authorization server.
        // Will fail because we don't have an authenticated session.
        final SessionIdAndRedirectUrl authorize = visitAuthorizeEndpoint(null);
        final String authSessionId = authorize.sessionId();
        assertThat(authSessionId).isNotNull();

        // Auth-Server will redirect us to the login page, in order to authenticate the user.
        // Obtain login page and get openid connect provider url
        final CsrfTokenAndBody loginPage = visitLoginPage(authSessionId, authorize.url());
        final String identityProviderEndpoint = extractIdentityProviderUrlFromLoginPage(loginPage.body(), 3);

        // Redirect to openid connect provider. Will respond with a location where we can find the login page of the idp.
        final String identityProviderLoginPageUrl = visitIdentityProviderEndpoint(authSessionId, identityProviderEndpoint, HttpStatus.FOUND);

        final String idpLoginResult = performLoginAtIdp(identityProviderLoginPageUrl, HttpStatus.FOUND);

        // Redirect back to the application and obtain authenticated user session
        final String userSessionId = processOidcLoginResponse(authSessionId, idpLoginResult);

        // Now call authorization endpoint again to get an authorization code, but this time with an authenticated user session.
        final SessionIdAndRedirectUrl authorize2 = visitAuthorizeEndpoint(userSessionId);
        final String authorizationCode = extractAuthorizationCodeFromRedirectUrl(authorize2.url());

        // Exchange authorization code for access & refresh token.
        final String accessToken = exchangeAuthorizationCodeForAccessToken(authorizationCode, userSessionId);
        fetchResource(accessToken);

        return userSessionId;
    }

    @NonNull
    private String samlLoginWithPostBinding() {
        // Try to get authorization code from authorization server.
        // Will fail because we don't have an authenticated session.
        final SessionIdAndRedirectUrl authorize1 = visitAuthorizeEndpoint(null);
        final String authSessionId = authorize1.sessionId();
        assertThat(authSessionId).isNotNull();

        // Auth-Server will redirect us to the login page, in order to authenticate the user.
        // Obtain login page and get SAML provider url
        final CsrfTokenAndBody loginPage = visitLoginPage(authSessionId, authorize1.url());
        final String identityProviderEndpoint = extractIdentityProviderUrlFromLoginPage(loginPage.body(), 2);

        // Redirect to SAML provider.
        // Because we are testing the POST binding, no redirect location will be provided, instead a
        // formular that contains the saml request, relay state and the url where to post the information.
        // As we don't have javascript enabled in the test cases, we have to manually post the form.
        final String samlAuthnRequestPostForm = visitIdentityProviderEndpoint(authSessionId, identityProviderEndpoint, HttpStatus.OK);
        assertThat(samlAuthnRequestPostForm).isNotNull();

        // Extract all the information in order to post the saml request.
        final String samlLoginUrl = extractKeyCloakPostUrlFromForm(samlAuthnRequestPostForm);
        final String samlLoginRequest = extractFormParameters(samlAuthnRequestPostForm, "SAMLRequest");
        final String samlRelayState = extractFormParameters(samlAuthnRequestPostForm, "RelayState");

        // Post the saml request and extract the location, where we should get send after we posted the login request.
        final IdentityProviderLoginPageInfoAfterPost samlLoginWithPostResult = postSamlSSORequest(samlLoginUrl, samlLoginRequest, samlRelayState);

        final String idpLoginResult = performLoginAtSamlIDPWithPostBinding(samlLoginWithPostResult.identityProviderUrl(), samlLoginWithPostResult.providerAuthSessionId(), samlLoginWithPostResult.providerAuthSessionIdLegacy());

        // Obtain SAML response and response url for POSTing the response.
        // Is needed because we don't have JavaScript enabled in the test cases.
        final String samlLoginResponse = extractFormParameters(idpLoginResult, "SAMLResponse");
        final String samlLoginResponseUrl = extractKeyCloakPostUrlFromForm(idpLoginResult);

        // POST saml response to application, redirect back to application
        // and obtain authenticated user session
        final String userSessionId = processSamlLoginResponse(authSessionId, samlLoginResponseUrl, samlLoginResponse);

        // Now call authorization endpoint again to get an authorization code, but this time with an authenticated user session.
        final SessionIdAndRedirectUrl authorize2 = visitAuthorizeEndpoint(userSessionId);
        final String authorizationCode = extractAuthorizationCodeFromRedirectUrl(authorize2.url());

        // Exchange authorization code for access token and fetch resource.
        final String accessToken = exchangeAuthorizationCodeForAccessToken(authorizationCode, userSessionId);
        fetchResource(accessToken);

        return userSessionId;
    }

    private void usernamePasswordLogout(@NonNull final String authSessionId) {
        // Open logout page and obtain CSRF/XSRF Tokens
        final String logoutXsrfToken = visitLogoutPage(authSessionId, HttpStatus.OK);

        // Send logout
        final String logoutResultUrl = performLogout(authSessionId, logoutXsrfToken);
        assertThat(logoutResultUrl).isEqualTo(authServer + "/");

        // Try to open logout page again, this time we should be redirected instead of getting the form for the logout.
        final String redirectUrl = visitLogoutPage(authSessionId, HttpStatus.FOUND);
        assertThat(redirectUrl).isEqualTo(authServer + localAuthenticationEndpointProperties.getLoginEndpoint());
    }

    private void oidcLogout(@NonNull final String authSessionId) {
        // Open logout page and obtain CSRF/XSRF Tokens
        final String logoutXsrfToken = visitLogoutPage(authSessionId, HttpStatus.OK);

        // Send logout
        final String logoutResultUrl = performLogout(authSessionId, logoutXsrfToken);
        assertThat(logoutResultUrl).contains("post_logout_redirect_uri=" + authServer);

        // Try to open logout page again, this time we should be redirected instead of getting the form for the logout.
        final String redirectUrl = visitLogoutPage(authSessionId, HttpStatus.FOUND);
        assertThat(redirectUrl).isEqualTo(authServer + localAuthenticationEndpointProperties.getLoginEndpoint());
    }

    private void samlLogout(@NonNull final String authSessionId) {
        // Open logout page and obtain CSRF/XSRF Tokens
        final String logoutXsrfToken = visitLogoutPage(authSessionId, HttpStatus.OK);

        // Send logout
        final SessionIdAndBody logoutResult = performSamlLogout(authSessionId, logoutXsrfToken);
        assertThat(logoutResult.sessionId()).isNotNull();
        assertThat(logoutResult.body()).isNotNull();

        // Obtain keycloak logout url, saml logout request and RelayState
        // We also get a new session, which will be used by spring to determine the initial logout request
        // that will be mapped to the latter received logout response.
        final String samlLogoutUrl = extractKeyCloakPostUrlFromForm(logoutResult.body());
        final String samlLogoutRequest = extractFormParameters(logoutResult.body(), "SAMLRequest");
        final String samlRelayState = extractFormParameters(logoutResult.body(), "RelayState");

        // Send logout request and obtain response
        final String samlLogoutResult = performSamlLogoutAtIdp(samlLogoutUrl, samlLogoutRequest, samlRelayState);
        final String keycloakLogoutResponseUrl = extractKeyCloakPostUrlFromForm(samlLogoutResult);
        final String samlLogoutResponse = extractFormParameters(samlLogoutResult, "SAMLResponse");

        // Send saml logout response
        processSamlLogoutResponse(logoutResult.sessionId(), keycloakLogoutResponseUrl, samlLogoutResponse, samlRelayState);

        // Try to open logout page again, this time we should be redirected instead of getting the form for the logout.
        final String redirectUrl = visitLogoutPage(logoutResult.sessionId(), HttpStatus.FOUND);
        assertThat(redirectUrl).isEqualTo(authServer + localAuthenticationEndpointProperties.getLoginEndpoint());
    }

    @NonNull
    private SessionIdAndRedirectUrl visitAuthorizeEndpoint(@Nullable final String authSessionId) {
        // By trying to get an authorization code without a provided session with an authenticated user,
        // it will redirect us to the login page. Otherwise, it will give as a redirect url which contains the authorization code.
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, authSessionId)
                .get(authServer + securityEndpointProperties.getAuthorizeEndpoint() + authorizeInitiateUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value());
        final String newAuthSessionId = response.getCookie(AUTH_SESSION_COOKIE_NAME);
        final String redirectUrl = URLDecoder.decode(response.getHeader(HttpHeaders.LOCATION), StandardCharsets.UTF_8);
        return new SessionIdAndRedirectUrl(newAuthSessionId, redirectUrl);
    }

    @NonNull
    private CsrfTokenAndBody visitLoginPage(@NonNull final String authSessionId,
                                            @NonNull final String loginPageUrl) {
        // Obtain login page and corresponding csrf tokens.
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, authSessionId)
                .get(loginPageUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
        final String xsrfToken = response.getCookie(XSRF_COOKIE_NAME);
        final String body = response.getBody().asString();
        return new CsrfTokenAndBody(xsrfToken, body);
    }

    @NonNull
    private SessionIdAndRedirectUrl performLogin(@NonNull final String loginPageUrl,
                                                 @NonNull final String username,
                                                 @NonNull final String password,
                                                 @NonNull final String authSessionId,
                                                 @NonNull final String xsrfToken) {

        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, authSessionId)
                .cookie(XSRF_COOKIE_NAME, xsrfToken)
                .formParams(localLoginFormUsernameParam, username, localLoginFormPasswordParam, password, localLoginFormCsrfParam, xsrfToken)
                .post(loginPageUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value());
        final String newAuthSessionId = response.getCookie(AUTH_SESSION_COOKIE_NAME);
        final String redirectUrl = URLDecoder.decode(response.getHeader(HttpHeaders.LOCATION), StandardCharsets.UTF_8);
        return new SessionIdAndRedirectUrl(newAuthSessionId, redirectUrl);
    }

    @NonNull
    private String visitLogoutPage(@NonNull final String authSessionId,
                                   @NonNull final HttpStatus expectedStatus) {
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, authSessionId)
                .get(logoutResourceUrl);
        assertThat(response.getStatusCode()).isEqualTo(expectedStatus.value());
        return expectedStatus == HttpStatus.OK ?
                response.getCookie(XSRF_COOKIE_NAME) :
                URLDecoder.decode(response.getHeader(HttpHeaders.LOCATION), StandardCharsets.UTF_8);
    }

    @NonNull
    private String performLogout(@NonNull final String authSessionId,
                                 @NonNull final String logoutXsrfToken) {
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, authSessionId)
                .cookie(XSRF_COOKIE_NAME, logoutXsrfToken)
                .formParam(localLoginFormCsrfParam, logoutXsrfToken)
                .post(authServer + securityEndpointProperties.getLogoutInitiateEndpoint());
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value());
        return URLDecoder.decode(response.getHeader(HttpHeaders.LOCATION), StandardCharsets.UTF_8);
    }

    @NonNull
    private SessionIdAndBody performSamlLogout(@NonNull final String authSessionId,
                                               @NonNull final String logoutXsrfToken) {
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, authSessionId)
                .cookie(XSRF_COOKIE_NAME, logoutXsrfToken)
                .formParam(localLoginFormCsrfParam, logoutXsrfToken)
                .post(authServer + securityEndpointProperties.getLogoutInitiateEndpoint());
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
        final String newAuthSessionId = response.getCookie(AUTH_SESSION_COOKIE_NAME);
        final String body = response.getBody().asString();
        return new SessionIdAndBody(newAuthSessionId, body);
    }

    @NonNull
    private String performSamlLogoutAtIdp(@NonNull final String samlLogoutUrl,
                                          @NonNull final String samlLogoutRequest,
                                          @NonNull final String samlRelayState) {
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .formParam("SAMLRequest", samlLogoutRequest, "RelayState", samlRelayState)
                .post(samlLogoutUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
        return response.getBody().asString();
    }

    private void processSamlLogoutResponse(@NonNull final String authSessionId,
                                           @NonNull final String samlLogoutResponseUrl,
                                           @NonNull final String samlLogoutResponse,
                                           @NonNull final String samlRelayState) {
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, authSessionId)
                .formParam("SAMLResponse", samlLogoutResponse)
                .param("RelayState", samlRelayState)
                .post(samlLogoutResponseUrl);
        final String redirectUrl = URLDecoder.decode(response.getHeader(HttpHeaders.LOCATION), StandardCharsets.UTF_8);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value());
        assertThat(redirectUrl).isEqualTo(authServer + "/");
    }

    @NonNull
    private String visitIdentityProviderEndpoint(@NonNull final String authSessionId,
                                                 @NonNull final String identityProviderEndpointUrl,
                                                 @NonNull final HttpStatus expectedStatus) {
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, authSessionId)
                .get(identityProviderEndpointUrl);
        assertThat(response.getStatusCode()).isEqualTo(expectedStatus.value());
        return expectedStatus == HttpStatus.OK ?
                response.getBody().asString() :
                URLDecoder.decode(response.getHeader(HttpHeaders.LOCATION), StandardCharsets.UTF_8);
    }

    @NonNull
    private String performLoginAtIdp(@NonNull final String identityProviderUrl,
                                     @NonNull final HttpStatus expectedStatus) {
        // Fetch provider login form for login endpoint
        Response response = RestAssured.given()
                .get(identityProviderUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
        final String keyCloakLoginUrl = extractKeyCloakPostUrlFromForm(response.getBody().asString());
        final String providerAuthSessionId = response.getCookie("AUTH_SESSION_ID");
        final String providerAuthSessionIdLegacy = response.getCookie("AUTH_SESSION_ID_LEGACY");

        // Authenticate at provider
        response = RestAssured.given()
                .urlEncodingEnabled(false)
                .redirects()
                .follow(false)
                .cookie("AUTH_SESSION_ID", providerAuthSessionId)
                .cookie("AUTH_SESSION_ID_LEGACY", providerAuthSessionIdLegacy)
                .formParams(keyCloakFormUsernameParam, keyCloakUsername, keyCloakLoginFormPasswordParam, keyCloakPassword, "credentialId", "")
                .post(keyCloakLoginUrl);
        assertThat(response.getStatusCode()).isEqualTo(expectedStatus.value());
        return expectedStatus == HttpStatus.OK ?
                response.getBody().asString() :
                URLDecoder.decode(response.getHeader(HttpHeaders.LOCATION), StandardCharsets.UTF_8);
    }

    @NonNull
    private IdentityProviderLoginPageInfoAfterPost postSamlSSORequest(@NonNull final String samlLoginRequestUrl,
                                                                      @NonNull final String samlLoginRequest,
                                                                      @NonNull final String samlRelayState) {
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .formParam("SAMLRequest", samlLoginRequest, "RelayState", samlRelayState)
                .post(samlLoginRequestUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value());
        final String providerAuthSessionId = response.getCookie("AUTH_SESSION_ID");
        final String providerAuthSessionIdLegacy = response.getCookie("AUTH_SESSION_ID_LEGACY");
        final String postLocation = URLDecoder.decode(response.getHeader(HttpHeaders.LOCATION), StandardCharsets.UTF_8);
        return new IdentityProviderLoginPageInfoAfterPost(postLocation, providerAuthSessionId, providerAuthSessionIdLegacy);

    }

    @NonNull
    private String performLoginAtSamlIDPWithPostBinding(@NonNull final String identityProviderUrl,
                                                        @NonNull final String providerAuthSessionId,
                                                        @NonNull final String providerAuthSessionIdLegacy) {
        // Fetch provider login form for login endpoint
        Response response = RestAssured.given()
                .cookie("AUTH_SESSION_ID", providerAuthSessionId)
                .cookie("AUTH_SESSION_ID_LEGACY", providerAuthSessionIdLegacy)
                .get(identityProviderUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
        final String keyCloakLoginUrl = extractKeyCloakPostUrlFromForm(response.getBody().asString());

        // Authenticate at provider
        response = RestAssured.given()
                .urlEncodingEnabled(false)
                .redirects()
                .follow(false)
                .cookie("AUTH_SESSION_ID", providerAuthSessionId)
                .cookie("AUTH_SESSION_ID_LEGACY", providerAuthSessionIdLegacy)
                .formParams(keyCloakFormUsernameParam, keyCloakUsername, keyCloakLoginFormPasswordParam, keyCloakPassword, "credentialId", "")
                .post(keyCloakLoginUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
        return response.getBody().asString();
    }

    @NonNull
    private String processOidcLoginResponse(@NonNull final String authSessionId,
                                            @NonNull final String oidcLoginResponseUrl) {
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, authSessionId)
                .get(oidcLoginResponseUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value());
        return response.getCookie(AUTH_SESSION_COOKIE_NAME);
    }

    @NonNull
    private String processSamlLoginResponse(@NonNull final String authSessionId,
                                            @NonNull final String samlLoginResponseUrl,
                                            @NonNull final String samlLoginResponse) {
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, authSessionId)
                .formParam("SAMLResponse", samlLoginResponse)
                .post(samlLoginResponseUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value());
        return response.getCookie(AUTH_SESSION_COOKIE_NAME);
    }

    private void clearLoginAttempts() {
        final Response response = RestAssured.given()
                .post(clearLoginAttemptsEndpoint);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
    }

    @NonNull
    private String exchangeAuthorizationCodeForAccessToken(@NonNull final String authorizationCode,
                                                           @NonNull final String userSessionId) {
        final Map<String, String> params = new HashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("code", authorizationCode);
        params.put("client_id", clientId);
        params.put("redirect_uri", redirectUrl);
        params.put("code_verifier", codeVerifier);
        final Response response = RestAssured.given()
                .redirects()
                .follow(false)
                .cookie(AUTH_SESSION_COOKIE_NAME, userSessionId)
                .formParams(params)
                .post(authServer + securityEndpointProperties.getTokenEndpoint());
        return response.jsonPath()
                .getString("access_token");
    }

    @NonNull
    private String extractAuthorizationCodeFromRedirectUrl(@NonNull final String authorizationCodeUrl) {
        final String codeUrl = URLDecoder.decode(authorizationCodeUrl, StandardCharsets.UTF_8);
        final Pattern codePattern = Pattern.compile("code=([^&]+)(&.*)?");
        final Matcher codeMatcher = codePattern.matcher(codeUrl);
        assertThat(codeMatcher.find()).isTrue();
        return codeMatcher.group(1);
    }

    @NonNull
    private String extractIdentityProviderUrlFromLoginPage(@NonNull final String htmlDocument,
                                                           final int providerNumber) {
        final Pattern providerPattern = Pattern.compile("action=\"([^\"]+)\"");
        final Matcher providerMatcher = providerPattern.matcher(htmlDocument);
        for (int i = 0; i < providerNumber; i++) {
            assertThat(providerMatcher.find()).isTrue();
        }
        return authServer + providerMatcher.group(1);
    }

    @NonNull
    private String extractKeyCloakPostUrlFromForm(@NonNull final String htmlDocument) {
        final Pattern loginPattern = Pattern.compile("<form.*action=\"([^\"]+)\"");
        final Matcher loginMatcher = loginPattern.matcher(htmlDocument);
        assertThat(loginMatcher.find()).isTrue();
        return HtmlEscape.unescapeHtml(loginMatcher.group(1));
    }

    @NonNull
    private String extractFormParameters(@NonNull final String htmlDocument,
                                         @NonNull final String formParameterName) {
        final Pattern regexPattern = Pattern.compile("name=\"" + formParameterName + "\" value=\"([^\"]+)\"");
        final Matcher regexMatcher = regexPattern.matcher(htmlDocument);
        assertThat(regexMatcher.find()).isTrue();
        return HtmlEscape.unescapeHtml(regexMatcher.group(1));
    }

    private int getMaxAllowedLoginAttempts() {
        final LocalAuthenticationSettingsRepository.LocalAuthenticationBaseSettings localAuthenticationBaseSettings = localAuthenticationSettingsRepository.loadSettings();
        assertThat(localAuthenticationBaseSettings).isNotNull();
        return localAuthenticationBaseSettings.maxFailedAttemptsPerUsernameAndIpInOneMinute();
    }

    private void assertBadCredentialsUrl(@NonNull final String url) {
        assertThat(url).contains(FederatedIdentityConfigurer.AuthFailureHandler.BASE_ERROR_ENDPOINT +
                FederatedIdentityConfigurer.AuthFailureHandler.BAD_CREDENTIALS_ERROR);
    }

    private void assertBannedUrl(@NonNull final String url) {
        assertThat(url).contains(FederatedIdentityConfigurer.AuthFailureHandler.BASE_ERROR_ENDPOINT +
                FederatedIdentityConfigurer.AuthFailureHandler.BANNED_ERROR);
    }

    @NonNull
    private static String createCodeChallenge(@NonNull final String codeVerifier) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        final byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private record LoginPageInfo(@NonNull String loginUrl,
                                 @NonNull String authSessionId,
                                 @NonNull String xsrfToken) {
    }

    private record SessionIdAndRedirectUrl(@Nullable String sessionId,
                                           @NonNull String url) {
    }

    private record SessionIdAndBody(@Nullable String sessionId,
                                    @Nullable String body) {
    }

    private record CsrfTokenAndBody(@NonNull String xsrfToken,
                                    @NonNull String body) {
    }

    private record IdentityProviderLoginPageInfoAfterPost(@NonNull String identityProviderUrl,
                                                          @NonNull String providerAuthSessionId,
                                                          @NonNull String providerAuthSessionIdLegacy) {

    }
}
