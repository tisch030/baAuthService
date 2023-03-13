package eu.firmax.cms.auth.controller;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.local.ratelimiting.LoginAttemptCache;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Used by the tests to control some behaviour of this service.
 */
@Controller
@RequiredArgsConstructor
@Profile("test")
public class TestLoginController {

    public static final String CLEAR_ATTEMPTS_ENDPOINT = "/api/auth/loginattempt/clear";
    private static final String TEST_LOGOUT_ENDPOINT = "/api/auth/test";

    @NonNull
    private final LoginAttemptCache loginAttemptCache;

    @GetMapping(TEST_LOGOUT_ENDPOINT)
    public String test() {
        return "index";
    }

    @PostMapping(CLEAR_ATTEMPTS_ENDPOINT)
    @ResponseBody
    public ResponseEntity<Void> clearAttempts() {
        // Endpoint is only used to clear all login attempts that occurred during integration tests,
        // where only one set of credentials is used to test the logins.
        // That's why the concrete username/ip combination doesn't matter.
        loginAttemptCache.clearLoginAttempts("testCase", "testCase");
        return ResponseEntity.ok(null);
    }
}
