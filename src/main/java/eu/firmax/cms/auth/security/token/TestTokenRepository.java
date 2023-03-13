package eu.firmax.cms.auth.security.token;


import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * {@link TokenRepository} implementation which uses an in memory mechanism in order to manage access tokens.
 * Needed for tests to avoid a redis dependency.
 */
@Repository
@Primary
@Profile("test")
@RequiredArgsConstructor
public class TestTokenRepository implements TokenRepository {

    private static final String BLACKLIST_KEY_PREFIX = "cc_blacklist_";

    @NonNull
    private final Map<String, Set<AccessToken>> tokenCache = new ConcurrentHashMap<>();

    @NonNull
    private final Set<String> blackListedTokens = new HashSet<>();

    @Override
    @NonNull
    public List<AccessToken> getAccessTokens(@NonNull final String personId) {

        expireOldTokens(personId);

        return tokenCache.getOrDefault(personId, Collections.emptySet()).stream()
                .sorted(Comparator.comparing(AccessToken::expiresAt))
                .collect(Collectors.toList());
    }

    @Override
    public void addAccessToken(@NonNull final String personId,
                               @NonNull final AccessToken accessToken) {

        expireOldTokens(personId);

        tokenCache.computeIfAbsent(personId, key -> new HashSet<>())
                .add(accessToken);
    }

    @Override
    public void deleteAccessTokens(@NonNull final String personId,
                                   @NonNull final String sessionId) {

        expireOldTokens(personId);

        final AccessToken[] tokens = getAccessTokens(personId).stream()
                .filter(accessToken -> accessToken.sessionId().equals(sessionId))
                .toArray(AccessToken[]::new);

        for (final AccessToken accessToken : tokens) {
            blacklistToken(accessToken);
        }

        if (tokenCache.containsKey(personId)) {
            tokenCache.get(personId)
                    .removeIf(token -> sessionId.equals(token.sessionId()));
        }
    }

    @Override
    public void deleteAccessTokens(@NonNull final String personId) {
        expireOldTokens(personId);

        for (final AccessToken accessToken : getAccessTokens(personId)) {
            blacklistToken(accessToken);
        }
        tokenCache.remove(personId);
    }

    @Override
    public void deleteAccessToken(@NonNull final String personId,
                                  @NonNull final String tokenId) {

        expireOldTokens(personId);

        final AccessToken[] tokens = getAccessTokens(personId).stream()
                .filter(accessToken -> accessToken.id().equals(tokenId))
                .toArray(AccessToken[]::new);

        for (final AccessToken accessToken : tokens) {
            blacklistToken(accessToken);
        }

        if (tokenCache.containsKey(personId)) {
            tokenCache.get(personId).stream().filter(token -> tokenId.equals(token.token()))
                    .findFirst()
                    .ifPresent(accessToken -> tokenCache.get(personId).remove(accessToken));

        }

    }

    private void blacklistToken(@NonNull final AccessToken accessToken) {
        final Duration blacklistExpire = Duration.between(Instant.now(), accessToken.expiresAt());
        if (!blacklistExpire.isNegative()) {
            blackListedTokens.add(BLACKLIST_KEY_PREFIX + accessToken.token());
        }
    }

    private void expireOldTokens(@NonNull final String personId) {
        if (tokenCache.containsKey(personId)) {
            tokenCache.get(personId).clear();
        }
    }
}
