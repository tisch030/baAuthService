package eu.firmax.cms.auth.local.ratelimiting;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@link LoginAttemptCache} implementation which uses an in memory implementation as the concrete cache.
 * Used to abstract away the redis dependency for the integration/unit tests.
 */
@Repository
@Profile("test")
@RequiredArgsConstructor
public class TestLoginAttemptCache implements LoginAttemptCache {

    @NonNull
    private final RedisLoginAttemptProperties redisLoginAttemptProperties;

    @NonNull
    private final Map<String, Integer> loginAttemptCache = new ConcurrentHashMap<>();

    @Override
    public int getNumberOfLoginAttempts(@NonNull final String username,
                                        @NonNull final String ip) {
        final Integer number = loginAttemptCache.get(getCacheKey(username, ip));
        return number == null ? 0 : number;
    }

    @Override
    public void increaseLoginAttemptsByOne(@NonNull final String username,
                                           @NonNull final String ip) {
        final String cacheKey = getCacheKey(username, ip);
        Integer number = loginAttemptCache.get(getCacheKey(username, ip));
        number = number == null ? 0 : number;
        number++;
        loginAttemptCache.put(cacheKey, number);
    }

    @Override
    public void clearLoginAttempts(@NonNull final String username,
                                   @NonNull final String ip) {
        loginAttemptCache.clear();
    }

    /**
     * Returns the cache key for the given username and the requesters IP.
     *
     * @param username username for which the cache key is returned.
     * @return the cache key for the given username and the requesters IP.
     */
    @NonNull
    private String getCacheKey(@NonNull final String username,
                               @NonNull final String ip) {
        return redisLoginAttemptProperties.getCacheKeyPrefix() + username + "_" + ip;
    }
}
