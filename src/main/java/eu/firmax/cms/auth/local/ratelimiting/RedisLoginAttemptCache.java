package eu.firmax.cms.auth.local.ratelimiting;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.List;

/**
 * {@link LoginAttemptCache} implementation which uses redis as the concrete cache.
 * Tracks an attempt only for a minute and automatically deletes the attempt afterwards.
 */
@Repository
@ConditionalOnClass(RedisConnectionFactory.class)
@Profile("default")
public class RedisLoginAttemptCache implements LoginAttemptCache {

    @NonNull
    private final RedisLoginAttemptProperties redisLoginAttemptProperties;

    @NonNull
    private final RedisTemplate<String, Integer> redisTemplate;

    public RedisLoginAttemptCache(@NonNull final RedisConnectionFactory redisConnectionFactory,
                                  @NonNull final RedisLoginAttemptProperties redisLoginAttemptProperties) {
        this.redisTemplate = new RedisTemplate<>();
        this.redisTemplate.setKeySerializer(new StringRedisSerializer());
        this.redisTemplate.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        this.redisTemplate.setConnectionFactory(redisConnectionFactory);
        this.redisTemplate.afterPropertiesSet();
        this.redisLoginAttemptProperties = redisLoginAttemptProperties;
    }

    @Override
    public int getNumberOfLoginAttempts(@NonNull final String username,
                                        @NonNull final String ip) {
        final Integer number = redisTemplate.opsForValue().get(getCacheKey(username, ip));
        return number == null ? 0 : number;
    }

    @Override
    public void increaseLoginAttemptsByOne(@NonNull final String username,
                                           @NonNull final String ip) {
        final String cacheKey = getCacheKey(username, ip);
        redisTemplate.execute(new SessionCallback<List<Object>>() {
            @Override
            public <K, V> List<Object> execute(@NonNull final RedisOperations<K, V> operations) throws DataAccessException {
                operations.multi();
                operations.opsForValue().increment((K) cacheKey);
                operations.expire((K) cacheKey, Duration.ofMinutes(1));
                return operations.exec();
            }
        });
    }

    @Override
    public void clearLoginAttempts(@NonNull final String username,
                                   @NonNull final String ip) {
        redisTemplate.delete(getCacheKey(username, ip));
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
