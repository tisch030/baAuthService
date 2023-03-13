package eu.firmax.cms.auth.security.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * {@link TokenRepository} implementation which uses redis in order to manage access tokens.
 */
@Repository
@ConditionalOnClass(RedisConnectionFactory.class)
@Profile("default")
public class RedisTokenRepository implements TokenRepository {

    private static final String TOKEN_KEY_PREFIX = "cc:auth:token:";
    private static final String BLOCKLIST_KEY_PREFIX = "cc:auth:blocklist:";
    private static final String BLOCKLIST_CHANNEL = "cc:auth:blocklist";

    @NonNull
    private final RedisTemplate<String, AccessToken> tokenRedisTemplate;

    @NonNull
    private final RedisTemplate<String, String> blocklistRedisTemplate;

    public RedisTokenRepository(@NonNull final RedisConnectionFactory redisConnectionFactory) {
        this.tokenRedisTemplate = new RedisTemplate<>();
        this.tokenRedisTemplate.setKeySerializer(new StringRedisSerializer());
        this.tokenRedisTemplate.setValueSerializer(new AccessTokenSerializer());
        this.tokenRedisTemplate.setConnectionFactory(redisConnectionFactory);
        this.tokenRedisTemplate.afterPropertiesSet();

        this.blocklistRedisTemplate = new RedisTemplate<>();
        this.blocklistRedisTemplate.setKeySerializer(new StringRedisSerializer());
        this.blocklistRedisTemplate.setValueSerializer(new StringRedisSerializer());
        this.blocklistRedisTemplate.setConnectionFactory(redisConnectionFactory);
        this.blocklistRedisTemplate.afterPropertiesSet();
    }

    @Override
    @NonNull
    public List<AccessToken> getAccessTokens(@NonNull final String personId) {

        expireOldTokens(personId);

        final Set<AccessToken> tokens = tokenRedisTemplate.opsForZSet().range(TOKEN_KEY_PREFIX + personId, 0, Long.MAX_VALUE);
        if (tokens == null) {
            // Can't be null under normal circumstances, but we don't want to have nasty warning.
            return List.of();
        }

        return tokens.stream()
                .sorted(Comparator.comparing(AccessToken::expiresAt))
                .collect(Collectors.toList());
    }

    @Override
    public void addAccessToken(@NonNull final String personId,
                               @NonNull final AccessToken accessToken) {

        expireOldTokens(personId);

        tokenRedisTemplate.opsForZSet().add(TOKEN_KEY_PREFIX + personId, accessToken, accessToken.expiresAt().getEpochSecond());
    }

    @Override
    public void deleteAccessTokens(@NonNull final String personId,
                                   @NonNull final String sessionId) {
        expireOldTokens(personId);

        final AccessToken[] tokens = getAccessTokens(personId).stream()
                .filter(accessToken -> accessToken.sessionId().equals(sessionId))
                .toArray(AccessToken[]::new);

        for (final AccessToken accessToken : tokens) {
            addTokenToBlocklist(accessToken);
        }

        if (tokens.length == 0) {
            // No issued tokens found. Indicates that the user just signed out of the AS, without providing any
            // access to the Client.
            return;
        }

        tokenRedisTemplate.opsForZSet().remove(TOKEN_KEY_PREFIX + personId, (Object[]) tokens);
    }

    @Override
    public void deleteAccessTokens(@NonNull final String personId) {

        expireOldTokens(personId);

        for (final AccessToken accessToken : getAccessTokens(personId)) {
            addTokenToBlocklist(accessToken);
        }
        tokenRedisTemplate.delete(TOKEN_KEY_PREFIX + personId);
    }

    @Override
    public void deleteAccessToken(@NonNull final String personId,
                                  @NonNull final String tokenId) {

        expireOldTokens(personId);

        final AccessToken[] tokens = getAccessTokens(personId).stream()
                .filter(accessToken -> accessToken.id().equals(tokenId))
                .toArray(AccessToken[]::new);

        for (final AccessToken accessToken : tokens) {
            addTokenToBlocklist(accessToken);
        }

        tokenRedisTemplate.opsForZSet().remove(TOKEN_KEY_PREFIX + personId, (Object[]) tokens);
    }

    private void addTokenToBlocklist(@NonNull final AccessToken accessToken) {
        final Duration blacklistExpire = Duration.between(Instant.now(), accessToken.expiresAt());
        if (!blacklistExpire.isNegative()) {
            // Null is fine as value, the serializer can handle it.
            blocklistRedisTemplate.opsForValue().set(BLOCKLIST_KEY_PREFIX + accessToken.token(), accessToken.expiresAt().toString(), blacklistExpire);
            blocklistRedisTemplate.convertAndSend(BLOCKLIST_CHANNEL, accessToken.token() + " " + accessToken.expiresAt());
        }
    }

    /**
     * Removes all tokens which expired and should not be tracked any further.
     * <p>
     * Since the tokens are added by score, where the score is composed of the expiration date of the token (see addAccessToken),
     * the redis function removeRangeByScore will be called, where the score is composed of the absolute minimum
     * till the score equivalent of the current time.
     *
     * @param personId the id of the person from which all expired tokens should be removed.
     */
    private void expireOldTokens(@NonNull final String personId) {
        tokenRedisTemplate.opsForZSet().removeRangeByScore(TOKEN_KEY_PREFIX + personId, 0, Instant.now().getEpochSecond());
    }

    private static class AccessTokenSerializer implements RedisSerializer<AccessToken> {

        private final ObjectMapper objectMapper = Jackson2ObjectMapperBuilder.json()
                .modules(new JavaTimeModule())
                .build();

        @NonNull
        @Override
        public byte[] serialize(final AccessToken accessToken) throws SerializationException {
            try {
                return objectMapper.writeValueAsBytes(accessToken);
            } catch (@NonNull final JsonProcessingException e) {
                throw new SerializationException(e.getMessage(), e);
            }
        }

        @NonNull
        @Override
        public AccessToken deserialize(final byte[] bytes) throws SerializationException {
            try {
                return objectMapper.readValue(bytes, AccessToken.class);
            } catch (@NonNull final IOException e) {
                throw new SerializationException(e.getMessage(), e);
            }
        }

    }
}
