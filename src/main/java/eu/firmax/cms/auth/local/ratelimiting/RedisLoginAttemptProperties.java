package eu.firmax.cms.auth.local.ratelimiting;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configures the properties for the configuration of the login attempt service.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyx.auth.local.rate-limiting")
public class RedisLoginAttemptProperties {

    /**
     * Prefix used for all cache keys.
     * Must be unique for each cache.
     */
    private String cacheKeyPrefix = "companyx:auth:ratelimiting:";
}
