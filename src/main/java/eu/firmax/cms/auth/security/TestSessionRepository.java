package eu.firmax.cms.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

import java.util.concurrent.ConcurrentHashMap;

/**
 * We don't want to use redis as the session manager while doing the integration test, that's why we use springs in memory
 * manager.
 */
@EnableSpringHttpSession
@Profile("test")
@Configuration
public class TestSessionRepository {

    @Bean
    public MapSessionRepository sessionRepository() {
        return new MapSessionRepository(new ConcurrentHashMap<>());
    }
}
