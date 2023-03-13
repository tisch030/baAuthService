package eu.firmax.cms.auth.client;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

/**
 * Configures the properties for clients that are allowed to use this authorization server.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyx.auth.client")
public class RegisteredClientProperties {

    /**
     * The interval in which the information about the registered clients to this authorization server should be refreshed.
     * Since the information about the registered clients currently are provided by properties and loaded
     * at server start, the concrete refresh interval doesn't matter.
     * But will matter in a future update, where the registered clients are also configured dynamically while the server runs.
     */
    private Duration refreshClientsInterval = Duration.ofDays(7);

    /**
     * List of all clients with their registration information that are allowed to access this
     * authorization server.
     */
    private List<RegisteredClientInformation> registeredClientInformationList;

    public record RegisteredClientInformation(@NonNull String clientId,
                                              @NonNull Duration accessTokenTimeToLive) {

    }
}
