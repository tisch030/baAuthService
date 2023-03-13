package eu.firmax.cms.auth.idp.saml.logout;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

/**
 * {@link Saml2LogoutRequestRepository} implementation that saves the saml logout request in redis instead
 * of inside the session.
 * This is needed because the {@link HttpSessionLogoutRequestRepository} tries to serialize the logout request
 * before saving it inside the session by using the {@link JdkSerializationRedisSerializer}, but the
 * serialization fails because the {@link Saml2LogoutRequest} contains a lambda attribute, which the serializer cannot serialize.
 * Configuring and using the {@link Jackson2JsonRedisSerializer} does not work, because the {@link Saml2LogoutRequest} does not have
 * a public constructor and can only be created by a builder.
 * That's why we also create our custom {@link Saml2LogoutRequestSerializer}.
 */
@Service
@ConditionalOnClass(RedisConnectionFactory.class)
@Profile("default")
public class RedisSamlLogoutRequestRepository implements Saml2LogoutRequestRepository {

    private static final String AUTHORIZATION_PREFIX = "cc:saml:logout-request:";

    @NonNull
    private final RedisTemplate<String, Saml2LogoutRequest> saml2LogoutRequestRedisTemplate;


    public RedisSamlLogoutRequestRepository(@NonNull final RedisConnectionFactory redisConnectionFactory,
                                            @NonNull final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.saml2LogoutRequestRedisTemplate = new RedisTemplate<>();
        this.saml2LogoutRequestRedisTemplate.setKeySerializer(new StringRedisSerializer());
        this.saml2LogoutRequestRedisTemplate.setValueSerializer(new Saml2LogoutRequestSerializer(relyingPartyRegistrationRepository));
        this.saml2LogoutRequestRedisTemplate.setConnectionFactory(redisConnectionFactory);
        this.saml2LogoutRequestRedisTemplate.afterPropertiesSet();
    }

    @Override
    public Saml2LogoutRequest loadLogoutRequest(@NonNull final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        final Saml2LogoutRequest saml2LogoutRequest = saml2LogoutRequestRedisTemplate.opsForValue().get(getLogoutRequestKey(session));
        if (stateParameterEquals(request, saml2LogoutRequest)) {
            return saml2LogoutRequest;
        }
        return null;
    }

    @Override
    public void saveLogoutRequest(@Nullable final Saml2LogoutRequest logoutRequest,
                                  @NonNull final HttpServletRequest request,
                                  @NonNull final HttpServletResponse response) {
        final String logoutRequestRedisKey = getLogoutRequestKey(request.getSession());
        if (logoutRequest == null) {
            saml2LogoutRequestRedisTemplate.delete(logoutRequestRedisKey);
            return;
        }
        final String state = logoutRequest.getRelayState();
        Assert.hasText(state, "logoutRequest.state cannot be empty");
        saml2LogoutRequestRedisTemplate.opsForValue().set(logoutRequestRedisKey, logoutRequest);
    }


    @Override
    public Saml2LogoutRequest removeLogoutRequest(@NonNull final HttpServletRequest request,
                                                  @NonNull final HttpServletResponse response) {
        final Saml2LogoutRequest logoutRequest = loadLogoutRequest(request);
        if (logoutRequest == null) {
            return null;
        }
        saml2LogoutRequestRedisTemplate.delete(getLogoutRequestKey(request.getSession()));
        return logoutRequest;
    }

    private boolean stateParameterEquals(@NonNull final HttpServletRequest request,
                                         @Nullable final Saml2LogoutRequest logoutRequest) {
        final String stateParameter = getStateParameter(request);
        if (stateParameter == null || logoutRequest == null) {
            return false;
        }
        final String relayState = logoutRequest.getRelayState();
        return MessageDigest.isEqual(Utf8.encode(stateParameter), Utf8.encode(relayState));
    }

    private String getStateParameter(@NonNull final HttpServletRequest request) {
        return request.getParameter(Saml2ParameterNames.RELAY_STATE);
    }

    private String getLogoutRequestKey(@NonNull final HttpSession session) {
        return AUTHORIZATION_PREFIX + session.getId();
    }

    /**
     * Custom {@link RedisSerializer} which is used to serialize and deserialize {@link Saml2LogoutRequest} by
     * first converting them into json objects, writing out the important attribute and while deserializing
     * read the attributes and constructs a {@link Saml2LogoutRequest} using the builder.
     */
    private static class Saml2LogoutRequestSerializer implements RedisSerializer<Saml2LogoutRequest> {

        @NonNull
        private final GenericJackson2JsonRedisSerializer redisSerializer;

        public Saml2LogoutRequestSerializer(@NonNull final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
            final ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.registerModule(createCustomSaml2LogoutRequestObjectMapperModule(relyingPartyRegistrationRepository));
            this.redisSerializer = new GenericJackson2JsonRedisSerializer(objectMapper);
        }

        @NonNull
        @Override
        public byte[] serialize(final Saml2LogoutRequest saml2LogoutRequest) throws SerializationException {

            if (saml2LogoutRequest == null) {
                return new byte[0];
            }

            final byte[] serialize = redisSerializer.serialize(saml2LogoutRequest);
            return Objects.requireNonNullElseGet(serialize, () -> new byte[0]);
        }

        @Nullable
        @Override
        public Saml2LogoutRequest deserialize(final byte[] bytes) throws SerializationException {
            if (bytes == null || bytes.length == 0) {
                return null;
            }
            return (Saml2LogoutRequest) redisSerializer.deserialize(bytes);
        }

        /**
         * The custom JsonDeserializer uses the object type because it will convert the JSON element first
         * into a java object while deserializing it.
         * At the point of converting the json element into a java object the deserializer does not know that it is
         * a Saml2LogoutRequest instance.
         * Therefore, the custom JsonDeserializer must use the Object type to convert the JSON element into a Java Object,
         * and then it must be converted from an Object into a Saml2LogoutRequest.
         * <p>
         * The custom JsonSerializer, on the other hand, already works with the Saml2LogoutRequest type because
         * it serialises a Saml2LogoutRequest instance.
         * Therefore, it is not necessary to use the object type, as the JsonSerializer already works with the correct type.
         *
         * @param relyingPartyRegistrationRepository the repository to retrieve the relying party registration
         *                                           based on the deserialized relyingPartyRegistrationId which will
         *                                           be used to build the Saml2LogoutRequest.
         * @return
         */
        private SimpleModule createCustomSaml2LogoutRequestObjectMapperModule(@NonNull final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {

            return new SimpleModule()
                    .addSerializer(Saml2LogoutRequest.class, new JsonSerializer<>() {
                        @Override
                        public void serialize(@NonNull final Saml2LogoutRequest saml2LogoutRequest,
                                              @NonNull final JsonGenerator gen,
                                              @NonNull final SerializerProvider serializers) throws IOException {
                            gen.writeStartObject();
                            gen.writeObjectField("location", saml2LogoutRequest.getLocation());
                            gen.writeObjectField("binding", saml2LogoutRequest.getBinding());
                            gen.writeObjectField("parameters", saml2LogoutRequest.getParameters());
                            gen.writeObjectField("id", saml2LogoutRequest.getId());
                            gen.writeObjectField("relyingPartyRegistrationId", saml2LogoutRequest.getRelyingPartyRegistrationId());
                            gen.writeObjectField("samlRequest", saml2LogoutRequest.getSamlRequest());
                            gen.writeObjectField("relayState", saml2LogoutRequest.getRelayState());
                            gen.writeEndObject();
                        }
                    })
                    .addDeserializer(Object.class, new JsonDeserializer<>() {

                        @Override
                        public Object deserialize(@NonNull final JsonParser p,
                                                  @NonNull final DeserializationContext ctxt) throws IOException, JsonProcessingException {
                            final JsonNode node = p.getCodec().readTree(p);
                            final String location = node.get("location").asText();
                            final JsonNode binding = node.get("binding");
                            final JsonNode parameters = node.get("parameters");
                            final String id = node.get("id").asText();
                            final String relyingPartyRegistrationId = node.get("relyingPartyRegistrationId").asText();
                            final String samlRequest = node.get("samlRequest").asText();
                            final String relayState = node.get("relayState").asText();

                            final RelyingPartyRegistration registration = relyingPartyRegistrationRepository.findByRegistrationId(relyingPartyRegistrationId);

                            final Saml2LogoutRequest.Builder samlLogoutRequestBuilder = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
                                    .id(id)
                                    .location(location)
                                    .binding(Saml2MessageBinding.valueOf(binding.asText()))
                                    .samlRequest(samlRequest)
                                    .relayState(relayState)
                                    .parameters((params) -> {
                                        for (final Iterator<Map.Entry<String, JsonNode>> it = parameters.fields(); it.hasNext(); ) {
                                            final Map.Entry<String, JsonNode> entry = it.next();
                                            final String key = entry.getKey();
                                            final String value = entry.getValue().asText();
                                            params.put(key, value);
                                        }
                                    });

                            return samlLogoutRequestBuilder.build();
                        }
                    });
        }

    }
}
