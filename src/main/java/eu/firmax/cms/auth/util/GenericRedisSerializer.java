package eu.firmax.cms.auth.util;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.security.token.IssuedTokenCustomizer;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Based upon the {@link JdkSerializationRedisSerializer}.
 * <p>
 * The usage of {@link JdkSerializationRedisSerializer} has led to {@link ClassCastException}s in
 * {@link IssuedTokenCustomizer}, because different classloaders were used.
 */
public class GenericRedisSerializer<T extends Serializable> implements RedisSerializer<T> {

    @Override
    @NonNull
    public byte[] serialize(@Nullable final T object) throws SerializationException {
        if (object == null) {
            return new byte[0];
        }

        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream();
             final ObjectOutput out = new ObjectOutputStream(bos)) {

            out.writeObject(object);
            return bos.toByteArray();

        } catch (final IOException e) {
            throw new SerializationException(e.getMessage(), e);
        }
    }

    @Nullable
    @Override
    public T deserialize(@Nullable final byte[] bytes) throws SerializationException {

        if (bytes == null || bytes.length == 0) {
            return null;
        }

        try (final ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             final ObjectInput in = new ObjectInputStream(bis)) {

            @SuppressWarnings("unchecked") final T result = (T) in.readObject();
            return result;

        } catch (IOException | ClassNotFoundException e) {
            throw new SerializationException(e.getMessage(), e);
        }
    }
}
