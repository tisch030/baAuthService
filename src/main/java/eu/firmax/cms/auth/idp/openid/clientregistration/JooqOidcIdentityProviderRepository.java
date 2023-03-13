package eu.firmax.cms.auth.idp.openid.clientregistration;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import static eu.companyx.cms.auth.dto.companyx_backend.tables.OpenIdConnectSettings.OPEN_ID_CONNECT_SETTINGS;

/**
 * {@link OidcIdentityProviderRepository} implementation which uses JOOQ to access the OIDC settings in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqOidcIdentityProviderRepository implements OidcIdentityProviderRepository {

    @NonNull
    private final DSLContext dsl;

    @Override
    @NonNull
    public Map<String, OidcProviderSettings> loadOidcSettings(@NonNull final Set<String> identityProviderIds) {
        return dsl.select(
                        OPEN_ID_CONNECT_SETTINGS.IDENTITY_PROVIDER_ID,
                        OPEN_ID_CONNECT_SETTINGS.USE_DISCOVERY,
                        OPEN_ID_CONNECT_SETTINGS.ISSUER_URL,
                        OPEN_ID_CONNECT_SETTINGS.AUTHORIZATION_URL,
                        OPEN_ID_CONNECT_SETTINGS.JWKS_URL,
                        OPEN_ID_CONNECT_SETTINGS.USER_INFO_URL,
                        OPEN_ID_CONNECT_SETTINGS.TOKEN_URL,
                        OPEN_ID_CONNECT_SETTINGS.CLIENT_ID,
                        OPEN_ID_CONNECT_SETTINGS.CLIENT_SECRET,
                        OPEN_ID_CONNECT_SETTINGS.SCOPES)
                .from(OPEN_ID_CONNECT_SETTINGS)
                .where(OPEN_ID_CONNECT_SETTINGS.IDENTITY_PROVIDER_ID.in(identityProviderIds))
                .fetchMap(
                        row -> row.get(OPEN_ID_CONNECT_SETTINGS.IDENTITY_PROVIDER_ID),
                        row -> new OidcProviderSettings(
                                row.get(OPEN_ID_CONNECT_SETTINGS.USE_DISCOVERY),
                                row.get(OPEN_ID_CONNECT_SETTINGS.ISSUER_URL),
                                row.get(OPEN_ID_CONNECT_SETTINGS.AUTHORIZATION_URL),
                                row.get(OPEN_ID_CONNECT_SETTINGS.JWKS_URL),
                                row.get(OPEN_ID_CONNECT_SETTINGS.USER_INFO_URL),
                                row.get(OPEN_ID_CONNECT_SETTINGS.TOKEN_URL),
                                row.get(OPEN_ID_CONNECT_SETTINGS.CLIENT_ID),
                                row.get(OPEN_ID_CONNECT_SETTINGS.CLIENT_SECRET),
                                Arrays.stream(row.get(OPEN_ID_CONNECT_SETTINGS.SCOPES).split(","))
                                        .map(String::trim)
                                        .toList()));
    }
}
