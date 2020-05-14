package org.sral.mappers.keycloak;

import com.fasterxml.jackson.core.type.TypeReference;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static java.util.Arrays.asList;

/**
 *  @author <a href="mailto:lars@nospam.sral.org">Lars Wilhelmsen</a>
 */
public class RegexReplaceMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String PROVIDER_ID = "oidc-regex-replace-mapper";
    public static final String TARGET_CLAIMS_PROPERTY = "target.claims";
    public static final String REPLACEMENT_MAP_PROPERTY = "replacement.map";

    static {
        configProperties.addAll(
                ProviderConfigurationBuilder.create()
                .property()
                .name(TARGET_CLAIMS_PROPERTY)
                .label("Target claim(s)")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("Comma-separated list of claims to do search/replace on.")
                .add()

                .property()
                .name(REPLACEMENT_MAP_PROPERTY)
                .label("Replacements")
                .type(ProviderConfigProperty.MAP_TYPE)
                .helpText("Replacements á la Java's String.replaceAll()")
                .add()

                .build());

        // Add toggles for include in (ID Token, access token and User Info endpoint
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, RegexReplaceMapper.class);
    }

    @Override
    public int getPriority() {
        return 10000;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Regular Expression Replace Mapper";
    }

    @Override
    public String getHelpText() {
        return "Regex search/replace on existing claim values";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {

        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mapperModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        var transformedToken = super.transformAccessToken(token, mapperModel, session, userSession, clientSessionCtx);

        // Split on comma and trim -> list of target claims
        var targetClaims = getTargetClaims(mapperModel);

        var replacementMap = getConfigMap(mapperModel.getConfig(), REPLACEMENT_MAP_PROPERTY);

        for (var kv : transformedToken.getOtherClaims().entrySet()) {
            for (var replacement : replacementMap.entrySet()) {

                if (targetClaims.contains(kv.getKey())) {
                    final var claim = kv.getValue();
                    if (claim instanceof String) {
                        var stringClaim = (String)claim;
                        var mutatedStringClaim = stringClaim.replaceAll(replacement.getKey(), replacement.getValue());
                        token.setOtherClaims(kv.getKey(), mutatedStringClaim);
                    } else if (claim instanceof List<?>) {
                        var listOfStrings = (List<String>) claim;
                        var mutatedStrings = listOfStrings
                                                .stream()
                                                .map(x -> x.replaceAll(replacement.getKey(),
                                                                       replacement.getValue()))
                                                .collect(Collectors.toList());
                        token.setOtherClaims(kv.getKey(), mutatedStrings);
                    } else if (claim instanceof Map<?, ?>) {
                        // moar claims in sub property.
                        // TODO Implement later (allow dotted props in targetClaims)

                    } else {
                        // ignore for now.
                    }
                }
            }
        }
        return token;
    }

    private static List<String> getTargetClaims(ProtocolMapperModel mapperModel) {
        return Arrays.asList(mapperModel.getConfig().get(TARGET_CLAIMS_PROPERTY).split(",[ ]*"));
    }

    @Override
    public void validateConfig(KeycloakSession session, RealmModel realm, ProtocolMapperContainerModel client, ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
        try {
            var map = getConfigMap(mapperModel.getConfig(), REPLACEMENT_MAP_PROPERTY);
        } catch (RuntimeException rex)
        {
            throw new ProtocolMapperConfigException("Internal error relating to replacement handling. Please report this bug.", "{0}", rex);
        }

        if (mapperModel.getConfig().get(TARGET_CLAIMS_PROPERTY).isEmpty() || getTargetClaims(mapperModel).isEmpty()) {
            throw new ProtocolMapperConfigException("No target claims specified.", "{0}");
        }
    }

    @Override
    public AccessToken transformUserInfoToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        return transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);
    }

    @Override
    public IDToken transformIDToken(IDToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        return super.transformIDToken(token, mappingModel, session, userSession, clientSessionCtx);
    }

//    protected void setClaim(final IDToken token,
//                            final ProtocolMapperModel mappingModel,
//                            final UserSessionModel userSession,
//                            final KeycloakSession keycloakSession,
//                            final ClientSessionContext clientSessionContext) {
//
//    }

    private Map<String, String> getConfigMap(final Map<String, String> config, final String configKey) {

        String configMap = config.get(configKey);

        try {
            List<StringPair> map = JsonSerialization.readValue(configMap, MAP_TYPE_REPRESENTATION);
            return map.stream().collect(Collectors.toMap(StringPair::getKey, StringPair::getValue));
        } catch (IOException e) {
            throw new RuntimeException("Could not deserialize json: " + configMap, e);
        }
    }

    private static final TypeReference<List<StringPair>> MAP_TYPE_REPRESENTATION = new TypeReference<List<StringPair>>() {
    };

    static class StringPair {
        private String key;
        private String value;

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
