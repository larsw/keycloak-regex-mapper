package org.sral.mappers.keycloak;

import com.fasterxml.jackson.core.type.TypeReference;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
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

import static java.util.Arrays.asList;

/*
 *  @author <a href="mailto:lars@nospam.sral.org">Lars Wilhelmsen</a>
 */
public class RegexReplaceMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String PROVIDER_ID = "oidc-regex-replace-mapper";

    public static final String TARGET_CLAIMS_PROPERTY = "target.claims";
    public static final String REPLACEMENT_MAP_PROPERTY = "replacement.map";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        var targetClaimsProperty = new ProviderConfigProperty();
        targetClaimsProperty.setName(TARGET_CLAIMS_PROPERTY);
        targetClaimsProperty.setLabel("Target claim(s)");
        targetClaimsProperty.setType(ProviderConfigProperty.STRING_TYPE);
        targetClaimsProperty.setHelpText("Comma-separated list of claims to do search/replace on.");
        configProperties.add(targetClaimsProperty);

        var replacementMapProperty = new ProviderConfigProperty();
        replacementMapProperty.setName(REPLACEMENT_MAP_PROPERTY);
        replacementMapProperty.setLabel("Replacements");
        replacementMapProperty.setType(ProviderConfigProperty.STRING_TYPE);
        replacementMapProperty.setHelpText("Replacements á la Java's String.replaceAll()");
        configProperties.add(replacementMapProperty);

        // Add toggles for include in (ID Token, access token and User Info endpoint
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, RegexReplaceMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Regex Replace Mapper";
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
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        // Split on comma and trim -> list of target claims
        var targetClaims = mappingModel.getConfig().get(TARGET_CLAIMS_PROPERTY).split(",[ ]*");

        var replacementMap = getConfigMap(mappingModel.getConfig(), REPLACEMENT_MAP_PROPERTY);

        Map.of token.getOtherClaims()

        for (var target : targetClaims) {

            // TODO get claim value


            // TODO if claim type is not string - ignore (for now)

            String claimValue = null;

            if (claim instanceof string) {
                claimValue = (String)claim;
            }

            // TODO if claim is collection, iterate over it ...
            // if (claim instanceof List) {}

            for (var replacement : replacementMap.entrySet()) {
                claimValue = claimValue.replaceAll(replacement.getKey(), replacement.getValue());
            }

            // TODO set claim value
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

    protected void setClaim(final IDToken token,
                            final ProtocolMapperModel mappingModel,
                            final UserSessionModel userSession,
                            final KeycloakSession keycloakSession,
                            final ClientSessionContext clientSessionContext) {

    }

    private Map<String, String> getConfigMap(final Map<String, String> config, String configKey) {
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
