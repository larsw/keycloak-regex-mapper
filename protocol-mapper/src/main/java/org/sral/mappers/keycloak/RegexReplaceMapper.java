package org.sral.mappers.keycloak;

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
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;
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

    protected void setClaim(final IDToken token,
                            final ProtocolMapperModel mappingModel,
                            final UserSessionModel userSession,
                            final KeycloakSession keycloakSession,
                            final ClientSessionContext clientSessionContext) {

        // Split on comma and trim -> list of target claims
        var targetClaims = Arrays.asList(mapperModel.getConfig().get(TARGET_CLAIMS_PROPERTY).split(",[ ]*"));
        var replacementMap = mapperModel.getConfigMap(REPLACEMENT_MAP_PROPERTY);
        
        for (var target : targetClaims) {

            // TODO get claim value


            // TODO if claim type is not string - ignore (for now)

            string claimValue = null;

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
}
