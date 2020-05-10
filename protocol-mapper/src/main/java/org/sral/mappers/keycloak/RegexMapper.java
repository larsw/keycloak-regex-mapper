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

/*
 * Our own example protocol mapper.
 */
public class RegexMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    /*
     * A config which keycloak uses to display a generic dialog to configure the token.
     */
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    /*
     * The ID of the token mapper. Is public, because we need this id in our data-setup project to
     * configure the protocol mapper in keycloak.
     */
    public static final String PROVIDER_ID = "oidc-regex-mapper";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty fullGroupNameProperty = new ProviderConfigProperty();
        fullGroupNameProperty.setName("full.path");
        fullGroupNameProperty.setLabel("Full group path");
        fullGroupNameProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        fullGroupNameProperty.setDefaultValue("true");
        fullGroupNameProperty.setHelpText("Include full path to group i.e. /top/level1/level2, false will just specify the group name");
        configProperties.add(fullGroupNameProperty);

        ProviderConfigProperty patternProperty = new ProviderConfigProperty();
        patternProperty.setName("regex.pattern");
        patternProperty.setLabel("Regex pattern");
        patternProperty.setType(ProviderConfigProperty.STRING_TYPE);
        patternProperty.setDefaultValue("(.*)");
        patternProperty.setHelpText("Regular expression with one or more groups");
        configProperties.add(patternProperty);

        ProviderConfigProperty matchGroupNumberOrNameProperty = new ProviderConfigProperty();
        matchGroupNumberOrNameProperty.setName("match.group.number.or.name");
        matchGroupNumberOrNameProperty.setLabel("Match group number/name");
        matchGroupNumberOrNameProperty.setType(ProviderConfigProperty.STRING_TYPE);
        matchGroupNumberOrNameProperty.setDefaultValue("1");
        configProperties.add(matchGroupNumberOrNameProperty);


        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, RegexMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return "Token mapper";
    }

    @Override
    public String getDisplayType() {
        return "Regex Mapper";
    }

    @Override
    public String getHelpText() {
        return "Add claim based on a regular expression over a model property";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    public static boolean useFullPath(ProtocolMapperModel mappingModel) {
        return "true".equals(mappingModel.getConfig().get("full.path"));
    }

    protected void setClaim(final IDToken token,
                            final ProtocolMapperModel mappingModel,
                            final UserSessionModel userSession,
                            final KeycloakSession keycloakSession,
                            ClientSessionContext clientSessionContext) {
        var regexPattern = mappingModel.getConfig().get("regex.pattern");

        var groupNumberOrName = mappingModel.getConfig().get("match.group.number.or.name");
        var groupNumber = -1;
        var groupName = "";
        try {
            groupNumber = Integer.parseInt(groupNumberOrName);
        } catch (NumberFormatException ignored) {
            groupName = groupNumberOrName;
        }

        var pattern = Pattern.compile(regexPattern);

        boolean fullPath = useFullPath(mappingModel);

        int finalGroupNumber = groupNumber;
        String finalGroupName = groupName;
        var memberships = userSession.getUser()
                .getGroups()
                .stream()
                .map(x -> fullPath ? pattern.matcher(ModelToRepresentation.buildGroupPath(x)) : pattern.matcher(x.getName()))
                .filter(Matcher::matches)
                .map(x -> {
                    String value;
                    if (finalGroupNumber == -1) {
                        value = x.group(finalGroupName);
                    } else {
                        value = x.group(finalGroupNumber);
                    }
                    return value;
                })
                .distinct()
                .collect(Collectors.toList());

        String protocolClaim = mappingModel.getConfig().get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);
        token.getOtherClaims().put(protocolClaim, memberships);
    }
}
