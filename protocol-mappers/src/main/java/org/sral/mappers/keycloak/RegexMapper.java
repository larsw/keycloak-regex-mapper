package org.sral.mappers.keycloak;

import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperConfigException;
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
public class RegexMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String PROVIDER_ID = "oidc-regex-mapper";

    public static final String MERGE_CLAIMS_PROPERTY = "merge.claims";
    public static final String TARGET_PROPERTY = "target";
    public static final String FULL_PATH_PROPERTY = "full.path";
    public static final String REGEX_PATTERN_PROPERTY = "regex.pattern";
    public static final String MATCH_GROUP_NUMBER_OR_NAME_PROPERTY = "match.group.number.or.name";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        var targetProperty = new ProviderConfigProperty();
        targetProperty.setName(TARGET_PROPERTY);
        targetProperty.setLabel("Match target");
        targetProperty.setHelpText("Only Groups supported at the moment.");
        targetProperty.setType(ProviderConfigProperty.LIST_TYPE);
        targetProperty.setOptions(asList("Groups")); // TODO , "Roles", "User attributes"));
        targetProperty.setDefaultValue("Groups");
        configProperties.add(targetProperty);

        var fullGroupNameProperty = new ProviderConfigProperty();
        fullGroupNameProperty.setName(FULL_PATH_PROPERTY);
        fullGroupNameProperty.setLabel("Match against full group path or not");
        fullGroupNameProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        fullGroupNameProperty.setDefaultValue("true");
        fullGroupNameProperty.setHelpText("Include full path to group i.e. /top/level1/level2, false will just specify the group name");
        configProperties.add(fullGroupNameProperty);

        var patternProperty = new ProviderConfigProperty();
        patternProperty.setName(REGEX_PATTERN_PROPERTY);
        patternProperty.setLabel("Regex pattern");
        patternProperty.setType(ProviderConfigProperty.STRING_TYPE);
        patternProperty.setDefaultValue("(.*)");
        patternProperty.setHelpText("Regular expression with one or more groups");
        configProperties.add(patternProperty);

        var matchGroupNumberOrNameProperty = new ProviderConfigProperty();
        matchGroupNumberOrNameProperty.setName(MATCH_GROUP_NUMBER_OR_NAME_PROPERTY);
        matchGroupNumberOrNameProperty.setLabel("Match group number/name");
        matchGroupNumberOrNameProperty.setType(ProviderConfigProperty.STRING_TYPE);
        matchGroupNumberOrNameProperty.setDefaultValue("1");
        configProperties.add(matchGroupNumberOrNameProperty);

        var mergeClaimsProperty = new ProviderConfigProperty();
        mergeClaimsProperty.setName(MERGE_CLAIMS_PROPERTY);
        mergeClaimsProperty.setLabel("Merge claims");
        mergeClaimsProperty.setHelpText("If the claim already exists, merge the new values into it");
        mergeClaimsProperty.setDefaultValue("false");
        mergeClaimsProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(mergeClaimsProperty);

        // Add toggles for include in (ID Token, access token and User Info endpoint
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, RegexMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Regular Expression Mapper";
    }

    @Override
    public String getHelpText() {
        return "Add claim based on a regular expression over model properties";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {

        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    public static boolean useFullPath(ProtocolMapperModel mapperModel) {
        return "true".equals(mapperModel.getConfig().get(FULL_PATH_PROPERTY));
    }

    public static boolean mergeClaimValues(ProtocolMapperModel mapperModel) {
        return "true".equals(mapperModel.getConfig().get(MERGE_CLAIMS_PROPERTY));
    }

    @Override
    public void validateConfig(final KeycloakSession session,
                               final RealmModel realm,
                               final ProtocolMapperContainerModel client,
                               final ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
        try {
            // Ensure that it is possible to construct the regex pattern without exception.
            var pattern = constructPattern(mapperModel);

        } catch (Exception ex) {
            throw new ProtocolMapperConfigException("Invalid regular expression pattern", "{0}", ex);
        }

        var matchGroupNumberOrName = mapperModel.getConfig().get(MATCH_GROUP_NUMBER_OR_NAME_PROPERTY);
        if (matchGroupNumberOrName == null || matchGroupNumberOrName.isEmpty())
            throw new ProtocolMapperConfigException("Match group number or name is not defined", "{0}");
    }

    private Pattern constructPattern(ProtocolMapperModel mappingModel) {
        var regexPattern = mappingModel.getConfig().get(REGEX_PATTERN_PROPERTY);
        return Pattern.compile(regexPattern);
    }

    protected void setClaim(final IDToken token,
                            final ProtocolMapperModel mapperModel,
                            final UserSessionModel userSession,
                            final KeycloakSession keycloakSession,
                            final ClientSessionContext clientSessionContext) {

        var targetClaimName = mapperModel.getConfig().get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);

        var pattern = constructPattern(mapperModel);

        var matchGroupNumberOrName = mapperModel.getConfig().get(MATCH_GROUP_NUMBER_OR_NAME_PROPERTY);
        var matchGroupNumber = -1;
        var matchGroupName = "";
        try {
            matchGroupNumber = Integer.parseInt(matchGroupNumberOrName);
        } catch (NumberFormatException ignored) {
            matchGroupName = matchGroupNumberOrName;
        }

        var values = getFilteredGroupMembershipsAsValues(mapperModel, userSession, matchGroupNumber, matchGroupName, pattern);

        if (mergeClaimValues(mapperModel)) {
            var existingClaim = token.getOtherClaims().get(targetClaimName);
            if (existingClaim != null) {
                if (existingClaim instanceof String) {
                    values.add((String)existingClaim);
                } else if (existingClaim instanceof List<?>) {
                    values.addAll((List<String>)existingClaim);
                } else {
                    // wut
                }
            }
        }

        token.getOtherClaims().put(targetClaimName, values);
    }

    private List<String> getFilteredGroupMembershipsAsValues(ProtocolMapperModel mappingModel, UserSessionModel userSession, int matchGroupNumber, String matchGroupName, Pattern pattern) {
        boolean fullPath = useFullPath(mappingModel);

        return userSession.getUser()
                .getGroups()
                .stream()
                .map(x -> fullPath ? pattern.matcher(ModelToRepresentation.buildGroupPath(x)) : pattern.matcher(x.getName()))
                .filter(Matcher::matches)
                .map(x -> {
                    String value;
                    if (matchGroupNumber == -1) {
                        value = x.group(matchGroupName);
                    } else {
                        value = x.group(matchGroupNumber);
                    }
                    return value;
                })
                .distinct()
                .collect(Collectors.toList());
    }
}