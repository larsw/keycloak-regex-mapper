package org.sral.keycloak.mappers;

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
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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
    public static final String MULTI_VALUE_PROPERTY = "multi.value";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        configProperties.addAll(
                ProviderConfigurationBuilder.create()
                .property()
                .name(TARGET_PROPERTY)
                .label("Match Target")
                .type(ProviderConfigProperty.LIST_TYPE)
                .helpText("Only Groups supported at the moment.")
                .defaultValue("Groups")
                .add()

                .property()
                .name(FULL_PATH_PROPERTY)
                .label("Match against full group path or not")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .helpText("Include full path to group i.e. /top/level1/level2, false will just specify the group name")
                .defaultValue("true")
                .add()

                .property()
                .name(REGEX_PATTERN_PROPERTY)
                .label("Match pattern")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("Regular expression with one or more groups")
                .defaultValue("(.*)")
                .add()

                .property()
                .name(MATCH_GROUP_NUMBER_OR_NAME_PROPERTY)
                .label("Match group number/name")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("The match group index or name to use as the claim value")
                .defaultValue("1")
                .add()

                .property()
                .name(MULTI_VALUE_PROPERTY)
                .label("Multi-valued")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .helpText("If set, all matching groups > 0 will be inserted as the claim value (list)")
                .defaultValue("false")
                .add()

                .property()
                .name(MERGE_CLAIMS_PROPERTY)
                .label("Merge claims")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .helpText("If the claim already exists, merge the new values into it")
                .defaultValue("false")
                .add()

                .build());

        // Add toggles for include in (ID Token, access token and User Info endpoint
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, RegexMapper.class);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
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

    public static boolean useFullPath(ProtocolMapperModel mapperModel) {
        return "true".equals(mapperModel.getConfig().get(FULL_PATH_PROPERTY));
    }

    public static boolean mergeClaimValues(ProtocolMapperModel mapperModel) {
        return "true".equals(mapperModel.getConfig().get(MERGE_CLAIMS_PROPERTY));
    }

    public static boolean multiValued(ProtocolMapperModel mapperModel) {
        return "true".equals(mapperModel.getConfig().get(MULTI_VALUE_PROPERTY));
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

        if (multiValued(mapperModel) == false) {
            var matchGroupNumberOrName = mapperModel.getConfig().get(MATCH_GROUP_NUMBER_OR_NAME_PROPERTY);
            if (matchGroupNumberOrName == null || matchGroupNumberOrName.isEmpty())
                throw new ProtocolMapperConfigException("Match group number or name is not defined", "{0}");
        }
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

        List<String> values;

//        if (multiValued(mapperModel)) {
//            values = getFilteredGroupMembershipsAsValues(mapperModel, userSession, pattern);
//        } else {
            var matchGroupNumberOrName = mapperModel.getConfig().get(MATCH_GROUP_NUMBER_OR_NAME_PROPERTY);
            var matchGroupNumber = -1;
            var matchGroupName = "";
            try {
                matchGroupNumber = Integer.parseInt(matchGroupNumberOrName);
            } catch (NumberFormatException ignored) {
                matchGroupName = matchGroupNumberOrName;
            }        
            values = getFilteredGroupMembershipsAsValues(mapperModel, userSession, matchGroupNumber, matchGroupName, pattern);
//        }

        if (mergeClaimValues(mapperModel)) {
            var existingClaim = token.getOtherClaims().get(targetClaimName);
            if (existingClaim != null) {
                if (existingClaim instanceof String) {
                    values.add((String)existingClaim);
                } else if (existingClaim instanceof List<?>) {
                    values.addAll((List<String>)existingClaim);
                } else {
                    // wut - TODO
                }
            }
        }

        token.getOtherClaims().put(targetClaimName, values);
    }

    private List<String> getFilteredGroupMembershipsAsValues(ProtocolMapperModel mappingModel, UserSessionModel userSession, Pattern pattern) {
        var fullPath = useFullPath(mappingModel);
        var multiValued = multiValued(mappingModel);

        var stream = userSession.getUser()
                .getGroups()
                .stream()
                .map(x -> fullPath ? pattern.matcher(ModelToRepresentation.buildGroupPath(x)) : pattern.matcher(x.getName()));

        if (multiValued) {
            return new ArrayList<String>();                    
            // TODO
        } else {
            return stream.filter(Matcher::matches)
               .flatMap(matcher -> {
                List<String> values = new ArrayList<>();
                while (matcher.find()) {
                   for (var i = 1; i < matcher.groupCount(); i++) {
                       values.add(matcher.group(i));
                   }
                }
                return values.stream();
            })
           .distinct()
           .collect(Collectors.toList());
        }
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
