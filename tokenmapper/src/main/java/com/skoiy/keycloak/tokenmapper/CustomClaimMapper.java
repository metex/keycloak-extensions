package com.skoiy.keycloak.tokenmapper;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
@Slf4j
public class CustomClaimMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper {
	private static final String PROVIDER_ID = "custom-claim-mapper";
	private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

	static {
		configProperties.add(new ProviderConfigProperty("lower", "Lower Bound", "Lower bound of lucky number.", ProviderConfigProperty.STRING_TYPE, 1));
		configProperties.add(new ProviderConfigProperty("upper", "Upper Bound", "Upper bound of lucky number.", ProviderConfigProperty.STRING_TYPE, 100));

		OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
		OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomClaimMapper.class);
	}

	// TODO this information should be defined as a configuration of the provider
	private static final String CLAIM_NAME = "secretClaim";

	@Override
	public String getDisplayCategory() {
		return TOKEN_MAPPER_CATEGORY;
	}

	@Override
	public String getDisplayType() {
		return "Custom Claim";
	}

	@Override
	public String getHelpText() {
		return "Map user secrets to token.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession keycloakSession,
																					UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

		log.info("USER_SECRET {} ", token.toString());
		// Put the note into the access token
		// Hint: it might have been interesting to distinguish between the different type of notes
		// that can be returned by a user storage provider like:
		// We will have to find a way to specify which note are to be included to the access token
		String note = userSession.getNote("USER_SECRET");
		if (note != null) {
			token.getOtherClaims().put(CLAIM_NAME, note);
		}

		return token;
	}
}
