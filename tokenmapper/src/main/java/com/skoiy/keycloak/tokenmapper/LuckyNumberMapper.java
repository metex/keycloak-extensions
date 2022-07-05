package com.skoiy.keycloak.tokenmapper;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.AccessToken;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
@Slf4j
public class LuckyNumberMapper extends AbstractOIDCProtocolMapper
	implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

	public static final String PROVIDER_ID = "oidc-lucky-number-mapper";

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

	static final String LOWER_BOUND = "lowerBound";
	static final String UPPER_BOUND = "upperBound";

	static {
		configProperties.add(new ProviderConfigProperty(LOWER_BOUND, "Lower Bound", "Lower bound of lucky number.", ProviderConfigProperty.STRING_TYPE, 1));
		configProperties.add(new ProviderConfigProperty(UPPER_BOUND, "Upper Bound", "Upper bound of lucky number.", ProviderConfigProperty.STRING_TYPE, 100));

		OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
		OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, LuckyNumberMapper.class);
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
		return "Lucky Number";
	}

	@Override
	public String getHelpText() {
		return "Map a random lucky number between bounds to a token claim.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
		int lower = Integer.parseInt(mappingModel.getConfig().get(LOWER_BOUND));
		int upper = Integer.parseInt(mappingModel.getConfig().get(UPPER_BOUND));

		int luckyNumber = (int) (Math.random() * (upper - lower)) + lower;

		OIDCAttributeMapperHelper.mapClaim(token, mappingModel, luckyNumber);
	}

	@Override
	public IDToken transformIDToken(IDToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
																	UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

		// This method is executed on login
		log.info("IDToken {} ", token.toString());
		if (!OIDCAttributeMapperHelper.includeInIDToken(mappingModel)) {
			return token;
		}

		token.getOtherClaims().put("custom_claim_name", "custom_claim_value");
		setClaim(token, mappingModel, userSession, session, clientSessionCtx);
		return token;
	}

	public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession keycloakSession,
																					UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
		token.getOtherClaims().put("custom_claim_name", "custom_claim_value");
		setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);
		return token;
	}
}
