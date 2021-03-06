package com.skoiy.keycloak;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;

import java.util.List;

public class ExternalUserProviderFactory implements UserStorageProviderFactory<ExternalUserProvider> {

	public static final String PROVIDER_ID = "external-user-provider";

	@Override
	public ExternalUserProvider create(KeycloakSession session, ComponentModel model) {
		return new ExternalUserProvider(session, model);
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getHelpText() {
		return "Peanuts User Provider";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return ProviderConfigurationBuilder.create()
				.property(Constants.BASE_URL, "Base URL", "Base URL of the API", ProviderConfigProperty.STRING_TYPE, "http://demo9781819.mockable.io", null)
				.property("peanuts.auth.username", "BasicAuth Username", "Username for BasicAuth at the API", ProviderConfigProperty.STRING_TYPE, "username", null)
//			.property(Constants.BASE_URL, "Base URL", "Base URL of the API", ProviderConfigProperty.STRING_TYPE, "", null)
//			.property(Constants.AUTH_USERNAME, "BasicAuth Username", "Username for BasicAuth at the API", ProviderConfigProperty.STRING_TYPE, "", null)
//			.property(Constants.AUTH_PASSWORD, "BasicAuth Password", "Password for BasicAuth at the API", ProviderConfigProperty.PASSWORD, "", null)
			.build();
	}

//	@Override
//	public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
////		if (StringUtil.isBlank(config.get("peanuts.base.url"))) {
////			throw new ComponentValidationException("Configuration not properly set, please verify.");
////		}
//	}
}
