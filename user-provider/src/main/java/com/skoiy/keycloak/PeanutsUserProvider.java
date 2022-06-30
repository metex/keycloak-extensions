package com.skoiy.keycloak;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.skoiy.keycloak.external.CredentialData;
import com.skoiy.keycloak.external.User;
import com.skoiy.keycloak.external.UsersClientSimpleHttp;
import com.skoiy.keycloak.external.Verified;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import javax.ws.rs.WebApplicationException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * @author Niko Köbler, http://www.n-k.de, @dasniko
 */
@Slf4j
public class PeanutsUserProvider implements UserStorageProvider,
	UserLookupProvider.Streams, UserQueryProvider.Streams,
	CredentialInputUpdater, CredentialInputValidator, UserRegistrationProvider {

	private final KeycloakSession session;
	private final ComponentModel model;
	private final UsersClientSimpleHttp client;
	protected Map<String, UserModel> loadedUsers = new HashMap<>();

	public PeanutsUserProvider(KeycloakSession session, ComponentModel model) {
		this.session = session;
		this.model = model;
		this.client = new UsersClientSimpleHttp(session, model);
	}

	@Override
	public void close() {
	}

	@Override
	public boolean supportsCredentialType(String credentialType) {
		return PasswordCredentialModel.TYPE.equals(credentialType);
	}

	@Override
	public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
		return supportsCredentialType(credentialType);
	}

	@Override
	public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
		if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) {
			return false;
		}

		CredentialData credentialData;
		try {
			credentialData = client.getCredentialData(StorageId.externalId(user.getId()));
			log.debug("Received credential data for userId {}: %{}", user.getId(), credentialData);
			if (credentialData == null) {
				return false;
			}
		} catch (WebApplicationException e) {
			log.error(String.format("Request to verify credentials for userId %s failed with response status %d",
				user.getId(), e.getResponse().getStatus()), e);
			return false;
		}

		UserCredentialModel cred = (UserCredentialModel) input;

		PasswordCredentialModel passwordCredentialModel = credentialData.toPasswordCredentialModel();
		PasswordHashProvider passwordHashProvider = session.getProvider(PasswordHashProvider.class, credentialData.getAlgorithm());

		// Make a HTTP request to validate the data
		String resource = this.session.getContext().getClient().getClientId();
		log.info("CLIENT ID {} ", resource);
		Verified verified = client.validateCredentials(user.getUsername(), passwordCredentialModel.getPasswordSecretData().getValue());
		Boolean isValid = verified.getVerified();
//        boolean isValid = passwordHashProvider.verify(cred.getChallengeResponse(), passwordCredentialModel);

		log.info("Password validation result: {}", isValid);
		return isValid;
	}

	@Override
	public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
		log.debug("Try to update credentials type {} for user {}.", input.getType(), user.getId());
		return true;
	}

	@Override
	public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
	}

	@Override
	public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
		return Set.of();
	}

	@Override
	public UserModel getUserById(RealmModel realm, String id) {
		log.info("getUserById: {}", id);
		return findUser(realm, StorageId.externalId(id));
	}

	@Override
	public UserModel getUserByUsername(RealmModel realm, String username) {
		log.info("getUserByUsername: {}", username);
		return findUser(realm, username);
	}

	@Override
	public UserModel getUserByEmail(RealmModel realm, String email) {
		log.info("getUserByEmail: {}", email);
		return findUser(realm, email);
	}

	private UserModel findUser(RealmModel realm, String identifier) {
		UserModel adapter = loadedUsers.get(identifier);
		if (adapter == null) {
			try {
				User user = client.getUserById(identifier);
				adapter = new UserAdapter(session, realm, model, user);
				loadedUsers.put(identifier, adapter);
			} catch (WebApplicationException e) {
				log.warn("User with identifier '{}' could not be found, response from server: {}", identifier, e.getResponse().getStatus());
			}
		} else {
			log.info("Found user data for {} in loadedUsers.", identifier);
		}
		return adapter;
	}

	@Override
	public int getUsersCount(RealmModel realm) {
		log.info("getUsersCount");
		return 1;
	}

	@Override
	public Stream<UserModel> getUsersStream(RealmModel realm, Integer firstResult, Integer maxResults) {
		return null;
	}

	@Override
	public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
		log.info("searchForUserStream1, search={}, first={}, max={}", search, firstResult, maxResults);
		return null;
	}

	@Override
	public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
		// When clicking in the "View all users" button without any filter
		log.info("searchForUserStream2, params={}, first={}, max={}", params, firstResult, maxResults);
		return toUserModelStream(client.getUsers(null, firstResult, maxResults), realm);
	}

	private Stream<UserModel> toUserModelStream(List<User> users, RealmModel realm) {
		log.info("Received {} users from provider", users.size());
		return users.stream().map(user -> new UserAdapter(session, realm, model, user));
	}

	@Override
	public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
		return Stream.empty();
	}

	@Override
	public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
		return Stream.empty();
	}

	@Override
	public UserModel addUser(RealmModel realm, String username) {
		log.info("addUser, realm {} username {}", realm, username);
		return null;
	}

	@Override
	public boolean removeUser(RealmModel realm, UserModel user) {
		log.info("removeUser, realm {} username {}", realm, user.getUsername());
		return false;
	}
}
