package com.skoiy.keycloak;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.skoiy.keycloak.external.CredentialData;
import com.skoiy.keycloak.external.User;
import com.skoiy.keycloak.external.UsersClientSimpleHttp;
import com.skoiy.keycloak.external.Verified;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;
import org.keycloak.storage.federated.UserAttributeFederatedStorage;
import org.keycloak.storage.user.*;

import javax.ws.rs.WebApplicationException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author Niko Köbler, http://www.n-k.de, @dasniko
 */
@Slf4j
public class ExternalUserProvider implements UserStorageProvider,
	UserLookupProvider.Streams, UserQueryProvider.Streams,
	CredentialInputUpdater, CredentialInputValidator,
	UserRegistrationProvider
	/*ImportSynchronization,
	UserAttributeFederatedStorage*/ {

	private final KeycloakSession session;
	private final ComponentModel model;
	private final UsersClientSimpleHttp client;
	protected Map<String, UserModel> loadedUsers = new HashMap<>();

	public ExternalUserProvider(KeycloakSession session, ComponentModel model) {
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

		String plainPassword = input.getChallengeResponse();

		log.info("Verifying {}", user.getUsername());
		// Make an HTTP request to validate the data
		Verified verified = client.validateCredentials(user.getUsername(), plainPassword);
		if (verified.getVerified()) {
			log.info("User {}", verified);
			addToStorage(realm, user.getUsername(), verified);
		}
		return verified.getVerified();
	}

	private void addToStorage(RealmModel realm, String username, Verified user) {
		UserModel local = session.userLocalStorage().getUserByUsername(realm, username);
		log.info("local ======>" + local);
		if (local == null) {
			local = session.userLocalStorage().addUser(realm, username);
			local.setFederationLink(model.getId());
			local.setEnabled(true);
			local.setEmailVerified(true);
			log.info("User {}", user.toString());
			local.setFirstName(user.getData().getFirstname());
			local.setLastName(user.getData().getLastname());
			local.setEmail(user.getData().getEmail());

			local.setSingleAttribute("id", user.getData().getId_user());
			local.setSingleAttribute("user_token", user.getData().getUser_token());
			local.setSingleAttribute("verified", user.getData().getVerified().toString());
			local.setSingleAttribute("active", user.getData().getActive().toString());
			local.setSingleAttribute("lang", user.getData().getLang());
			local.setSingleAttribute("updated_at", user.getData().getUpdated_at());
			local.setSingleAttribute("created_at", user.getData().getCreated_at());
			local.setSingleAttribute("register_Date", user.getData().getRegister_Date());
			local.setSingleAttribute("remember_token", user.getData().getRemember_token());
			local.setSingleAttribute("birthday", user.getData().getBirthday());
			local.setSingleAttribute("gender", user.getData().getGender());
			//local.grantRole(realm.getRole("admin"));// here you need to added what do you want...
			//local.grantRole(realm.getRole("create-realm"));// here you need to added what do you want...
			log.info("added to local <======");
			session.userCache().clear();
		}
	}

	protected UserModel createAdapter(RealmModel realm, String username) {
		return new AbstractUserAdapterFederatedStorage(session, realm, model) {
			@Override
			public String getUsername() {
				return username;
			}

			@Override
			public void setUsername(String username) {
				log.info("Settingusername");
			}
		};
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
		return findUser(realm, StorageId.externalId(id), "id_user");
	}

	@Override
	public UserModel getUserByUsername(RealmModel realm, String username) {
		log.info("getUserByUsername: {}", username);
		return findUser(realm, username, "email");
	}

	@Override
	public UserModel getUserByEmail(RealmModel realm, String email) {
		log.info("getUserByEmail: {}", email);
		return findUser(realm, email, "email");
	}

	private UserModel findUser(RealmModel realm, String identifier, String filterBy) {
		log.info("findUser: {}", identifier);
		UserModel adapter = loadedUsers.get(identifier);

		UserAdapter adapter2 = null;
		if (adapter == null) {
			try {
				User user = client.getUserById(identifier, filterBy);
				adapter = new UserAdapter(session, realm, model, user);
				//adapter = createAdapter(realm, user.getUsername()); // new line
				loadedUsers.put(identifier, adapter);
				//session.userLocalStorage().addUser(realm, user.getUsername()); // new line
			} catch (WebApplicationException e) {
				log.warn("User with identifier '{}' could not be found, response from server: {}", identifier, e.getResponse().getStatus());
			}
		} else {

			UserModel local = session.userLocalStorage().getUserByUsername(realm, adapter.getUsername()); // new line
			if (local == null) {
				log.info("AdapterId1 {}.", adapter.getUsername());
			}

			local = session.userLocalStorage().getUserByEmail(realm, adapter.getEmail()); // new line
			if (local == null) {
				log.info("AdapterId2 {}.", adapter.getEmail());
			}

			local = session.userLocalStorage().getUserById(realm, adapter.getId()); // new line
			if (local == null) {
				log.info("AdapterId3 {}.", adapter.getId());
			}
//			adapter.setSingleAttribute("gender", "b");
//			log.info("Storage {}.", local.getAttributes().toString());
			adapter2 = (UserAdapter) loadedUsers.get(identifier);
			log.info("Gender {}.", adapter2.getGender());
			//adapter2.setGender("b");
			//adapter2.setSingleAttribute("gender", "b1"); // persist on keycloak database
			log.info("Found user data for {} in loadedUsers.", identifier);
		}

		return adapter2 != null ? adapter2 : adapter;
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
		return UserCache.findUsers("").stream().map(user -> new UserAdapter(session, realm, model, user));
//		return toUserModelStream(client.getUsers(null, firstResult, maxResults), realm);
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
/*
	@Override
	public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
		log.info("SynchronizationResult");
		return null;
	}

	@Override
	public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
		log.info("syncSince");
		return null;
	}

	@Override
	public void setSingleAttribute(RealmModel realm, String userId, String name, String value) {
		log.info("setSingleAttribute");
	}

	@Override
	public void setAttribute(RealmModel realm, String userId, String name, List<String> values) {
		log.info("setAttribute");
	}

	@Override
	public void removeAttribute(RealmModel realm, String userId, String name) {
		log.info("removeAttribute");
	}

	@Override
	public MultivaluedHashMap<String, String> getAttributes(RealmModel realm, String userId) {
		log.info("getAttributes");
		return null;
	}

	@Override
	public List<String> getUsersByUserAttribute(RealmModel realm, String name, String value) {
		log.info("getUsersByUserAttribute");
		return null;
	}
	*/
}
