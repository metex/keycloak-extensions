package com.skoiy.keycloak;

import com.skoiy.keycloak.external.User;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;
import org.keycloak.storage.federated.UserAttributeFederatedStorage;

import java.util.List;
import java.util.Map;

@Slf4j
public class UserAdapter extends AbstractUserAdapterFederatedStorage  {

    private final User user;
    private final String keycloakId;

    public UserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, User user) {
        super(session, realm, model);
        this.user = user;
        this.keycloakId = StorageId.keycloakId(model, user.getId_user());
    }

    @Override
    public String getId() {
        return keycloakId;
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public void setUsername(String username) {
        user.setUsername(username);
    }

    @Override
    public String getEmail() {
        return user.getEmail();
    }

		@Override
		public boolean isEmailVerified() {
		return user.getVerified();
	}

		@Override
    public void setEmail(String email) { user.setEmail(email); }

    @Override
    public String getFirstName() {
        return user.getFirstname();
    }

    @Override
    public void setFirstName(String firstName) {
        user.setFirstname(firstName);
    }

    @Override
    public String getLastName() {
        return user.getLastname();
    }

    @Override
    public void setLastName(String lastName) {
        user.setLastname(lastName);
    }

		public String getGender() {
		return user.getGender();
	}

		public void setGender(String gender) {
		user.setGender(gender);
	}

	////////////////////////////////////
		@Override
		public void setAttribute(String name, List<String> values) {
			log.info("setAttribute {} {}", name, values.toString());
			if (UserModel.USERNAME.equals(name)) {
				setUsername((values != null && values.size() > 0) ? values.get(0) : null);
			} else {
				log.info("getFederatedStorage {} ", getFederatedStorage().toString());
				getFederatedStorage().setAttribute(realm, this.getId(), mapAttribute(name), values);
			}
		}
		////////////////////////////////////

    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
        attributes.add(UserModel.USERNAME, getUsername());
        attributes.add(UserModel.EMAIL, getEmail());
        attributes.add(UserModel.EMAIL_VERIFIED, Boolean.toString(isEmailVerified()));
        attributes.add(UserModel.FIRST_NAME, getFirstName());
        attributes.add(UserModel.LAST_NAME, getLastName());
        attributes.add("birthday", user.getBirthday());
        attributes.add("gender", user.getGender());
        return attributes;
    }
}
