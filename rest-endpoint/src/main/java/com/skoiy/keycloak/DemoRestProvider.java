package com.skoiy.keycloak;

import com.skoiy.keycloak.model.UserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.common.UserModelIdentity;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.permission.evaluator.Evaluators;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.authorization.permission.evaluator.PermissionEvaluator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.utils.MediaType;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
//@RequiredArgsConstructor
public class DemoRestProvider implements RealmResourceProvider {
    private final KeycloakSession session;

		public DemoRestProvider(KeycloakSession session) {
			this.session = session;
    }

    public void close() {

    }

	@GET
	@Path("hello")
	@Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
	public Response helloAnonymous() {
		return Response.ok(Map.of("hello", session.getContext().getRealm().getName())).build();
	}

	@GET
	@Path("hello-auth")
	@Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
	public Response helloAuthenticated() {
		log.info("helloAuthenticated");
		Object obj = new Object(){
			public final String bruno = "gomes";
		};

		AuthenticationManager.AuthResult auth = checkAuth();
		this.session.setAttribute("bruno", obj);

		auth.getSession().setNote("note", "note_Desc");
		auth.getSession().getUser().setSingleAttribute("hello", "world2");
		auth.getToken().setOtherClaims("tenant_id", 15);
		auth.getToken().setOtherClaims("lucky", 99999999);
		auth.getToken().setOtherClaims("hardcoded", "99999999");
		auth.getToken().setOtherClaims("custom_claim_name", "99999999");
		auth.getToken().getOtherClaims().put("custom_claim_name", "custom_claim_value_changed");
		auth.getToken().getOtherClaims().put("custom_claim_name_hello", "custom_claim_value_world");
		//auth.getToken().subject("some");
		log.info(auth.getToken().toString());
/*
		String clientId = ""; // Client id which resources are defined.
		String resourceType = ""; // Get resources by type.

		final RealmModel realm = this.session.getContext().getRealm();
		final AuthorizationProvider authorizationProvider = this.session.getProvider(AuthorizationProvider.class);
		final ClientModel client = this.session.clientStorageManager().getClientByClientId(realm, clientId);
		final ResourceServer resourceServer = authorizationProvider
			.getStoreFactory()
			.getResourceServerStore()
			.findById(client.getId());
		final Evaluators evaluators = authorizationProvider.evaluators();

		final AuthorizationRequest request = new AuthorizationRequest();
		request.setSubjectToken(auth.getToken().toString());

		// Get resources by type and put them in a map
		final Map<String, Resource> resourceMap = authorizationProvider
			.getStoreFactory()
			.getResourceStore()
			.findByType(resourceServer, resourceServer.getId())
			.stream()
			.collect(Collectors.toMap(Resource::getId, r -> r));

		// Generate a permission evaluator for all resources of given type
		final PermissionEvaluator permissionEvaluator = evaluators
			.from(
				resourceMap
					.entrySet()
					.stream()
					.map(r -> new ResourcePermission(r.getValue(), Collections.emptyList(), resourceServer))
					.collect(Collectors.toList()),
				new DefaultEvaluationContext(new UserModelIdentity(realm, auth.getUser()), this.session));

		// Evaluate permission and put them in a result set.
		final Collection<Permission> permissions = permissionEvaluator.evaluate(resourceServer, request);
		final Set<Resource> resources = new HashSet<>();
		for (final Permission permission : permissions) {
			if (resourceMap.containsKey(permission.getResourceId())) {
				resources.add(resourceMap.get(permission.getResourceId()));
			}
		}
		return resources;
*/
		return Response.ok(Map.of("hello", auth.getUser().getUsername())).build();
	}

	@GET
	@Path("demoresources")
	@NoCache
	@Produces({MediaType.APPLICATION_JSON})
	@Encoded
	public List<UserDetails> listDemoResources() {
//		if (this.auth == null || this.auth.getToken() == null) {
//			throw new NotAuthorizedException("Bearer");
//		}

		List<UserModel> userModel = session.users().getUsers(session.getContext().getRealm());
		return userModel.stream().map(e -> toUserDetail(e)).collect(Collectors.toList());
		/*
		String clientId = ""; // Client id which resources are defined.
		String resourceType = ""; // Get resources by type.

		final RealmModel realm = this.session.getContext().getRealm();
		final AuthorizationProvider authorizationProvider = this.session.getProvider(AuthorizationProvider.class);
		final ClientModel client = this.session.clientStorageManager().getClientByClientId(realm, clientId);
		final ResourceServer resourceServer = authorizationProvider
			.getStoreFactory()
			.getResourceServerStore()
			.findById(client.getId());
		final Evaluators evaluators = authorizationProvider.evaluators();

		final AuthorizationRequest request = new AuthorizationRequest();
		request.setSubjectToken(this.auth.getToken().toString());

		// Get resources by type and put them in a map
		final Map<String, Resource> resourceMap = authorizationProvider
			.getStoreFactory()
			.getResourceStore()
			.findByType(resourceType, resourceServer.getId())
			.stream()
			.collect(Collectors.toMap(Resource::getId, r -> r));

		// Generate a permission evaluator for all resources of given type
		final PermissionEvaluator permissionEvaluator = evaluators
			.from(
				resourceMap
					.entrySet()
					.stream()
					.map(r -> new ResourcePermission(r.getValue(), Collections.emptyList(), resourceServer))
					.collect(Collectors.toList()),
				new DefaultEvaluationContext(new UserModelIdentity(realm, this.auth.getUser()), this.session));

		// Evaluate permission and put them in a result set.
		final Collection<Permission> permissions = permissionEvaluator.evaluate(resourceServer, request);
		final Set<Resource> resources = new HashSet<>();
		for (final Permission permission : permissions) {
			if (resourceMap.containsKey(permission.getResourceId())) {
				resources.add(resourceMap.get(permission.getResourceId()));
			}
		}
		return resources;*/
	}

    public Object getResource() {
        return this;
    }

    @GET
    @Path("users")
    @NoCache
    @Produces({MediaType.APPLICATION_JSON})
    @Encoded
    public List<UserDetails> getUsers() {
        List<UserModel> userModel = session.users().getUsers(session.getContext().getRealm());
        return userModel.stream().map(e -> toUserDetail(e)).collect(Collectors.toList());
    }

    private UserDetails toUserDetail(UserModel um) {
        return new UserDetails(um.getUsername(), um.getFirstName(), um.getLastName());

    }

	private AuthenticationManager.AuthResult checkAuth() {
		AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
		if (auth == null) {
			throw new NotAuthorizedException("Bearer");
		} /*else if (auth.getToken().getIssuedFor() == null || !auth.getToken().getIssuedFor().equals("admin-cli")) {
			throw new ForbiddenException("Token is not properly issued for admin-cli");
		}*/
		return auth;
	}
}
