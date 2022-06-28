package skoiy.keycloak.external;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.List;

@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface UsersClient {

	@GET
	List<User> getUsers(@QueryParam("search") String search, @QueryParam("first") int first, @QueryParam("max") int max);

	@GET
	List<User> login(@QueryParam("username") String username, @QueryParam("password") String password);

	@GET
	@Path("/{id}")
	User getUserById(@PathParam("id") String identifier);

	@GET
	@Path("/{id}/credentials")
	CredentialData getCredentialData(@PathParam("id") String id);

	@GET
	@Path("/{id}/{password}")
	Verified validateCredentials(@PathParam("id") String id, @PathParam("password") String password);

}
