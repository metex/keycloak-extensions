package com.skoiy.keycloak;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.fasterxml.jackson.core.type.TypeReference;
import com.skoiy.keycloak.external.CredentialData;
import com.skoiy.keycloak.external.User;
import com.skoiy.keycloak.external.Verified;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import lombok.SneakyThrows;
import org.apache.http.HttpStatus;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.mockserver.integration.ClientAndServer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Container;

import javax.ws.rs.WebApplicationException;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class ExternalUserProviderTest {

	static final String REALM = "peanuts";
	static Network network = Network.newNetwork();

	@Container
	private static final KeycloakContainer keycloak = new KeycloakContainer()
		.withRealmImportFile("/peanuts-realm.json")
		.withProviderClassesFrom("target/classes")
		.withNetwork(network);

	private static ClientAndServer mockServer;
	private static String baseUrl;

	@BeforeAll
	public static void startMockServer() {
		baseUrl = "http://localhost:5000";
	}

//    @BeforeAll
//    public static void startMockServer() {
//        mockServer = startClientAndServer(8081);
//
//        Expectation[] expectations = new MockServerClient("localhost", 8081)
//                .when(
//                        request()
//                                .withMethod("GET")
//                                .withPath("/view/cart")
//                                .withCookies(
//                                        cookie("session", "4930456C-C718-476F-971F-CB8E047AB349")
//                                )
//                                .withQueryStringParameters(
//                                        param("cartId", "055CA455-1DF7-45BB-8535-4F83E7266092")
//                                )
//                )
//                .respond(
//                        response()
//                                .withBody("some_response_body")
//                );
//        System.out.println(Arrays.toString(expectations));
//
//        RequestDefinition[] requestDefinitions = new MockServerClient("localhost", 8081)
//                .retrieveRecordedRequests(
//                        request()
//                                .withPath("/view/cart")
//                                .withQueryStringParameter("cartId","055CA455-1DF7-45BB-8535-4F83E7266092")
//                                .withMethod("GET")
//                );
//        System.out.println(Arrays.toString(requestDefinitions));
//    }

//    @AfterAll
//    public static void stopMockServer() {
//        mockServer.stop();
//    }

//    @Test
//    public void simpleTest() {
//        CartManager cm = new CartManager();
//        cm.viewCart();
//
//        new MockServerClient("localhost", 8081)
//                .verify(
//                        request()
//                                .withPath("/view/cart"),
//                        VerificationTimes.atLeast(1)
//                );
//    }

	@Test
	public void testLoginAsUserWithInvalidPassword() {
		assertTrue(true);
	}

	@Test
	@SneakyThrows
	public void testGetUserById() {
		String id = "admin";
		String url = String.format("%s/user/%s?filter=email", baseUrl, id);
		CloseableHttpClient httpClient = HttpClientBuilder.create().build();
		SimpleHttp.Response response = SimpleHttp.doGet(url, httpClient).asResponse();
		if (response.getStatus() == HttpStatus.SC_NOT_FOUND) {
			throw new WebApplicationException(response.getStatus());
		}

		User u = response.asJson(User.class);
		System.out.println(u.getFirstname());
	}

	@Test
	@SneakyThrows
	public void testGeCredentialsData() {
		String id = "admin";
		String url = String.format("%s/user/%s/credentials", baseUrl, id);
		CloseableHttpClient httpClient = HttpClientBuilder.create().build();
		SimpleHttp.Response response = SimpleHttp.doGet(url, httpClient).asResponse();
		if (response.getStatus() == 404) {
			throw new WebApplicationException(response.getStatus());
		}

		CredentialData u = response.asJson(CredentialData.class);
		System.out.println(u.getValue());
	}

	@Test
	@SneakyThrows
	public void testValidateCredentials() {
		Object obj = new Object() {
			public final String username = "admin";
			public final String password = "secret";
		};

		String url = String.format("%s/validate", baseUrl);
		CloseableHttpClient httpClient = HttpClientBuilder.create().build();
		SimpleHttp.Response response = SimpleHttp.doPost(url, httpClient)
			.acceptJson()
			.json(obj)
			.asResponse();
		if (response.getStatus() == 404) {
			throw new WebApplicationException(response.getStatus());
		}

		Verified u = response.asJson(Verified.class);
		System.out.println(u.getVerified());
	}

	@Test
	@SneakyThrows
	public void testGetUsers() {
		int first = 1;
		int max = 2;
		String url = String.format("%s/users", baseUrl);
		CloseableHttpClient httpClient = HttpClientBuilder.create().build();
		SimpleHttp.Response response = SimpleHttp.doGet(url, httpClient)
			.param("first", String.valueOf(first))
			.param("max", String.valueOf(max))
			.asResponse();
		if (response.getStatus() == 404) {
			throw new WebApplicationException(response.getStatus());
		}

		Object t = response.asJson(new TypeReference<>() {
		});
		System.out.println(t);
	}

	@Test
	@SneakyThrows
	public void testBCrypt() {
		String password = "1234567";
		String hash = "$2y$10$1/xlmIBAoz1SMgMTyAtr8eKhE33Truhg/t5xjic6VXclhgfEINv4i";
		BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), hash);
		System.out.println(result.verified);
	}
}
